package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"strings"
	"sync"
	"time"

	"github.com/baba01hacker/cerberus/internal/config"
	"github.com/baba01hacker/cerberus/internal/mesh"
	"github.com/baba01hacker/cerberus/internal/store"
)

type State struct {
	mu        sync.RWMutex
	Cfg       *config.Config
	Store     *store.Store
	Allocator *mesh.Allocator
	StartedAt time.Time
}

func NewState(cfg *config.Config, st *store.Store) (*State, error) {
	alloc, err := mesh.NewAllocator(cfg.MeshCIDR)
	if err != nil {
		return nil, err
	}
	// mark existing peers as used
	for _, p := range st.List() {
		if p.MeshIP != "" {
			_ = allocReserve(alloc, p.MeshIP)
		}
	}
	s := &State{Cfg: cfg, Store: st, Allocator: alloc, StartedAt: time.Now()}
	return s, nil
}

// allocReserve helper to mark ip used (exported via method not available); do inline.
func allocReserve(a *mesh.Allocator, ip string) error {
	// Allocator.Allocate with preferred marks used; but returns new if not. Use Allocate then Release? Simpler: call Allocate(preferred) and ignore returned if matches.
	got, err := a.Allocate(ip)
	if err != nil {
		return err
	}
	if got != ip {
		a.Release(got)
	}
	return nil
}

type RegisterReq struct {
	Name      string            `json:"name"`
	PublicKey string            `json:"public_key"`
	Endpoint  string            `json:"endpoint"`
	MeshIP    string            `json:"mesh_ip,omitempty"`
	Container string            `json:"container,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type infoResp struct {
	NodeName  string `json:"node_name"`
	PublicKey string `json:"public_key"`
	MeshCIDR  string `json:"mesh_cidr"`
	Interface string `json:"interface"`
	Endpoint  string `json:"endpoint"`
	StartedAt int64  `json:"started_at"`
}

func (s *State) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		writeJSON(w, http.StatusOK, infoResp{
			NodeName:  s.Cfg.NodeName,
			PublicKey: s.Cfg.PublicKey,
			MeshCIDR:  s.Cfg.MeshCIDR,
			Interface: s.Cfg.Interface,
			Endpoint:  s.Cfg.Endpoint,
			StartedAt: s.StartedAt.Unix(),
		})
	})
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, s.Store.List())
		case http.MethodPost:
			var req RegisterReq
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			if req.PublicKey == "" {
				writeErr(w, http.StatusBadRequest, fmt.Errorf("public_key required"))
				return
			}
			id := req.Name
			if id == "" {
				id = req.PublicKey[:8]
			}
			ip, err := s.Allocator.Allocate(req.MeshIP)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
			peer := store.Peer{
				ID:         id,
				Name:       req.Name,
				PublicKey:  req.PublicKey,
				Endpoint:   req.Endpoint,
				MeshIP:     ip,
				AllowedIPs: []string{ip + "/32"},
				Container:  req.Container,
				Labels:     req.Labels,
				LastSeen:   time.Now().Unix(),
			}
			if err := s.Store.Add(peer); err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
			_ = s.Store.Save()
			writeJSON(w, http.StatusCreated, peer)
		case http.MethodDelete:
			id := strings.TrimPrefix(r.URL.Path, "/peers/")
			if id == "" || id == "/peers" {
				// try query
				id = r.URL.Query().Get("id")
			}
			if id == "" {
				writeErr(w, http.StatusBadRequest, fmt.Errorf("id required"))
				return
			}
			if p, ok := s.Store.Get(id); ok && p.MeshIP != "" {
				s.Allocator.Release(p.MeshIP)
			}
			s.Store.Remove(id)
			_ = s.Store.Save()
			writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/peers/", func(w http.ResponseWriter, r *http.Request) {
		// DELETE /peers/{id}
		if r.Method == http.MethodDelete {
			id := strings.TrimPrefix(r.URL.Path, "/peers/")
			if p, ok := s.Store.Get(id); ok && p.MeshIP != "" {
				s.Allocator.Release(p.MeshIP)
			}
			s.Store.Remove(id)
			_ = s.Store.Save()
			writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
			return
		}
		writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// Client helpers

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 15 * time.Second}}
}

func (c *Client) Info() (*infoResp, error) {
	resp, err := c.HTTP.Get(c.BaseURL + "/info")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("info: %s: %s", resp.Status, string(b))
	}
	var info infoResp
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *Client) ListPeers() ([]store.Peer, error) {
	resp, err := c.HTTP.Get(c.BaseURL + "/peers")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list peers: %s: %s", resp.Status, string(b))
	}
	var peers []store.Peer
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, err
	}
	return peers, nil
}

func (c *Client) Register(req RegisterReq) (*store.Peer, error) {
	b, _ := json.Marshal(req)
	resp, err := c.HTTP.Post(c.BaseURL+"/peers", "application/json", strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("register: %s: %s", resp.Status, string(body))
	}
	var p store.Peer
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (c *Client) DeletePeer(id string) error {
	req, _ := http.NewRequest(http.MethodDelete, c.BaseURL+"/peers/"+id, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete: %s: %s", resp.Status, string(body))
	}
	return nil
}

// Serve starts HTTP server (HTTP/2 enabled automatically by Go when TLS configured; plain HTTP/1.1 otherwise).
func Serve(cfg *config.Config, st *store.Store, addr string) error {
	state, err := NewState(cfg, st)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: h2c.NewHandler(state.Handler(), &http2.Server{}),
	}
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		return srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// ensure net import used
var _ = net.Listen
