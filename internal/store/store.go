package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type Peer struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	PublicKey    string            `json:"public_key"`
	PresharedKey string            `json:"preshared_key,omitempty"`
	PeerSecret   string            `json:"peer_secret,omitempty"`
	Endpoint     string            `json:"endpoint"`
	MeshIP       string            `json:"mesh_ip"`
	AllowedIPs   []string          `json:"allowed_ips"`
	Container    string            `json:"container,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	LastSeen     int64             `json:"last_seen,omitempty"`
	Isolated     bool              `json:"isolated,omitempty"`
}

// Clone returns a deep copy of Peer so callers cannot mutate internal map/slice memory.
func (p Peer) Clone() Peer {
	cp := p
	if p.AllowedIPs != nil {
		cp.AllowedIPs = append([]string(nil), p.AllowedIPs...)
	}
	if p.Labels != nil {
		cp.Labels = make(map[string]string, len(p.Labels))
		for k, v := range p.Labels {
			cp.Labels[k] = v
		}
	}
	return cp
}

// PublicView strips secret server-side fields (PeerSecret, PresharedKey) before exposing peers
// on public listing endpoints to other peers.
func (p Peer) PublicView() Peer {
	cp := p.Clone()
	cp.PeerSecret = ""
	cp.PresharedKey = ""
	return cp
}

type Store struct {
	mu     sync.RWMutex
	saveMu sync.Mutex
	path   string
	Peers  map[string]Peer `json:"peers"`
}

func New(dataDir string) *Store {
	s := &Store{
		path:  filepath.Join(dataDir, "peers.json"),
		Peers: map[string]Peer{},
	}
	_ = s.Load()
	return s
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var tmp struct {
		Peers map[string]Peer `json:"peers"`
	}
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	if tmp.Peers != nil {
		s.Peers = make(map[string]Peer, len(tmp.Peers))
		for k, v := range tmp.Peers {
			s.Peers[k] = v.Clone()
		}
	}
	return nil
}

// Save atomically persists the peer table using a serialized write mutex + unique temp file + rename
// so concurrent goroutines never race on temporary filenames or corrupt state.
func (s *Store) Save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.RLock()
	snapshot := struct {
		Peers map[string]Peer `json:"peers"`
	}{
		Peers: make(map[string]Peer, len(s.Peers)),
	}
	for k, v := range s.Peers {
		snapshot.Peers[k] = v.Clone()
	}
	s.mu.RUnlock()

	b, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".peers-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func (s *Store) Add(p Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		return fmt.Errorf("peer id required")
	}
	s.Peers[p.ID] = p.Clone()
	return nil
}

func (s *Store) UpdateLastSeen(id string, ts int64, endpoint string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.Peers[id]
	if !ok {
		return false
	}
	p.LastSeen = ts
	if endpoint != "" {
		p.Endpoint = endpoint
	}
	s.Peers[id] = p
	return true
}

func (s *Store) Remove(id string) (Peer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.Peers[id]
	if ok {
		delete(s.Peers, id)
	}
	return p.Clone(), ok
}

func (s *Store) Get(id string) (Peer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.Peers[id]
	if !ok {
		return Peer{}, false
	}
	return p.Clone(), true
}

func (s *Store) FindByPublicKey(pubKey string) (Peer, bool) {
	if pubKey == "" {
		return Peer{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.Peers {
		if p.PublicKey == pubKey {
			return p.Clone(), true
		}
	}
	return Peer{}, false
}

func (s *Store) FindByMeshIP(ip string) (Peer, bool) {
	if ip == "" {
		return Peer{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.Peers {
		if p.MeshIP == ip {
			return p.Clone(), true
		}
	}
	return Peer{}, false
}

// List returns deep-copied peers sorted deterministically by ID.
func (s *Store) List() []Peer {
	s.mu.RLock()
	out := make([]Peer, 0, len(s.Peers))
	for _, p := range s.Peers {
		out = append(out, p.Clone())
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

// PublicList returns peers stripped of secret fields, sorted deterministically by ID.
func (s *Store) PublicList() []Peer {
	s.mu.RLock()
	out := make([]Peer, 0, len(s.Peers))
	for _, p := range s.Peers {
		out = append(out, p.PublicView())
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

// Count returns the number of stored peers safely under read lock.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.Peers)
}

func (s *Store) Path() string { return s.path }
