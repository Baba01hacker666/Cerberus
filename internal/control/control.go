package control

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/Baba01hacker666/cerberus/internal/config"
	"github.com/Baba01hacker666/cerberus/internal/isolation"
	"github.com/Baba01hacker666/cerberus/internal/mesh"
	"github.com/Baba01hacker666/cerberus/internal/store"
	"github.com/Baba01hacker666/cerberus/internal/tunnel"
)

// State is the authoritative, concurrency-safe Smart Server coordinator unifying:
//   - Zero-setup key + PSK + IP auto-provisioning (/join and /peers)
//   - Immediate event-driven WireGuard peer & firewall policy reconciliation
//   - Single-port HTTP Upgrade WireGuard TCP relay (/wg-tunnel)
//   - Real-time SSE topology push stream (/events)
type State struct {
	mu          sync.RWMutex
	reconcileMu sync.Mutex
	Cfg         *config.Config
	CfgPath    string
	Store      *store.Store
	Allocator  *mesh.Allocator
	Policy     *isolation.PolicyEngine
	Firewall   *isolation.Manager
	Tunnel     *tunnel.Tunnel
	StartedAt  time.Time
	ServerCtx  context.Context

	version    atomic.Uint64
	subsMu     sync.Mutex
	subs       map[uint64]chan uint64
	nextSubID  uint64
}

type StateOptions struct {
	ConfigPath string
	Policy     *isolation.PolicyEngine
	Firewall   *isolation.Manager
	Tunnel     *tunnel.Tunnel
	Context    context.Context
}

func NewState(cfg *config.Config, st *store.Store) (*State, error) {
	return NewStateWithOptions(cfg, st, StateOptions{})
}

func NewStateWithOptions(cfg *config.Config, st *store.Store, opts StateOptions) (*State, error) {
	alloc, err := mesh.NewAllocator(cfg.MeshCIDR)
	if err != nil {
		return nil, err
	}
	if cfg.PrivateKey == "" {
		priv, pub, err := tunnel.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		cfg.PrivateKey = priv
		cfg.PublicKey = pub
	} else if cfg.PublicKey == "" {
		if pub, err := tunnel.PublicKeyFromPrivate(cfg.PrivateKey); err == nil {
			cfg.PublicKey = pub
		}
	}
	if cfg.MeshIP == "" {
		cfg.MeshIP = alloc.ServerIP()
	}

	// Reserve existing peers in allocator with owner keys so restarts preserve every peer's IP
	for _, p := range st.List() {
		if p.MeshIP != "" {
			owner := p.ID
			if owner == "" {
				owner = p.PublicKey
			}
			_ = alloc.ReserveForOwner(owner, p.MeshIP)
		}
	}

	pol := opts.Policy
	if pol == nil {
		pol = isolation.NewPolicyEngine()
	}
	fw := opts.Firewall
	if fw == nil && !cfg.UserspaceOnly {
		fw = isolation.New("CERBERUS")
	}
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}

	s := &State{
		Cfg:       cfg,
		CfgPath:   opts.ConfigPath,
		Store:     st,
		Allocator: alloc,
		Policy:    pol,
		Firewall:  fw,
		Tunnel:    opts.Tunnel,
		StartedAt: time.Now(),
		ServerCtx: ctx,
		subs:      make(map[uint64]chan uint64),
	}
	s.version.Store(1)
	s.Reconcile()
	return s, nil
}

// Reconcile immediately applies the latest peer list & isolation policy to BOTH
// the userspace PolicyEngine/RouterTUN/WireGuard device AND host iptables (if available),
// then notifies all connected SSE clients.
func (s *State) Reconcile() {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()

	s.mu.RLock()
	cfgSnap := s.Cfg.Clone()
	tun := s.Tunnel
	pol := s.Policy
	fw := s.Firewall
	s.mu.RUnlock()

	peers := s.Store.List()
	nameToIP := make(map[string]string, len(peers)*2+2)
	nameToIP[cfgSnap.NodeName] = cfgSnap.MeshIP
	nameToIP["server"] = cfgSnap.MeshIP

	var isolatedIPs []string
	allMeshIPs := []string{}
	if cfgSnap.MeshIP != "" {
		allMeshIPs = append(allMeshIPs, cfgSnap.MeshIP)
	}

	tunPeers := make([]tunnel.PeerConfig, 0, len(peers))
	for i, p := range peers {
		if p.MeshIP != "" {
			allMeshIPs = append(allMeshIPs, p.MeshIP)
			if p.Name != "" {
				nameToIP[p.Name] = p.MeshIP
			}
			if p.ID != "" {
				nameToIP[p.ID] = p.MeshIP
			}
			if p.Isolated {
				isolatedIPs = append(isolatedIPs, p.MeshIP)
			}
		}
		if p.PublicKey == "" {
			continue
		}
		allowed := p.AllowedIPs
		if len(allowed) == 0 && p.MeshIP != "" {
			allowed = []string{p.MeshIP + "/32"}
		}
		tunPeers = append(tunPeers, tunnel.PeerConfig{
			Index:        uint32(i + 1),
			PublicKey:    p.PublicKey,
			PresharedKey: p.PresharedKey,
			Endpoint:     p.Endpoint,
			MeshIP:       p.MeshIP,
			AllowedIPs:   allowed,
		})
	}

	if pol != nil {
		pol.Configure(
			cfgSnap.Isolation.Enabled,
			cfgSnap.Isolation.DefaultDeny,
			cfgSnap.Isolation.AllowedPeers,
			cfgSnap.Isolation.BlockedPeers,
			isolatedIPs,
			nameToIP,
		)
	}

	if tun != nil {
		tun.UpdatePeers(tunPeers)
	}

	if !cfgSnap.UserspaceOnly && cfgSnap.Isolation.Enabled && fw != nil && isolation.CanUseIptables() {
		allowedMatrix, _, defaultDeny := pol.BuildAllowedMatrix(allMeshIPs)
		_ = fw.ApplyPolicy(allMeshIPs, allowedMatrix, defaultDeny)
	}

	ver := s.version.Add(1)
	s.broadcastVersion(ver)
}

func (s *State) broadcastVersion(ver uint64) {
	s.subsMu.Lock()
	for _, ch := range s.subs {
		select {
		case ch <- ver:
		default:
		}
	}
	s.subsMu.Unlock()
}

func (s *State) subscribeEvents() (uint64, <-chan uint64, func()) {
	ch := make(chan uint64, 4)
	s.subsMu.Lock()
	s.nextSubID++
	id := s.nextSubID
	s.subs[id] = ch
	cur := s.version.Load()
	s.subsMu.Unlock()
	return cur, ch, func() {
		s.subsMu.Lock()
		delete(s.subs, id)
		s.subsMu.Unlock()
	}
}

type RegisterReq struct {
	PeerID     string            `json:"peer_id,omitempty"`
	PeerSecret string            `json:"peer_secret,omitempty"`
	Token      string            `json:"token,omitempty"`
	Name       string            `json:"name"`
	PublicKey  string            `json:"public_key"`
	Endpoint   string            `json:"endpoint"`
	MeshIP     string            `json:"mesh_ip,omitempty"`
	Container  string            `json:"container,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type InfoResp struct {
	NodeName     string `json:"node_name"`
	PublicKey    string `json:"public_key"`
	MeshIP       string `json:"mesh_ip"`
	MeshCIDR     string `json:"mesh_cidr"`
	UDPPort      int    `json:"udp_port"`
	MTU          int    `json:"mtu"`
	Keepalive    int    `json:"keepalive"`
	Interface    string `json:"interface"`
	Endpoint     string `json:"endpoint"`
	AuthRequired bool   `json:"auth_required"`
	PeersCount   int    `json:"peers_count"`
	Version      uint64 `json:"version"`
	StartedAt    int64  `json:"started_at"`
}

type JoinResp struct {
	Peer          store.Peer   `json:"peer"`
	PrivateKey    string       `json:"private_key,omitempty"` // Non-empty ONLY when smart server auto-generated keys!
	PresharedKey  string       `json:"preshared_key,omitempty"`
	PeerSecret    string       `json:"peer_secret"`
	Server        InfoResp     `json:"server"`
	Peers         []store.Peer `json:"peers"`
	WireGuardConf string       `json:"wireguard_conf"`
}

type HeartbeatReq struct {
	PeerID     string `json:"peer_id"`
	PeerSecret string `json:"peer_secret"`
	Endpoint   string `json:"endpoint,omitempty"`
}

type HeartbeatResp struct {
	OK      bool         `json:"ok"`
	Version uint64       `json:"version"`
	MeshIP  string       `json:"mesh_ip"`
	Server  InfoResp     `json:"server"`
	Peers   []store.Peer `json:"peers"`
}

type StatusResp struct {
	Info           InfoResp                  `json:"info"`
	Peers          []store.Peer              `json:"peers"`
	TunnelStats    []tunnel.PeerRuntimeStats `json:"tunnel_stats"`
	RelayedPackets uint64                    `json:"relayed_packets"`
	DroppedPolicy  uint64                    `json:"dropped_policy"`
	OSInterfaceUp  bool                      `json:"os_interface_up"`
	Isolation      config.IsolationConfig    `json:"isolation"`
}

type IsolationRuleReq struct {
	Src         string `json:"src,omitempty"`
	Dst         string `json:"dst,omitempty"`
	DefaultDeny *bool  `json:"default_deny,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
}

func (s *State) currentInfoLocked() InfoResp {
	udpPort := s.Cfg.EffectiveUDPPort()
	if s.Tunnel != nil && s.Tunnel.ActualUDPPort() > 0 {
		udpPort = s.Tunnel.ActualUDPPort()
	}
	return InfoResp{
		NodeName:     s.Cfg.NodeName,
		PublicKey:    s.Cfg.PublicKey,
		MeshIP:       s.Cfg.MeshIP,
		MeshCIDR:     s.Cfg.MeshCIDR,
		UDPPort:      udpPort,
		MTU:          s.Cfg.MTU,
		Keepalive:    s.Cfg.Keepalive,
		Interface:    s.Cfg.Interface,
		Endpoint:     s.Cfg.Endpoint,
		AuthRequired: s.Cfg.AuthToken != "",
		PeersCount:   s.Store.Count(),
		Version:      s.version.Load(),
		StartedAt:    s.StartedAt.Unix(),
	}
}

func (s *State) InfoSnapshot() InfoResp {
	s.mu.RLock()
	info := s.currentInfoLocked()
	s.mu.RUnlock()
	info.PeersCount = len(s.Store.List())
	return info
}

func extractBearerOrHeader(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if tok := strings.TrimSpace(r.Header.Get("X-Cerberus-Token")); tok != "" {
		return tok
	}
	return strings.TrimSpace(r.URL.Query().Get("token"))
}

func (s *State) checkServerToken(r *http.Request, bodyToken string) bool {
	s.mu.RLock()
	expected := s.Cfg.AuthToken
	s.mu.RUnlock()
	if expected == "" {
		return true
	}
	got := extractBearerOrHeader(r)
	if got == "" {
		got = strings.TrimSpace(bodyToken)
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

// provisionPeer implements smart zero-setup registration (used by both POST /join and POST /peers).
func (s *State) provisionPeer(r *http.Request, req RegisterReq, allowSyntheticKey bool) (*JoinResp, int, error) {
	if !s.checkServerToken(r, req.Token) {
		return nil, http.StatusUnauthorized, fmt.Errorf("invalid or missing auth token")
	}

	s.mu.Lock()
	// 1. Key handling: if client passed NO keys, smart server generates fresh X25519 keys automatically!
	var generatedPriv string
	pubKey := strings.TrimSpace(req.PublicKey)
	if pubKey == "" {
		priv, pub, err := tunnel.GenerateKeyPair()
		if err != nil {
			s.mu.Unlock()
			return nil, http.StatusInternalServerError, fmt.Errorf("generate client keypair: %w", err)
		}
		generatedPriv = priv
		pubKey = pub
	} else {
		if normalized, err := tunnel.ValidatePublicKey(pubKey); err == nil {
			pubKey = normalized
		} else if !allowSyntheticKey {
			s.mu.Unlock()
			return nil, http.StatusBadRequest, fmt.Errorf("invalid public_key: %w", err)
		}
	}

	// 2. Identity & anti-hijack resolution:
	//    - Reconnecting peer with valid PeerSecret (or matching PublicKey on same entry) keeps its exact ID & IP!
	//    - Distinct machine that happens to share the same hostname (e.g. two "ubuntu" hosts!) automatically gets
	//      a clean disambiguated ID ("ubuntu-2", "ubuntu-3") so it NEVER overwrites an existing peer!
	var existingPeer *store.Peer
	suppliedSecret := strings.TrimSpace(req.PeerSecret)
	if suppliedSecret == "" {
		suppliedSecret = strings.TrimSpace(r.Header.Get("X-Cerberus-Peer-Secret"))
	}

	if req.PeerID != "" {
		if p, ok := s.Store.Get(req.PeerID); ok {
			if p.PeerSecret != "" && subtle.ConstantTimeCompare([]byte(p.PeerSecret), []byte(suppliedSecret)) == 1 {
				existingPeer = &p
			} else if p.PublicKey == pubKey && (p.PeerSecret == "" || suppliedSecret == "") {
				existingPeer = &p
			}
		}
	}
	if existingPeer == nil && pubKey != "" {
		if p, ok := s.Store.FindByPublicKey(pubKey); ok {
			if p.PeerSecret == "" || suppliedSecret == "" || subtle.ConstantTimeCompare([]byte(p.PeerSecret), []byte(suppliedSecret)) == 1 {
				existingPeer = &p
			}
		}
	}

	cleanName := sanitizePeerName(req.Name)
	var id string
	if existingPeer != nil {
		id = existingPeer.ID
		if cleanName == "" {
			cleanName = existingPeer.Name
		}
	} else {
		baseID := cleanName
		if baseID == "" {
			if len(pubKey) >= 8 {
				baseID = "node-" + sanitizePeerName(pubKey[:8])
			} else {
				baseID = "node"
			}
			cleanName = baseID
		}
		id = baseID
		for suffix := 2; ; suffix++ {
			if _, taken := s.Store.Get(id); !taken {
				break
			}
			id = fmt.Sprintf("%s-%d", baseID, suffix)
		}
	}

	// 3. Allocate or preserve MeshIP idempotently for this peer ID
	preferredIP := strings.TrimSpace(req.MeshIP)
	if preferredIP == "" && existingPeer != nil {
		preferredIP = existingPeer.MeshIP
	}
	ip, err := s.Allocator.AllocateForOwner(id, preferredIP)
	if err != nil {
		s.mu.Unlock()
		return nil, http.StatusInsufficientStorage, err
	}

	// 4. Preserve or generate PeerSecret + PresharedKey
	peerSecret := ""
	psk := ""
	if existingPeer != nil {
		peerSecret = existingPeer.PeerSecret
		psk = existingPeer.PresharedKey
	}
	if peerSecret == "" {
		peerSecret, _ = tunnel.GenerateRandomToken(24)
	}
	if psk == "" {
		psk, _ = tunnel.GeneratePresharedKey()
	}

	endpoint := strings.TrimSpace(req.Endpoint)
	if endpoint == "" && existingPeer != nil {
		endpoint = existingPeer.Endpoint
	}

	peer := store.Peer{
		ID:           id,
		Name:         cleanName,
		PublicKey:    pubKey,
		PresharedKey: psk,
		PeerSecret:   peerSecret,
		Endpoint:     endpoint,
		MeshIP:       ip,
		AllowedIPs:   []string{ip + "/32"},
		Container:    req.Container,
		Labels:       req.Labels,
		LastSeen:     time.Now().Unix(),
	}
	if existingPeer != nil {
		peer.Isolated = existingPeer.Isolated
	}

	if err := s.Store.Add(peer); err != nil {
		s.mu.Unlock()
		return nil, http.StatusInternalServerError, err
	}
	s.mu.Unlock()

	_ = s.Store.Save()
	// Immediately reconcile WireGuard + firewall BEFORE responding so the server tunnel is 100% ready
	// when the client receives this response!
	s.Reconcile()

	srvInfo := s.InfoSnapshot()
	srvEndpoint := srvInfo.Endpoint
	if srvEndpoint == "" && r.Host != "" {
		hostOnly := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			hostOnly = h
		}
		srvEndpoint = net.JoinHostPort(hostOnly, strconv.Itoa(srvInfo.UDPPort))
	}

	wgConf := tunnel.RenderWireGuardConf(tunnel.WireGuardConfParams{
		PrivateKey:      generatedPriv,
		Address:         mesh.MeshIPWithPrefix(ip, srvInfo.MeshCIDR),
		MTU:             srvInfo.MTU,
		ServerPublicKey: srvInfo.PublicKey,
		PresharedKey:    psk,
		ServerEndpoint:  srvEndpoint,
		AllowedIPs:      srvInfo.MeshCIDR,
		Keepalive:       srvInfo.Keepalive,
	})

	resp := &JoinResp{
		Peer:          peer.PublicView(),
		PrivateKey:    generatedPriv,
		PresharedKey:  psk,
		PeerSecret:    peerSecret,
		Server:        srvInfo,
		Peers:         s.Store.PublicList(),
		WireGuardConf: wgConf,
	}
	return resp, http.StatusCreated, nil
}

func sanitizePeerName(name string) string {
	name = strings.TrimSpace(strings.TrimPrefix(name, "/"))
	if name == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		case r == ' ' || r == '/':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func (s *State) handleDeletePeer(w http.ResponseWriter, r *http.Request, id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("id required"))
		return
	}
	existing, ok := s.Store.Get(id)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
		return
	}
	// If server has AuthToken, verify either AuthToken or matching X-Cerberus-Peer-Secret
	if !s.checkServerToken(r, "") {
		suppliedSecret := strings.TrimSpace(r.Header.Get("X-Cerberus-Peer-Secret"))
		if existing.PeerSecret == "" || subtle.ConstantTimeCompare([]byte(existing.PeerSecret), []byte(suppliedSecret)) != 1 {
			writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
			return
		}
	}

	s.Allocator.ReleaseOwner(id)
	if existing.MeshIP != "" {
		s.Allocator.Release(existing.MeshIP)
	}
	s.Store.Remove(id)
	_ = s.Store.Save()
	s.Reconcile()
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (s *State) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.InfoSnapshot())
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if !s.checkServerToken(r, "") {
			writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
			return
		}
		var stats []tunnel.PeerRuntimeStats
		var relayed, dropped uint64
		var osUp bool
		s.mu.RLock()
		tun := s.Tunnel
		iso := s.Cfg.GetIsolation()
		s.mu.RUnlock()
		if tun != nil {
			stats, _ = tun.PeerStats()
			osUp = tun.HasOSInterface()
			if rt := tun.Router(); rt != nil {
				relayed = rt.RelayedPackets.Load()
				dropped = rt.DroppedPolicy.Load()
			}
		}
		writeJSON(w, http.StatusOK, StatusResp{
			Info:           s.InfoSnapshot(),
			Peers:          s.Store.PublicList(),
			TunnelStats:    stats,
			RelayedPackets: relayed,
			DroppedPolicy:  dropped,
			OSInterfaceUp:  osUp,
			Isolation:      iso,
		})
	})

	// Smart zero-setup client provisioning endpoint
	mux.HandleFunc("/join", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		var req RegisterReq
		if r.Body != nil {
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil && err != io.EOF {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
		}
		resp, code, err := s.provisionPeer(r, req, false)
		if err != nil {
			writeErr(w, code, err)
			return
		}
		writeJSON(w, code, resp)
	})

	// Lightweight client heartbeat + topology sync check
	mux.HandleFunc("/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		var req HeartbeatReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		p, ok := s.Store.Get(req.PeerID)
		if !ok {
			writeErr(w, http.StatusNotFound, fmt.Errorf("peer %q not registered", req.PeerID))
			return
		}
		if p.PeerSecret != "" && subtle.ConstantTimeCompare([]byte(p.PeerSecret), []byte(req.PeerSecret)) != 1 && !s.checkServerToken(r, "") {
			writeErr(w, http.StatusUnauthorized, fmt.Errorf("invalid peer secret"))
			return
		}
		s.Store.UpdateLastSeen(req.PeerID, time.Now().Unix(), req.Endpoint)
		writeJSON(w, http.StatusOK, HeartbeatResp{
			OK:      true,
			Version: s.version.Load(),
			MeshIP:  p.MeshIP,
			Server:  s.InfoSnapshot(),
			Peers:   s.Store.PublicList(),
		})
	})

	// Real-time Server-Sent Events push stream so clients learn peer/policy updates in <10ms
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if !s.checkServerToken(r, "") {
			// Also allow registered peers presenting their own PeerID + PeerSecret headers!
			peerID := strings.TrimSpace(r.Header.Get("X-Cerberus-Peer-ID"))
			secret := strings.TrimSpace(r.Header.Get("X-Cerberus-Peer-Secret"))
			p, ok := s.Store.Get(peerID)
			if !ok || p.PeerSecret == "" || subtle.ConstantTimeCompare([]byte(p.PeerSecret), []byte(secret)) != 1 {
				writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
				return
			}
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("streaming unsupported"))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		curVer, ch, unsub := s.subscribeEvents()
		defer unsub()

		_, _ = fmt.Fprintf(w, "data: {\"version\":%d}\n\n", curVer)
		flusher.Flush()

		keepAlive := time.NewTicker(20 * time.Second)
		defer keepAlive.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case <-s.ServerCtx.Done():
				return
			case ver := <-ch:
				_, _ = fmt.Fprintf(w, "data: {\"version\":%d}\n\n", ver)
				flusher.Flush()
			case <-keepAlive.C:
				_, _ = fmt.Fprintf(w, ": ping\n\n")
				flusher.Flush()
			}
		}
	})

	// Single-port HTTP Upgrade transport for encrypted WireGuard frames when raw UDP is firewalled
	mux.HandleFunc("/wg-tunnel", func(w http.ResponseWriter, r *http.Request) {
		peerID := strings.TrimSpace(r.Header.Get("X-Cerberus-Peer-ID"))
		secret := strings.TrimSpace(r.Header.Get("X-Cerberus-Peer-Secret"))
		p, ok := s.Store.Get(peerID)
		if !ok {
			writeErr(w, http.StatusNotFound, fmt.Errorf("unknown peer %q", peerID))
			return
		}
		if p.PeerSecret != "" && subtle.ConstantTimeCompare([]byte(p.PeerSecret), []byte(secret)) != 1 && !s.checkServerToken(r, "") {
			writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized peer stream"))
			return
		}

		s.mu.RLock()
		tun := s.Tunnel
		s.mu.RUnlock()
		if tun == nil {
			writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("server tunnel not active"))
			return
		}

		hj, ok := w.(http.Hijacker)
		if !ok {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("http connection hijack requires HTTP/1.1"))
			return
		}
		rawConn, brw, err := hj.Hijack()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		_, err = rawConn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: cerberus-wg/1\r\n\r\n"))
		if err != nil {
			_ = rawConn.Close()
			return
		}

		streamID := "peer-" + peerID
		// Point this peer's WireGuard endpoint to the authenticated persistent TCP stream immediately!
		p.Endpoint = "tcp://" + streamID
		p.LastSeen = time.Now().Unix()
		_ = s.Store.Add(p)
		s.Reconcile()

		var br *bufio.Reader
		if brw != nil {
			br = brw.Reader
		}
		tun.Bind().AttachStream(s.ServerCtx, streamID, rawConn, br)
	})

	// Live mesh ping helper endpoint (used by `cerberus ping <ip>`)
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		if !s.checkServerToken(r, "") {
			writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
			return
		}
		var req struct {
			Target    string `json:"target"`
			TimeoutMS int    `json:"timeout_ms"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		targetIP := strings.TrimSpace(req.Target)
		// Allow pinging by peer name or ID too!
		for _, p := range s.Store.List() {
			if p.Name == targetIP || p.ID == targetIP {
				targetIP = p.MeshIP
				break
			}
		}
		s.mu.RLock()
		tun := s.Tunnel
		s.mu.RUnlock()
		if tun == nil {
			writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("tunnel not running"))
			return
		}
		timeout := 3 * time.Second
		if req.TimeoutMS > 0 {
			timeout = time.Duration(req.TimeoutMS) * time.Millisecond
		}
		rtt, err := tun.Ping(r.Context(), targetIP, timeout)
		if err != nil {
			writeErr(w, http.StatusGatewayTimeout, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"target": targetIP,
			"rtt_ms": float64(rtt.Microseconds()) / 1000.0,
		})
	})

	// Live isolation rule control API
	mux.HandleFunc("/isolation", func(w http.ResponseWriter, r *http.Request) {
		if !s.checkServerToken(r, "") {
			writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, s.Cfg.GetIsolation())
		case http.MethodPost:
			var req IsolationRuleReq
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			s.Cfg.SetIsolation(func(iso *config.IsolationConfig) {
				if req.Enabled != nil {
					iso.Enabled = *req.Enabled
				}
				if req.DefaultDeny != nil {
					iso.DefaultDeny = *req.DefaultDeny
				}
			})
			if s.CfgPath != "" {
				_ = s.Cfg.Save(s.CfgPath)
			}
			s.Reconcile()
			writeJSON(w, http.StatusOK, s.Cfg.GetIsolation())
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/isolation/block", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !s.checkServerToken(r, "") {
			writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
			return
		}
		var req IsolationRuleReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		rule := strings.TrimSpace(req.Src)
		if req.Dst != "" {
			rule = fmt.Sprintf("%s->%s", strings.TrimSpace(req.Src), strings.TrimSpace(req.Dst))
		}
		if rule == "" {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("src required"))
			return
		}
		s.Cfg.SetIsolation(func(iso *config.IsolationConfig) {
			iso.Enabled = true
			iso.AllowedPeers = removeRule(iso.AllowedPeers, rule)
			iso.BlockedPeers = addUniqueRule(iso.BlockedPeers, rule)
		})
		if s.CfgPath != "" {
			_ = s.Cfg.Save(s.CfgPath)
		}
		s.Reconcile()
		writeJSON(w, http.StatusOK, s.Cfg.GetIsolation())
	})

	mux.HandleFunc("/isolation/allow", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !s.checkServerToken(r, "") {
			writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
			return
		}
		var req IsolationRuleReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		rule := strings.TrimSpace(req.Src)
		if req.Dst != "" {
			rule = fmt.Sprintf("%s->%s", strings.TrimSpace(req.Src), strings.TrimSpace(req.Dst))
		}
		if rule == "" {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("src required"))
			return
		}
		s.Cfg.SetIsolation(func(iso *config.IsolationConfig) {
			// Also remove both single-peer quarantine and matching directional/bidirectional blocks
			iso.BlockedPeers = removeMatchingBlocks(iso.BlockedPeers, strings.TrimSpace(req.Src), strings.TrimSpace(req.Dst))
			iso.AllowedPeers = addUniqueRule(iso.AllowedPeers, rule)
		})
		if s.CfgPath != "" {
			_ = s.Cfg.Save(s.CfgPath)
		}
		s.Reconcile()
		writeJSON(w, http.StatusOK, s.Cfg.GetIsolation())
	})

	// Backward-compatible /peers REST collection
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if !s.checkServerToken(r, "") {
				peerID := strings.TrimSpace(r.Header.Get("X-Cerberus-Peer-ID"))
				secret := strings.TrimSpace(r.Header.Get("X-Cerberus-Peer-Secret"))
				p, ok := s.Store.Get(peerID)
				if !ok || p.PeerSecret == "" || subtle.ConstantTimeCompare([]byte(p.PeerSecret), []byte(secret)) != 1 {
					writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
					return
				}
			}
			writeJSON(w, http.StatusOK, s.Store.PublicList())
		case http.MethodPost:
			var req RegisterReq
			if r.Body != nil {
				if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil && err != io.EOF {
					writeErr(w, http.StatusBadRequest, err)
					return
				}
			}
			resp, code, err := s.provisionPeer(r, req, true)
			if err != nil {
				writeErr(w, code, err)
				return
			}
			out := resp.Peer
			// Include PresharedKey & PeerSecret only for the newly registered caller
			out.PresharedKey = resp.PresharedKey
			out.PeerSecret = resp.PeerSecret
			writeJSON(w, code, out)
		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			s.handleDeletePeer(w, r, id)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/peers/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/peers/")
		if r.Method == http.MethodDelete {
			s.handleDeletePeer(w, r, id)
			return
		}
		writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	})

	return mux
}

func addUniqueRule(list []string, rule string) []string {
	for _, r := range list {
		if r == rule {
			return list
		}
	}
	return append(list, rule)
}

func removeRule(list []string, target string) []string {
	out := make([]string, 0, len(list))
	for _, r := range list {
		if r != target {
			out = append(out, r)
		}
	}
	return out
}

func removeMatchingBlocks(list []string, src, dst string) []string {
	out := make([]string, 0, len(list))
	fwd := fmt.Sprintf("%s->%s", src, dst)
	comma1 := fmt.Sprintf("%s,%s", src, dst)
	comma2 := fmt.Sprintf("%s,%s", dst, src)
	bi1 := fmt.Sprintf("%s<->%s", src, dst)
	bi2 := fmt.Sprintf("%s<->%s", dst, src)
	for _, r := range list {
		if r == fwd || r == comma1 || r == comma2 || r == bi1 || r == bi2 || (dst == "" && r == src) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// Client communicates with a remote or local Cerberus control plane.
type Client struct {
	BaseURL    string
	AuthToken  string
	PeerID     string
	PeerSecret string
	HTTP       *http.Client
}

func NewClient(baseURL string) *Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 16,
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP: &http.Client{
			Timeout:   15 * time.Second,
			Transport: tr,
		},
	}
}

func (c *Client) addHeaders(req *http.Request) {
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}
	if c.PeerID != "" {
		req.Header.Set("X-Cerberus-Peer-ID", c.PeerID)
	}
	if c.PeerSecret != "" {
		req.Header.Set("X-Cerberus-Peer-Secret", c.PeerSecret)
	}
}

func (c *Client) Info() (*InfoResp, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/info", nil)
	if err != nil {
		return nil, err
	}
	c.addHeaders(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("info: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var info InfoResp
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *Client) Status() (*StatusResp, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/status", nil)
	if err != nil {
		return nil, err
	}
	c.addHeaders(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var st StatusResp
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Join calls POST /join to perform smart zero-config onboarding (auto-assigned keys, IP, PSK, server config & peers).
func (c *Client) Join(req RegisterReq) (*JoinResp, error) {
	if req.Token == "" && c.AuthToken != "" {
		req.Token = c.AuthToken
	}
	if req.PeerID == "" && c.PeerID != "" {
		req.PeerID = c.PeerID
	}
	if req.PeerSecret == "" && c.PeerSecret != "" {
		req.PeerSecret = c.PeerSecret
	}
	b, _ := json.Marshal(req)
	hreq, err := http.NewRequest(http.MethodPost, c.BaseURL+"/join", strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	c.addHeaders(hreq)

	resp, err := c.HTTP.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("join: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var jr JoinResp
	if err := json.NewDecoder(resp.Body).Decode(&jr); err != nil {
		return nil, err
	}
	c.PeerID = jr.Peer.ID
	c.PeerSecret = jr.PeerSecret
	return &jr, nil
}

func (c *Client) Heartbeat(endpoint string) (*HeartbeatResp, error) {
	b, _ := json.Marshal(HeartbeatReq{
		PeerID:     c.PeerID,
		PeerSecret: c.PeerSecret,
		Endpoint:   endpoint,
	})
	hreq, err := http.NewRequest(http.MethodPost, c.BaseURL+"/heartbeat", strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	c.addHeaders(hreq)

	resp, err := c.HTTP.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("heartbeat: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var hr HeartbeatResp
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		return nil, err
	}
	return &hr, nil
}

// WatchEvents subscribes to SSE /events and calls onUpdate whenever server topology or isolation rules change.
func (c *Client) WatchEvents(ctx context.Context, onUpdate func(version uint64)) error {
	streamHTTP := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/events", nil)
	if err != nil {
		return err
	}
	c.addHeaders(hreq)
	resp, err := streamHTTP.Do(hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("events status: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		var msg struct {
			Version uint64 `json:"version"`
		}
		if err := json.Unmarshal([]byte(payload), &msg); err == nil && msg.Version > 0 {
			onUpdate(msg.Version)
		}
	}
	return sc.Err()
}

func (c *Client) ListPeers() ([]store.Peer, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/peers", nil)
	if err != nil {
		return nil, err
	}
	c.addHeaders(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list peers: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var peers []store.Peer
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		return nil, err
	}
	return peers, nil
}

func (c *Client) Register(req RegisterReq) (*store.Peer, error) {
	if req.Token == "" && c.AuthToken != "" {
		req.Token = c.AuthToken
	}
	b, _ := json.Marshal(req)
	hreq, err := http.NewRequest(http.MethodPost, c.BaseURL+"/peers", strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	c.addHeaders(hreq)
	resp, err := c.HTTP.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("register: %s: %s", resp.Status, strings.TrimSpace(string(body)) )
	}
	var p store.Peer
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (c *Client) DeletePeer(id string) error {
	req, err := http.NewRequest(http.MethodDelete, c.BaseURL+"/peers/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	c.addHeaders(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) PingPeer(target string, timeout time.Duration) (float64, string, error) {
	b, _ := json.Marshal(map[string]interface{}{
		"target":     target,
		"timeout_ms": int(timeout.Milliseconds()),
	})
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/ping", strings.NewReader(string(b)))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	c.addHeaders(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, "", fmt.Errorf("ping: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out struct {
		Target string  `json:"target"`
		RTTMS  float64 `json:"rtt_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, "", err
	}
	return out.RTTMS, out.Target, nil
}

func (c *Client) BlockPeers(src, dst string) (*config.IsolationConfig, error) {
	return c.postIsolation("/isolation/block", IsolationRuleReq{Src: src, Dst: dst})
}

func (c *Client) AllowPeers(src, dst string) (*config.IsolationConfig, error) {
	return c.postIsolation("/isolation/allow", IsolationRuleReq{Src: src, Dst: dst})
}

func (c *Client) SetIsolationPolicy(enabled, defaultDeny bool) (*config.IsolationConfig, error) {
	return c.postIsolation("/isolation", IsolationRuleReq{Enabled: &enabled, DefaultDeny: &defaultDeny})
}

func (c *Client) postIsolation(path string, payload IsolationRuleReq) (*config.IsolationConfig, error) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.addHeaders(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("isolation: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var iso config.IsolationConfig
	if err := json.NewDecoder(resp.Body).Decode(&iso); err != nil {
		return nil, err
	}
	return &iso, nil
}

// ServeListener starts the HTTP/2 + HTTP/1.1 Upgrade server on an already-bound net.Listener
// and cleanly shuts down when ctx cancels.
func ServeListener(ctx context.Context, state *State, ln net.Listener) error {
	srv := &http.Server{
		Handler:           h2c.NewHandler(state.Handler(), &http2.Server{}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	var err error
	if state.Cfg.TLS.CertFile != "" && state.Cfg.TLS.KeyFile != "" {
		err = srv.ServeTLS(ln, state.Cfg.TLS.CertFile, state.Cfg.TLS.KeyFile)
	} else {
		err = srv.Serve(ln)
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Serve starts an HTTP server on addr (retained for backwards compatibility).
func Serve(cfg *config.Config, st *store.Store, addr string) error {
	state, err := NewState(cfg, st)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ServeListener(context.Background(), state, ln)
}
