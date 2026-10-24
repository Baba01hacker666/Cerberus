package node

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Baba01hacker666/cerberus/internal/config"
	"github.com/Baba01hacker666/cerberus/internal/control"
	"github.com/Baba01hacker666/cerberus/internal/docker"
	"github.com/Baba01hacker666/cerberus/internal/isolation"
	"github.com/Baba01hacker666/cerberus/internal/store"
	"github.com/Baba01hacker666/cerberus/internal/tunnel"
)

type ServerOptions struct {
	Config     *config.Config
	ConfigPath string
	ForceTCP   bool // disable UDP to simulate strict TCP-only firewall
}

// Server runs a full Cerberus hub + mesh coordinator (HTTP/2 control plane, SSE push,
// single-port TCP fallback relay, WireGuard tunnel engine, userspace/iptables firewall,
// peer sync, and Docker label auto-discovery).
type Server struct {
	Cfg      *config.Config
	CfgPath  string
	Store    *store.Store
	Policy   *isolation.PolicyEngine
	Firewall *isolation.Manager
	Tunnel   *tunnel.Tunnel
	State    *control.State

	ln         net.Listener
	listenAddr string

	stopOnce sync.Once
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func StartServer(parentCtx context.Context, opts ServerOptions) (*Server, error) {
	c := opts.Config
	if c == nil {
		c = config.DefaultServerConfig()
	}

	if c.PrivateKey == "" {
		priv, pub, err := tunnel.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generate server keys: %w", err)
		}
		c.PrivateKey = priv
		c.PublicKey = pub
		if opts.ConfigPath != "" {
			_ = c.Save(opts.ConfigPath)
		}
	} else if c.PublicKey == "" {
		if pub, err := tunnel.PublicKeyFromPrivate(c.PrivateKey); err == nil {
			c.PublicKey = pub
		}
	}

	// Bind TCP listener FIRST so if ListenAddr uses port :0, we immediately bind the exact same port
	// on UDP whenever free (single-port server UX!).
	ln, err := net.Listen("tcp", c.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen tcp %s: %w", c.ListenAddr, err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	actualListenAddr := ln.Addr().String()

	desiredUDPPort := c.UDPPort
	if desiredUDPPort == 0 {
		desiredUDPPort = tcpAddr.Port
	}

	st := store.New(c.DataDir)
	pol := isolation.NewPolicyEngine()
	isoMgr := isolation.New("CERBERUS")
	if c.Isolation.Enabled && isolation.CanUseIptables() {
		isoMgr.EnsureChainNoErr()
	}

	ctx, cancel := context.WithCancel(parentCtx)

	// Determine server MeshIP from allocator (.1) before starting tunnel
	tmpState, err := control.NewStateWithOptions(c, st, control.StateOptions{
		ConfigPath: opts.ConfigPath,
		Policy:     pol,
		Firewall:   isoMgr,
		Context:    ctx,
	})
	if err != nil {
		cancel()
		_ = ln.Close()
		return nil, err
	}

	meshPrefix := tunnel.MeshIPWithPrefix(c.MeshIP, c.MeshCIDR)
	tun := tunnel.New(tunnel.TunnelConfig{
		Name:          c.Interface,
		PrivateKey:    c.PrivateKey,
		PublicKey:     c.PublicKey,
		MeshIP:        meshPrefix,
		ListenPort:    desiredUDPPort,
		MTU:           c.MTU,
		IsServer:      true,
		UserspaceOnly: c.UserspaceOnly,
		ForceTCP:      opts.ForceTCP,
		Policy:        pol,
		CAFile:        c.TLS.CAFile,
	})
	if err := tun.Start(ctx); err != nil && desiredUDPPort != 0 {
		// If the exact UDP port happened to be occupied by another UDP service on host, fall back cleanly to any free UDP port!
		tun = tunnel.New(tunnel.TunnelConfig{
			Name:          c.Interface,
			PrivateKey:    c.PrivateKey,
			PublicKey:     c.PublicKey,
			MeshIP:        meshPrefix,
			ListenPort:    0,
			MTU:           c.MTU,
			IsServer:      true,
			UserspaceOnly: c.UserspaceOnly,
			ForceTCP:      opts.ForceTCP,
			Policy:        pol,
			CAFile:        c.TLS.CAFile,
		})
		if err2 := tun.Start(ctx); err2 != nil {
			cancel()
			_ = ln.Close()
			return nil, fmt.Errorf("start server wireguard tunnel: %w", err2)
		}
	}

	tmpState.Tunnel = tun
	tmpState.Reconcile()

	srv := &Server{
		Cfg:        c,
		CfgPath:    opts.ConfigPath,
		Store:      st,
		Policy:     pol,
		Firewall:   isoMgr,
		Tunnel:     tun,
		State:      tmpState,
		ln:         ln,
		listenAddr: actualListenAddr,
		cancel:     cancel,
	}

	if c.Docker.AutoAdd {
		srv.wg.Add(1)
		go func() {
			defer srv.wg.Done()
			srv.autoAddLoop(ctx)
		}()
	}

	if len(c.Peers) > 0 {
		srv.wg.Add(1)
		go func() {
			defer srv.wg.Done()
			srv.syncLoop(ctx)
		}()
	}

	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		if err := control.ServeListener(ctx, tmpState, ln); err != nil {
			cancel()
		}
	}()

	return srv, nil
}

func (s *Server) ListenAddr() string {
	return s.listenAddr
}

func (s *Server) BaseURL() string {
	scheme := "http"
	if s.Cfg.TLS.CertFile != "" && s.Cfg.TLS.KeyFile != "" {
		scheme = "https"
	}
	host, port, err := net.SplitHostPort(s.listenAddr)
	if err == nil && (host == "0.0.0.0" || host == "::" || host == "") {
		host = "127.0.0.1"
	}
	if err == nil {
		return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, port))
	}
	return fmt.Sprintf("%s://%s", scheme, s.listenAddr)
}

func (s *Server) UDPPort() int {
	return s.Tunnel.ActualUDPPort()
}

func (s *Server) MeshIP() string {
	return s.Cfg.MeshIP
}

func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		s.cancel()
		_ = s.ln.Close()
		s.Tunnel.Stop()
		s.wg.Wait()
	})
}

func (s *Server) autoAddLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	s.scanContainersOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scanContainersOnce()
		}
	}
}

func (s *Server) scanContainersOnce() {
	containers, err := docker.ListContainers(s.Cfg.Docker.Socket, s.Cfg.Docker.LabelFilter)
	if err != nil {
		return
	}
	changed := false
	for _, cont := range containers {
		if !docker.LabelMatches(cont.Labels, s.Cfg.Docker.LabelFilter) {
			continue
		}
		id := "ctr-" + docker.ShortID(cont.ID)
		if _, ok := s.Store.Get(id); ok {
			continue
		}
		ip, err := s.State.Allocator.AllocateForOwner(id, "")
		if err != nil {
			continue
		}
		pub := cont.Labels["cerberus.public-key"]
		psk, _ := tunnel.GeneratePresharedKey()
		peer := store.Peer{
			ID:           id,
			Name:         strings.TrimPrefix(cont.Names, "/"),
			PublicKey:    pub,
			PresharedKey: psk,
			MeshIP:       ip,
			AllowedIPs:   []string{ip + "/32"},
			Container:    cont.ID,
			Labels:       cont.Labels,
			Isolated:     cont.Labels["cerberus.isolate"] == "true",
			LastSeen:     docker.Now(),
		}
		_ = s.Store.Add(peer)
		changed = true
	}
	if changed {
		_ = s.Store.Save()
		s.State.Reconcile()
	}
}

func (s *Server) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	s.syncPeersOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.syncPeersOnce()
		}
	}
}

func (s *Server) syncPeersOnce() {
	changed := false
	for _, p := range s.Cfg.Peers {
		base := p
		if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
			base = "http://" + base
		}
		cl := control.NewClient(base)
		cl.AuthToken = s.Cfg.AuthToken
		cl.CAFile = s.Cfg.TLS.CAFile
		info, err := cl.Info()
		if err != nil {
			continue
		}
		// Register self with peer server if needed and exchange peer tables
		peerHost, _, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://"))
		remoteEndpoint := info.Endpoint
		if remoteEndpoint == "" && peerHost != "" && info.UDPPort > 0 {
			remoteEndpoint = net.JoinHostPort(peerHost, strconv.Itoa(info.UDPPort))
		}
		if info.PublicKey != "" && info.PublicKey != s.Cfg.PublicKey && info.MeshIP != "" {
			if _, exists := s.Store.FindByPublicKey(info.PublicKey); !exists {
				_ = s.State.Allocator.ReserveForOwner("srv-"+info.NodeName, info.MeshIP)
				_ = s.Store.Add(store.Peer{
					ID:         "srv-" + info.NodeName,
					Name:       info.NodeName,
					PublicKey:  info.PublicKey,
					Endpoint:   remoteEndpoint,
					MeshIP:     info.MeshIP,
					AllowedIPs: []string{info.MeshIP + "/32"},
					LastSeen:   time.Now().Unix(),
				})
				changed = true
			}
		}
		peers, err := cl.ListPeers()
		if err != nil {
			continue
		}
		for _, rp := range peers {
			if rp.ID == "" || rp.PublicKey == s.Cfg.PublicKey {
				continue
			}
			if existing, ok := s.Store.Get(rp.ID); ok && existing.Container != "" {
				continue
			}
			// Do not clobber a local peer that has a different public key.
			if existing, ok := s.Store.Get(rp.ID); ok && existing.PublicKey != "" && existing.PublicKey != rp.PublicKey {
				continue
			}
			if rp.MeshIP != "" {
				if err := s.State.Allocator.ReserveForOwner(rp.ID, rp.MeshIP); err != nil {
					continue
				}
			}
			existing, exists := s.Store.Get(rp.ID)
			if exists {
				// Remote listings strip secrets; preserve local credentials and metadata
				// so a sync never breaks an existing peer's authentication.
				rp.PeerSecret = existing.PeerSecret
				rp.PresharedKey = existing.PresharedKey
				if rp.Name == "" {
					rp.Name = existing.Name
				}
				if rp.Container == "" {
					rp.Container = existing.Container
				}
				if rp.Labels == nil {
					rp.Labels = existing.Labels
				}
			}
			if !exists || existing.PublicKey != rp.PublicKey || existing.Endpoint != rp.Endpoint || existing.MeshIP != rp.MeshIP || !slices.Equal(existing.AllowedIPs, rp.AllowedIPs) {
				if err := s.Store.Add(rp); err == nil {
					changed = true
				}
			}
		}
	}
	if changed {
		_ = s.Store.Save()
		s.State.Reconcile()
	}
}
