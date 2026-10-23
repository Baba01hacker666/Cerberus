package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Baba01hacker666/cerberus/internal/control"
	"github.com/Baba01hacker666/cerberus/internal/mesh"
	"github.com/Baba01hacker666/cerberus/internal/store"
	"github.com/Baba01hacker666/cerberus/internal/tunnel"
)

type ClientOptions struct {
	ServerAddr     string // e.g. "1.2.3.4:7443" or "http://1.2.3.4:7443"
	Name           string // optional; defaults to OS hostname
	Interface      string // default "cerberus0"
	ListenPort     int    // default 0 = OS ephemeral port (zero conflict!)
	Endpoint       string // optional explicit public endpoint
	Token          string // optional server auth token
	StateDir       string // optional local state dir to preserve identity/IP across restarts
	Ephemeral      bool   // if true, generate brand-new identity without persisting state, and deregister on exit
	UserspaceOnly  bool   // skip kernel TUN device (used in unprivileged mode & unit tests)
	ForceTCP       bool   // force WireGuard-over-TCP single-port transport
	ProbeTimeout   time.Duration
}

type savedClientIdentity struct {
	ServerURL    string `json:"server_url"`
	PeerID       string `json:"peer_id"`
	PeerSecret   string `json:"peer_secret"`
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	MeshIP       string `json:"mesh_ip"`
}

// Client manages a zero-setup Cerberus mesh client node:
//   1. Contacts the Smart Server on its single open port and auto-receives keys, PSK, IP, and topology
//   2. Automatically probes native WireGuard UDP on that port and uses native UDP if reachable,
//      OR seamlessly tunnels encrypted WireGuard over HTTP-Upgrade TCP on the exact same port if UDP is blocked
//   3. Subscribes to live SSE updates + periodic heartbeats so new peers are discovered immediately
type Client struct {
	opts      ClientOptions
	api       *control.Client
	Tunnel    *tunnel.Tunnel
	JoinInfo  *control.JoinResp
	Transport string // "wireguard-udp" or "wireguard-tcp"

	peersMu sync.RWMutex
	peers   []store.Peer

	stopOnce sync.Once
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func normalizeServerURL(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("server address required")
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid server url %q: %w", raw, err)
	}
	host := u.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("invalid server host in %q", raw)
	}
	// If no port specified, default to Cerberus port 7443!
	if u.Port() == "" {
		u.Host = net.JoinHostPort(host, "7443")
	}
	return strings.TrimRight(u.String(), "/"), host, nil
}

func StartClient(parentCtx context.Context, opts ClientOptions) (*Client, error) {
	baseURL, serverHost, err := normalizeServerURL(opts.ServerAddr)
	if err != nil {
		return nil, err
	}
	if opts.Name == "" {
		h, _ := os.Hostname()
		if h == "" {
			h = "cerberus-client"
		}
		opts.Name = h
	}
	if opts.Interface == "" {
		opts.Interface = "cerberus0"
	}
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = 350 * time.Millisecond
	}

	// Restore persisted identity if StateDir is set and not Ephemeral so restarts keep the exact same IP & keys!
	var saved savedClientIdentity
	stateFile := ""
	if !opts.Ephemeral && opts.StateDir != "" {
		stateFile = filepath.Join(opts.StateDir, "client-state.json")
		if b, err := os.ReadFile(stateFile); err == nil {
			_ = json.Unmarshal(b, &saved)
			if saved.ServerURL != "" && saved.ServerURL != baseURL {
				// Connecting to a different server: request fresh credentials cleanly
				saved = savedClientIdentity{}
			}
		}
	}

	api := control.NewClient(baseURL)
	api.AuthToken = opts.Token
	api.PeerID = saved.PeerID
	api.PeerSecret = saved.PeerSecret

	// ZERO-SETUP SMART PROVISIONING:
	// Notice that on first run, PublicKey AND MeshIP are BOTH empty ("") — the Smart Server generates
	// our X25519 keypair, generates a 256-bit PresharedKey, allocates our MeshIP, configures server WireGuard
	// immediately, and hands back everything in one atomic HTTP round trip!
	joinResp, err := api.Join(control.RegisterReq{
		PeerID:     saved.PeerID,
		PeerSecret: saved.PeerSecret,
		Token:      opts.Token,
		Name:       opts.Name,
		PublicKey:  saved.PublicKey,
		Endpoint:   opts.Endpoint,
		MeshIP:     saved.MeshIP,
	})
	if err != nil {
		return nil, err
	}

	privKey := joinResp.PrivateKey
	if privKey == "" {
		privKey = saved.PrivateKey
	}
	pubKey := joinResp.Peer.PublicKey
	psk := joinResp.PresharedKey
	if psk == "" {
		psk = saved.PresharedKey
	}

	// Persist identity safely (0600) so future restarts reconnect with identical keys & IP
	if stateFile != "" && privKey != "" {
		_ = os.MkdirAll(opts.StateDir, 0o700)
		if b, err := json.MarshalIndent(savedClientIdentity{
			ServerURL:    baseURL,
			PeerID:       joinResp.Peer.ID,
			PeerSecret:   joinResp.PeerSecret,
			PrivateKey:   privKey,
			PublicKey:    pubKey,
			PresharedKey: psk,
			MeshIP:       joinResp.Peer.MeshIP,
		}, "", "  "); err == nil {
			_ = os.WriteFile(stateFile, b, 0o600)
		}
	}

	meshIPPrefix := mesh.MeshIPWithPrefix(joinResp.Peer.MeshIP, joinResp.Server.MeshCIDR)
	mtu := joinResp.Server.MTU
	if mtu <= 0 {
		mtu = tunnel.MTU
	}

	ctx, cancel := context.WithCancel(parentCtx)

	tun := tunnel.New(tunnel.TunnelConfig{
		Name:          opts.Interface,
		PrivateKey:    privKey,
		PublicKey:     pubKey,
		MeshIP:        meshIPPrefix,
		ListenPort:    opts.ListenPort,
		MTU:           mtu,
		IsServer:      false,
		UserspaceOnly: opts.UserspaceOnly,
		ForceTCP:      opts.ForceTCP,
	})
	if err := tun.Start(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("start client wireguard tunnel: %w", err)
	}

	cl := &Client{
		opts:     opts,
		api:      api,
		Tunnel:   tun,
		JoinInfo: joinResp,
		peers:    joinResp.Peers,
		cancel:   cancel,
	}

	// Determine optimal WireGuard transport to the server:
	//   1. Probe native WireGuard UDP on <serverHost>:<UDPPort>
	//   2. If UDP responds within ProbeTimeout -> use zero-overhead native WireGuard UDP!
	//   3. Otherwise -> automatically establish single-port HTTP-Upgrade TCP transport on /wg-tunnel!
	udpEndpoint := joinResp.Server.Endpoint
	if udpEndpoint == "" {
		udpEndpoint = net.JoinHostPort(serverHost, strconv.Itoa(joinResp.Server.UDPPort))
	}

	var serverWGEndpoint string
	if !opts.ForceTCP {
		if _, err := tun.Bind().ProbeUDP(ctx, udpEndpoint, opts.ProbeTimeout); err == nil {
			serverWGEndpoint = udpEndpoint
			cl.Transport = "wireguard-udp"
		}
	}

	if serverWGEndpoint == "" {
		cl.Transport = "wireguard-tcp"
		serverWGEndpoint = "tcp://server"
		ready := make(chan struct{})
		cl.wg.Add(1)
		go func() {
			defer cl.wg.Done()
			tun.Bind().MaintainClientStream(
				ctx,
				baseURL,
				"server",
				joinResp.Peer.ID,
				joinResp.PeerSecret,
				opts.Token,
				func() { close(ready) },
			)
		}()
		select {
		case <-ready:
		case <-time.After(3 * time.Second):
			cl.Stop()
			return nil, fmt.Errorf("failed to establish single-port tcp tunnel to %s", baseURL)
		case <-ctx.Done():
			cl.Stop()
			return nil, ctx.Err()
		}
	}

	ka := joinResp.Server.Keepalive
	if ka <= 0 {
		ka = 20
	}

	// Configure server as WireGuard hub router for the entire MeshCIDR!
	// Because Server has AllowedIPs = MeshCIDR (e.g. 10.77.0.0/16), BOTH client<->server (10.77.0.1)
	// AND client<->client (10.77.0.2 <-> 10.77.0.3, even across double symmetric NATs!) work immediately!
	tun.UpdatePeers([]tunnel.PeerConfig{
		{
			Index:        1,
			PublicKey:    joinResp.Server.PublicKey,
			PresharedKey: psk,
			Endpoint:     serverWGEndpoint,
			MeshIP:       joinResp.Server.MeshIP,
			AllowedIPs:   []string{joinResp.Server.MeshCIDR},
			Keepalive:    ka,
		},
	})

	// Perform initial WireGuard handshake verification ping to server gateway (.1) in background / warm start
	if joinResp.Server.MeshIP != "" {
		_, _ = tun.Ping(ctx, joinResp.Server.MeshIP, 500*time.Millisecond)
	}

	// Start background heartbeat + live SSE topology watcher
	cl.wg.Add(2)
	go func() {
		defer cl.wg.Done()
		cl.heartbeatLoop(ctx)
	}()
	go func() {
		defer cl.wg.Done()
		cl.watchEventsLoop(ctx)
	}()

	return cl, nil
}

func (c *Client) MeshIP() string {
	return c.JoinInfo.Peer.MeshIP
}

func (c *Client) ServerMeshIP() string {
	return c.JoinInfo.Server.MeshIP
}

func (c *Client) PeerID() string {
	return c.JoinInfo.Peer.ID
}

func (c *Client) Peers() []store.Peer {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()
	out := make([]store.Peer, len(c.peers))
	for i, p := range c.peers {
		out[i] = p.Clone()
	}
	return out
}

func (c *Client) Ping(ctx context.Context, dstIP string, timeout time.Duration) (time.Duration, error) {
	return c.Tunnel.Ping(ctx, dstIP, timeout)
}

func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		if c.opts.Ephemeral && c.api != nil && c.JoinInfo != nil {
			_ = c.api.DeletePeer(c.JoinInfo.Peer.ID)
		}
		c.cancel()
		c.Tunnel.Stop()
		c.wg.Wait()
	})
}

func (c *Client) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if hr, err := c.api.Heartbeat(c.opts.Endpoint); err == nil {
				c.peersMu.Lock()
				c.peers = hr.Peers
				c.peersMu.Unlock()
			}
		}
	}
}

func (c *Client) watchEventsLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		_ = c.api.WatchEvents(ctx, func(_ uint64) {
			if peers, err := c.api.ListPeers(); err == nil {
				c.peersMu.Lock()
				c.peers = peers
				c.peersMu.Unlock()
			}
		})
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Second):
		}
	}
}
