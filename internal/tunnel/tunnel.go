package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Baba01hacker666/cerberus/internal/isolation"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type PeerConfig struct {
	Index        uint32
	PublicKey    string
	PresharedKey string
	Endpoint     string
	MeshIP       string
	AllowedIPs   []string
	Keepalive    int
}

type TunnelConfig struct {
	Name          string
	PrivateKey    string
	PublicKey     string
	MeshIP        string // e.g. "10.77.0.1/16" or "10.77.0.2/16"
	ListenPort    int    // 0 = auto-pick free UDP port
	MTU           int
	IsServer      bool // enables userspace hub-router mesh forwarding between peers
	UserspaceOnly bool // skips kernel /dev/net/tun even when running as root
	ForceTCP      bool // disables raw UDP so WireGuard tunnels strictly over single-port TCP
	VerboseLogs   bool
	Policy        *isolation.PolicyEngine
	CAFile        string // optional CA bundle for HTTPS control-plane verification
}

// PeerRuntimeStats reports real live cryptographic session metrics from wireguard-go.
type PeerRuntimeStats struct {
	PublicKey            string `json:"public_key"`
	Endpoint             string `json:"endpoint"`
	TxBytes              uint64 `json:"tx_bytes"`
	RxBytes              uint64 `json:"rx_bytes"`
	LastHandshakeTimeSec int64  `json:"last_handshake_sec"`
}

type appliedPeer struct {
	pubHex     string
	pskHex     string
	endpoint   string
	allowedIPs []string
	keepalive  int
}

type Tunnel struct {
	cfg TunnelConfig

	mu          sync.RWMutex
	reconcileMu sync.Mutex

	bind       *HybridBind
	router     *RouterTUN
	wgDev      *device.Device
	realIfName string
	running    bool
	stopOnce   sync.Once
	stopCh     chan struct{}

	activePeers     map[string]appliedPeer // keyed by hex public key
	lastDesired     []PeerConfig
	needsFullResync bool
}

func New(cfg TunnelConfig) *Tunnel {
	if cfg.Name == "" {
		cfg.Name = "cerberus0"
	}
	if cfg.MTU <= 0 {
		cfg.MTU = MTU
	}
	b := NewHybridBind()
	b.SetCAFile(cfg.CAFile)
	if cfg.ForceTCP {
		b.DisableUDP(true)
	}
	return &Tunnel{
		cfg:         cfg,
		bind:        b,
		stopCh:      make(chan struct{}),
		activePeers: make(map[string]appliedPeer),
	}
}

func (t *Tunnel) Bind() *HybridBind {
	return t.bind
}

func (t *Tunnel) Router() *RouterTUN {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.router
}

func (t *Tunnel) InterfaceName() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.realIfName != "" {
		return t.realIfName
	}
	return t.cfg.Name
}

func (t *Tunnel) ActualUDPPort() int {
	return t.bind.ActualUDPPort()
}

func (t *Tunnel) HasOSInterface() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.router != nil && t.router.HasOSDevice()
}

func (t *Tunnel) Available() bool {
	return Available()
}

// Available reports whether kernel OS TUN creation is available on this host.
// Note: Even when Available() returns false (e.g. non-root containers or unit tests),
// Tunnel.Start() still works 100% in userspace WireGuard mode!
func Available() bool {
	return osTunnelSupported()
}

func parseLocalMeshAddr(meshIP string) netip.Addr {
	s := strings.TrimSpace(meshIP)
	if s == "" {
		return netip.Addr{}
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.Addr().Unmap()
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		if a, ok := netip.AddrFromSlice(ip); ok {
			return a.Unmap()
		}
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}

func (t *Tunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return nil
	}

	privHex, err := KeyToHex(t.cfg.PrivateKey)
	if err != nil {
		t.mu.Unlock()
		return fmt.Errorf("invalid tunnel private key: %w", err)
	}

	var osDev tun.Device
	ifName := t.cfg.Name
	if !t.cfg.UserspaceOnly && osTunnelSupported() {
		dev, realName, err := createAndConfigureOSTUN(t.cfg.Name, t.cfg.MeshIP, t.cfg.MTU)
		if err == nil {
			osDev = dev
			ifName = realName
		}
		// If OS TUN fails (e.g. unprivileged Docker container without CAP_NET_ADMIN), seamlessly continue in userspace mode!
	}

	localAddr := parseLocalMeshAddr(t.cfg.MeshIP)
	router := NewRouterTUN(RouterTUNOptions{
		Name:     ifName,
		MTU:      t.cfg.MTU,
		Inner:    osDev,
		LocalIP:  localAddr,
		IsRouter: t.cfg.IsServer,
		Policy:   t.cfg.Policy,
	})

	logLevel := device.LogLevelSilent
	if t.cfg.VerboseLogs {
		logLevel = device.LogLevelVerbose
	}
	logger := device.NewLogger(logLevel, fmt.Sprintf("cerberus(%s) ", ifName))
	wgDev := device.NewDevice(router, t.bind, logger)

	var ipcCfg strings.Builder
	ipcCfg.WriteString(fmt.Sprintf("private_key=%s\n", privHex))
	ipcCfg.WriteString(fmt.Sprintf("listen_port=%d\n", t.cfg.ListenPort))
	if err := wgDev.IpcSet(ipcCfg.String()); err != nil {
		wgDev.Close()
		_ = router.Close()
		t.bind.Shutdown()
		t.mu.Unlock()
		return fmt.Errorf("wireguard ipc init: %w", err)
	}
	if err := wgDev.Up(); err != nil {
		wgDev.Close()
		_ = router.Close()
		t.bind.Shutdown()
		t.mu.Unlock()
		return fmt.Errorf("wireguard device up: %w", err)
	}

	t.router = router
	t.wgDev = wgDev
	t.realIfName = ifName
	t.running = true
	pending := append([]PeerConfig(nil), t.lastDesired...)
	t.mu.Unlock()

	if len(pending) > 0 {
		t.UpdatePeers(pending)
	}

	go func() {
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.stopCh:
		}
	}()
	return nil
}

func (t *Tunnel) Stop() {
	t.stopOnce.Do(func() {
		t.reconcileMu.Lock()
		defer t.reconcileMu.Unlock()
		close(t.stopCh)
		t.mu.Lock()
		t.running = false
		wgDev := t.wgDev
		router := t.router
		t.wgDev = nil
		t.mu.Unlock()

		if wgDev != nil {
			wgDev.Close()
		}
		if router != nil {
			_ = router.Close()
		}
		t.bind.Shutdown()
	})
}

// UpdatePeers incrementally reconciles the WireGuard peer configuration without resetting
// existing sessions, active Noise keys, or learned NAT roaming endpoints!
func (t *Tunnel) UpdatePeers(peers []PeerConfig) {
	t.reconcileMu.Lock()
	defer t.reconcileMu.Unlock()

	t.mu.Lock()
	cpDesired := make([]PeerConfig, len(peers))
	for i, p := range peers {
		cpDesired[i] = p
		if p.AllowedIPs != nil {
			cpDesired[i].AllowedIPs = append([]string(nil), p.AllowedIPs...)
		}
	}
	t.lastDesired = cpDesired
	wgDev := t.wgDev
	router := t.router
	running := t.running
	selfPub := t.cfg.PublicKey
	t.mu.Unlock()

	if !running || wgDev == nil {
		return
	}

	fullResync := t.needsFullResync
	if fullResync {
		t.activePeers = make(map[string]appliedPeer)
	}

	// Update RouterTUN peer IP set first so any hairpinned mesh traffic routes immediately
	meshIPs := make([]string, 0, len(peers))
	desiredMap := make(map[string]appliedPeer, len(peers))

	for _, pc := range peers {
		if pc.PublicKey == "" || pc.PublicKey == selfPub {
			continue
		}
		pubHex, err := KeyToHex(pc.PublicKey)
		if err != nil {
			continue
		}
		var pskHex string
		if pc.PresharedKey != "" {
			if h, err := KeyToHex(pc.PresharedKey); err == nil {
				pskHex = h
			}
		}
		var allowed []string
		if len(pc.AllowedIPs) > 0 {
			for _, a := range pc.AllowedIPs {
				if _, err := netip.ParsePrefix(a); err == nil {
					allowed = append(allowed, a)
				}
			}
		} else if pc.MeshIP != "" {
			if strings.Contains(pc.MeshIP, "/") {
				if _, err := netip.ParsePrefix(pc.MeshIP); err == nil {
					allowed = []string{pc.MeshIP}
				}
			} else {
				cidr := pc.MeshIP + "/32"
				if _, err := netip.ParsePrefix(cidr); err == nil {
					allowed = []string{cidr}
				}
			}
		}
		if len(allowed) == 0 {
			continue
		}
		sort.Strings(allowed)
		if pc.MeshIP != "" {
			meshIPs = append(meshIPs, strings.Split(pc.MeshIP, "/")[0])
		}
		desiredMap[pubHex] = appliedPeer{
			pubHex:     pubHex,
			pskHex:     pskHex,
			endpoint:   strings.TrimSpace(pc.Endpoint),
			allowedIPs: allowed,
			keepalive:  pc.Keepalive,
		}
	}
	if router != nil {
		router.SetPeerIPs(meshIPs)
	}

	var uapi strings.Builder
	if fullResync {
		uapi.WriteString("replace_peers=true\n")
	}

	// 1. Remove peers that disappeared
	for pubHex := range t.activePeers {
		if _, keep := desiredMap[pubHex]; !keep {
			uapi.WriteString(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
			delete(t.activePeers, pubHex)
		}
	}

	// 2. Add new peers or differentially update changed fields ONLY
	for pubHex, next := range desiredMap {
		prev, exists := t.activePeers[pubHex]
		if exists && peersEqual(prev, next) {
			continue
		}
		uapi.WriteString(fmt.Sprintf("public_key=%s\n", pubHex))
		if !exists || prev.pskHex != next.pskHex {
			if next.pskHex != "" {
				uapi.WriteString(fmt.Sprintf("preshared_key=%s\n", next.pskHex))
			} else if exists && prev.pskHex != "" {
				uapi.WriteString(fmt.Sprintf("preshared_key=%064d\n", 0))
			}
		}
		// CRITICAL: Only emit endpoint=... when next.endpoint is non-empty AND actually changed from
		// the previously configured value! Otherwise we preserve WireGuard's live NAT-roamed endpoint!
		if next.endpoint != "" && (!exists || prev.endpoint != next.endpoint) {
			if _, err := t.bind.ParseEndpoint(next.endpoint); err == nil {
				uapi.WriteString(fmt.Sprintf("endpoint=%s\n", next.endpoint))
			}
		}
		if !exists || !slicesEqual(prev.allowedIPs, next.allowedIPs) {
			uapi.WriteString("replace_allowed_ips=true\n")
			for _, cidr := range next.allowedIPs {
				uapi.WriteString(fmt.Sprintf("allowed_ip=%s\n", cidr))
			}
		}
		if (!exists && next.keepalive > 0) || (exists && prev.keepalive != next.keepalive) {
			uapi.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", next.keepalive))
		}
		t.activePeers[pubHex] = next
	}

	cmd := uapi.String()
	if cmd != "" {
		if err := wgDev.IpcSet(cmd); err != nil {
			t.activePeers = make(map[string]appliedPeer)
			t.needsFullResync = true
		} else {
			t.needsFullResync = false
		}
	} else {
		t.needsFullResync = false
	}
}

func peersEqual(a, b appliedPeer) bool {
	return a.pskHex == b.pskHex &&
		a.endpoint == b.endpoint &&
		a.keepalive == b.keepalive &&
		slicesEqual(a.allowedIPs, b.allowedIPs)
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Ping sends an encrypted ICMP Echo Request over the active WireGuard tunnel to dstIP.
func (t *Tunnel) Ping(ctx context.Context, dstIP string, timeout time.Duration) (time.Duration, error) {
	r := t.Router()
	if r == nil {
		return 0, fmt.Errorf("tunnel not running")
	}
	return r.Ping(ctx, dstIP, timeout)
}

// PeerStats queries wireguard-go's live UAPI telemetry (tx_bytes, rx_bytes, roamed endpoint, handshake timestamp).
func (t *Tunnel) PeerStats() ([]PeerRuntimeStats, error) {
	t.mu.RLock()
	wgDev := t.wgDev
	t.mu.RUnlock()
	if wgDev == nil {
		return nil, nil
	}
	raw, err := wgDev.IpcGet()
	if err != nil {
		return nil, err
	}
	var out []PeerRuntimeStats
	var cur *PeerRuntimeStats
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			if cur != nil {
				out = append(out, *cur)
			}
			b64, err := HexToKey(v)
			if err != nil {
				b64 = v
			}
			cur = &PeerRuntimeStats{PublicKey: b64}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "last_handshake_time_sec":
			if cur != nil {
				cur.LastHandshakeTimeSec, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out, nil
}
