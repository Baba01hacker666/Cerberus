package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

const (
	probeMagicReq  = "CBPG" // 4 bytes + 8 byte nonce = 12 bytes
	probeMagicResp = "CBPK" // 4 bytes + 8 byte nonce = 12 bytes
	tcpEndpointPfx = "tcp://"
	upgradeHeader  = "cerberus-wg/1"
	maxFrameSize   = 65535
)

// hybridEndpoint implements conn.Endpoint for both native UDP (AddrPort) and
// HTTP-Upgraded persistent TCP streams ("tcp://<streamID>").
type hybridEndpoint struct {
	udpAddr   netip.AddrPort
	tcpID     string
	remoteNet netip.AddrPort
}

func (e *hybridEndpoint) ClearSrc()           {}
func (e *hybridEndpoint) SrcToString() string { return "" }
func (e *hybridEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (e *hybridEndpoint) DstToString() string {
	if e.tcpID != "" {
		return tcpEndpointPfx + e.tcpID
	}
	return e.udpAddr.String()
}

func (e *hybridEndpoint) DstToBytes() []byte {
	ap := e.udpAddr
	if e.tcpID != "" {
		ap = e.remoteNet
	}
	b, err := ap.MarshalBinary()
	if err != nil {
		return []byte{127, 0, 0, 1, 0, 1}
	}
	return b
}

// DstIP returns a deterministic per-endpoint 128-bit address for wireguard-go's handshake
// ratelimiter so 100+ containers/clients behind the same corporate/Docker NAT IP never starve
// each other's 5-packet burst bucket, while still strictly rate-limiting any single source socket.
func (e *hybridEndpoint) DstIP() netip.Addr {
	sum := sha256.Sum256([]byte("cerberus-ep:" + e.DstToString()))
	var addr16 [16]byte
	copy(addr16[:], sum[:16])
	return netip.AddrFrom16(addr16)
}

type tcpStreamConn struct {
	id        string
	conn      net.Conn
	remoteNet netip.AddrPort
	writeMu   sync.Mutex
	closed    atomic.Bool
}

func (s *tcpStreamConn) writePacket(pkt []byte) error {
	if len(pkt) == 0 || len(pkt) > maxFrameSize {
		return nil
	}
	if s.closed.Load() {
		return net.ErrClosed
	}
	frame := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(pkt)))
	copy(frame[2:], pkt)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := s.conn.Write(frame)
	return err
}

func (s *tcpStreamConn) close() {
	if s.closed.CompareAndSwap(false, true) {
		_ = s.conn.Close()
	}
}

type inboundTCPFrame struct {
	streamID  string
	remoteNet netip.AddrPort
	data      []byte
}

// HybridBind implements golang.zx2c4.com/wireguard/conn.Bind with BOTH:
//  1. Zero-overhead native UDP socket transport (used whenever UDP reaches the server port)
//  2. Single-port HTTP Upgrade TCP stream transport (automatic fallback when UDP is firewalled!)
type HybridBind struct {
	openMu      sync.Mutex
	isOpen      bool
	pinnedPort  uint16
	udpConn     *net.UDPConn
	openDone    chan struct{}
	actualPort  atomic.Uint32
	udpDisabled atomic.Bool // for testing or forced TCP mode

	tcpInCh chan inboundTCPFrame

	streamsMu sync.RWMutex
	streams   map[string]*tcpStreamConn

	probesMu sync.Mutex
	probes   map[[8]byte]chan struct{}

	caFile string
}

func NewHybridBind() *HybridBind {
	return &HybridBind{
		tcpInCh: make(chan inboundTCPFrame, 4096),
		streams: make(map[string]*tcpStreamConn),
		probes:  make(map[[8]byte]chan struct{}),
	}
}

// SetCAFile configures the CA bundle used to verify HTTPS control-plane
// connections. An empty path uses the system roots.
func (b *HybridBind) SetCAFile(path string) {
	b.caFile = path
}

func (b *HybridBind) tlsClientConfig(serverName string) *tls.Config {
	cfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	if b.caFile != "" {
		if caBytes, err := os.ReadFile(b.caFile); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caBytes) {
				cfg.RootCAs = pool
			} else if systemPool, serr := x509.SystemCertPool(); serr == nil {
				cfg.RootCAs = systemPool
			}
		}
	}
	return cfg
}

// DisableUDP forces all WireGuard traffic away from raw UDP (useful for testing single-TCP-port firewalls or --tcp-only).
func (b *HybridBind) DisableUDP(disabled bool) {
	b.udpDisabled.Store(disabled)
}

func (b *HybridBind) ActualUDPPort() int {
	return int(b.actualPort.Load())
}

func (b *HybridBind) BatchSize() int {
	return 16
}

func (b *HybridBind) SetMark(_ uint32) error {
	return nil
}

func (b *HybridBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if strings.HasPrefix(s, tcpEndpointPfx) {
		id := strings.TrimPrefix(s, tcpEndpointPfx)
		if id == "" {
			return nil, fmt.Errorf("empty tcp endpoint id")
		}
		return &hybridEndpoint{
			tcpID:     id,
			remoteNet: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 7443),
		}, nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err == nil {
		return &hybridEndpoint{udpAddr: ap}, nil
	}
	udpAddr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	return &hybridEndpoint{udpAddr: udpAddr.AddrPort()}, nil
}

func (b *HybridBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.openMu.Lock()
	defer b.openMu.Unlock()

	if b.isOpen {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	targetPort := port
	if targetPort == 0 && b.pinnedPort != 0 {
		targetPort = b.pinnedPort
	}
	udpAddr := &net.UDPAddr{Port: int(targetPort)}
	uconn, err := net.ListenUDP("udp", udpAddr)
	if err != nil && port == 0 && targetPort != 0 {
		// In rare case another process grabbed the previous ephemeral port during brief rebind, pick any free port
		uconn, err = net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	}
	if err != nil {
		return nil, 0, err
	}
	_ = uconn.SetReadBuffer(4 * 1024 * 1024)
	_ = uconn.SetWriteBuffer(4 * 1024 * 1024)

	boundPort := uint16(uconn.LocalAddr().(*net.UDPAddr).Port)
	if port == 0 {
		b.pinnedPort = boundPort
	}
	done := make(chan struct{})

	b.udpConn = uconn
	b.openDone = done
	b.isOpen = true
	b.actualPort.Store(uint32(boundPort))

	recvUDP := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, addrPort, err := uconn.ReadFromUDPAddrPort(packets[0])
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return 0, net.ErrClosed
				}
				select {
				case <-done:
					return 0, net.ErrClosed
				default:
				}
				return 0, err
			}
			if b.udpDisabled.Load() {
				continue
			}
			// Intercept lightweight 12-byte UDP reachability probe packets before WireGuard sees them
			if n == 12 {
				hdr := string(packets[0][:4])
				if hdr == probeMagicReq {
					var resp [12]byte
					copy(resp[0:4], probeMagicResp)
					copy(resp[4:12], packets[0][4:12])
					_, _ = uconn.WriteToUDPAddrPort(resp[:], addrPort)
					continue
				}
				if hdr == probeMagicResp {
					var nonce [8]byte
					copy(nonce[:], packets[0][4:12])
					b.probesMu.Lock()
					ch, ok := b.probes[nonce]
					b.probesMu.Unlock()
					if ok {
						select {
						case ch <- struct{}{}:
						default:
						}
					}
					continue
				}
			}
			// Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1) so endpoints match cleanly!
			if addrPort.Addr().Is4In6() {
				addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
			}
			sizes[0] = n
			eps[0] = &hybridEndpoint{udpAddr: addrPort}
			return 1, nil
		}
	}

	recvTCP := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-done:
			return 0, net.ErrClosed
		case frame := <-b.tcpInCh:
			if len(frame.data) > len(packets[0]) {
				sizes[0] = 0
				return 0, nil
			}
			n := copy(packets[0], frame.data)
			sizes[0] = n
			eps[0] = &hybridEndpoint{
				tcpID:     frame.streamID,
				remoteNet: frame.remoteNet,
			}
			return 1, nil
		}
	}

	return []conn.ReceiveFunc{recvUDP, recvTCP}, boundPort, nil
}

func (b *HybridBind) Close() error {
	b.openMu.Lock()
	if !b.isOpen {
		b.openMu.Unlock()
		return nil
	}
	b.isOpen = false
	done := b.openDone
	uconn := b.udpConn
	b.udpConn = nil
	b.openMu.Unlock()

	close(done)
	if uconn != nil {
		return uconn.Close()
	}
	return nil
}

// Shutdown permanently tears down both UDP and all active TCP stream connections.
func (b *HybridBind) Shutdown() {
	_ = b.Close()
	b.streamsMu.Lock()
	for id, st := range b.streams {
		st.close()
		delete(b.streams, id)
	}
	b.streamsMu.Unlock()
}

func (b *HybridBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	hep, ok := ep.(*hybridEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	if hep.tcpID != "" {
		b.streamsMu.RLock()
		st := b.streams[hep.tcpID]
		b.streamsMu.RUnlock()
		if st == nil {
			// Drop quietly until stream reconnects (same as unreachable UDP packet)
			return nil
		}
		for _, pkt := range bufs {
			if err := st.writePacket(pkt); err != nil {
				st.close()
				return nil
			}
		}
		return nil
	}

	if b.udpDisabled.Load() {
		return nil
	}
	b.openMu.Lock()
	uconn := b.udpConn
	b.openMu.Unlock()
	if uconn == nil {
		return net.ErrClosed
	}
	dst := hep.udpAddr
	if dst.Addr().Is4In6() {
		dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	}
	for _, pkt := range bufs {
		if _, err := uconn.WriteToUDPAddrPort(pkt, dst); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return net.ErrClosed
			}
		}
	}
	return nil
}

// AttachStream registers a hijacked / upgraded persistent TCP net.Conn for WireGuard packet framing.
// Blocks until the stream closes or ctx cancels.
func (b *HybridBind) AttachStream(ctx context.Context, streamID string, rawConn net.Conn, br *bufio.Reader) {
	var rnet netip.AddrPort
	if ap, err := netip.ParseAddrPort(rawConn.RemoteAddr().String()); err == nil {
		rnet = ap
	} else {
		rnet = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 7443)
	}
	st := &tcpStreamConn{
		id:        streamID,
		conn:      rawConn,
		remoteNet: rnet,
	}

	b.streamsMu.Lock()
	if prev, ok := b.streams[streamID]; ok {
		prev.close()
	}
	b.streams[streamID] = st
	b.streamsMu.Unlock()

	defer func() {
		st.close()
		b.streamsMu.Lock()
		if b.streams[streamID] == st {
			delete(b.streams, streamID)
		}
		b.streamsMu.Unlock()
	}()

	stopDone := make(chan struct{})
	defer close(stopDone)
	go func() {
		select {
		case <-ctx.Done():
			st.close()
		case <-stopDone:
		}
	}()

	var r io.Reader = rawConn
	if br != nil {
		r = br
	}
	var hdr [2]byte
	for {
		_ = rawConn.SetReadDeadline(time.Now().Add(90 * time.Second))
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return
		}
		frameLen := int(binary.BigEndian.Uint16(hdr[:]))
		if frameLen == 0 {
			// 0-length keepalive frame
			continue
		}
		payload := make([]byte, frameLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return
		}
		select {
		case b.tcpInCh <- inboundTCPFrame{
			streamID:  streamID,
			remoteNet: rnet,
			data:      payload,
		}:
		default:
			// Queue full: drop oldest-style tail drop without stalling TCP read loop
		}
	}
}

// DialStream MaintainLoop connects outbound to the server's /wg-tunnel endpoint using HTTP/1.1 Upgrade
// over the exact same port as the REST control API, reconnecting automatically on transient drops.
func (b *HybridBind) MaintainClientStream(
	ctx context.Context,
	baseURL string,
	streamID string,
	peerID string,
	peerSecret string,
	authToken string,
	readyOnce func(),
) {
	var once sync.Once
	backoff := 150 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return
		}
		err := b.dialClientStreamOnce(ctx, baseURL, streamID, peerID, peerSecret, authToken, func() {
			once.Do(func() {
				if readyOnce != nil {
					readyOnce()
				}
			})
			backoff = 150 * time.Millisecond
		})
		if ctx.Err() != nil {
			return
		}
		_ = err
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
			if backoff < 3*time.Second {
				backoff *= 2
			}
		}
	}
}

func (b *HybridBind) dialClientStreamOnce(
	ctx context.Context,
	baseURL string,
	streamID string,
	peerID string,
	peerSecret string,
	authToken string,
	onConnected func(),
) error {
	u, err := url.Parse(strings.TrimRight(baseURL, "/") + "/wg-tunnel")
	if err != nil {
		return err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}
	var rawConn net.Conn
	if u.Scheme == "https" {
		// WireGuard still authenticates & encrypts every inner packet end-to-end;
		// the control-plane credentials on this stream MUST be protected by TLS verification.
		rawConn, err = tls.DialWithDialer(dialer, "tcp", host, b.tlsClientConfig(u.Hostname()))
	} else {
		rawConn, err = dialer.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, u.RequestURI(), nil)
	if err != nil {
		_ = rawConn.Close()
		return err
	}
	req.Host = u.Host
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", upgradeHeader)
	if peerID != "" {
		req.Header.Set("X-Cerberus-Peer-ID", peerID)
	}
	if peerSecret != "" {
		req.Header.Set("X-Cerberus-Peer-Secret", peerSecret)
	}
	if authToken != "" && (peerID == "" || peerSecret == "") {
		// Only send the server-wide auth token when no per-peer credentials are in use,
		// so per-peer secrets stay the single source of truth for authenticated streams.
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	if err := req.Write(rawConn); err != nil {
		_ = rawConn.Close()
		return err
	}
	br := bufio.NewReader(rawConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = rawConn.Close()
		return err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = rawConn.Close()
		return fmt.Errorf("upgrade status: %s", resp.Status)
	}

	// Send lightweight 0-length frame every 25s so idle reverse proxies / NATs keep TCP alive
	doneKA := make(chan struct{})
	defer close(doneKA)
	go func() {
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-doneKA:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				b.streamsMu.RLock()
				st := b.streams[streamID]
				b.streamsMu.RUnlock()
				if st != nil && !st.closed.Load() {
					st.writeMu.Lock()
					_ = st.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
					_, _ = st.conn.Write([]byte{0, 0})
					st.writeMu.Unlock()
				}
			}
		}
	}()

	if onConnected != nil {
		onConnected()
	}
	b.AttachStream(ctx, streamID, rawConn, br)
	return nil
}

// ProbeUDP sends a 12-byte CBPG echo probe out of our active UDP socket to target ("host:port")
// and measures RTT. Returns an error immediately if UDP is disabled or no echo arrives before timeout.
func (b *HybridBind) ProbeUDP(ctx context.Context, target string, timeout time.Duration) (time.Duration, error) {
	if b.udpDisabled.Load() {
		return 0, fmt.Errorf("udp disabled")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return 0, err
	}
	dst := udpAddr.AddrPort()
	if dst.Addr().Is4In6() {
		dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	}

	b.openMu.Lock()
	uconn := b.udpConn
	b.openMu.Unlock()
	if uconn == nil {
		return 0, net.ErrClosed
	}

	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	waitCh := make(chan struct{}, 1)
	b.probesMu.Lock()
	b.probes[nonce] = waitCh
	b.probesMu.Unlock()
	defer func() {
		b.probesMu.Lock()
		delete(b.probes, nonce)
		b.probesMu.Unlock()
	}()

	var pkt [12]byte
	copy(pkt[0:4], probeMagicReq)
	copy(pkt[4:12], nonce[:])

	start := time.Now()
	if _, err := uconn.WriteToUDPAddrPort(pkt[:], dst); err != nil {
		return 0, err
	}
	// Retry once halfway through timeout so a single dropped UDP packet doesn't falsely trigger fallback
	half := timeout / 2
	if half < 40*time.Millisecond {
		half = timeout
	}
	timerHalf := time.NewTimer(half)
	defer timerHalf.Stop()
	timerFull := time.NewTimer(timeout)
	defer timerFull.Stop()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-waitCh:
		return time.Since(start), nil
	case <-timerHalf.C:
		_, _ = uconn.WriteToUDPAddrPort(pkt[:], dst)
	}

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-waitCh:
		return time.Since(start), nil
	case <-timerFull.C:
		return 0, fmt.Errorf("udp probe to %s timed out after %s", target, timeout)
	}
}
