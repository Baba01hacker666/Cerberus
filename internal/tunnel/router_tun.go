package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Baba01hacker666/cerberus/internal/isolation"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	MTU             = 1420
	routerQueueSize = 4096
	routerBatchMax  = 64
)

type pingKey struct {
	id  uint16
	seq uint16
}

// RouterTUN wraps an optional OS tun.Device (e.g. Linux cerberus0 / macOS utun) with:
//   - Lock-free zero-trust packet filtering via isolation.PolicyEngine
//   - High-speed userspace hub-and-spoke mesh packet forwarding (IsRouter = true) so
//     NAT'd clients communicate peer-to-peer immediately with zero kernel sysctl setup
//   - Preserved pre-offset headroom on Linux GSO/IFF_VNET_HDR writes to OS TUN
//   - Userspace packet pub/sub + ICMP Echo responder & Ping RTT measurement
type RouterTUN struct {
	name     string
	mtu      int
	inner    tun.Device // nil when running in userspace-only mode
	localIP  netip.Addr
	isRouter bool
	policy   *isolation.PolicyEngine

	peerIPs atomic.Pointer[map[netip.Addr]bool]

	txCh   chan []byte
	events chan tun.Event
	closed chan struct{}

	closeOnce sync.Once

	subMu       sync.RWMutex
	subscribers map[uint64]chan []byte
	nextSubID   uint64

	pingMu  sync.Mutex
	waiters map[pingKey]chan time.Time

	RelayedPackets atomic.Uint64
	DroppedPolicy  atomic.Uint64
}

type RouterTUNOptions struct {
	Name     string
	MTU      int
	Inner    tun.Device
	LocalIP  netip.Addr
	IsRouter bool
	Policy   *isolation.PolicyEngine
}

func NewRouterTUN(opts RouterTUNOptions) *RouterTUN {
	if opts.Name == "" {
		opts.Name = "cerberus0"
	}
	if opts.MTU <= 0 {
		opts.MTU = MTU
	}
	r := &RouterTUN{
		name:        opts.Name,
		mtu:         opts.MTU,
		inner:       opts.Inner,
		localIP:     opts.LocalIP,
		isRouter:    opts.IsRouter,
		policy:      opts.Policy,
		txCh:        make(chan []byte, routerQueueSize),
		events:      make(chan tun.Event, 4),
		closed:      make(chan struct{}),
		subscribers: make(map[uint64]chan []byte),
		waiters:     make(map[pingKey]chan time.Time),
	}
	empty := make(map[netip.Addr]bool)
	r.peerIPs.Store(&empty)

	if r.inner != nil {
		go r.pumpInnerReads()
		go r.forwardInnerEvents()
	}
	return r
}

func (r *RouterTUN) HasOSDevice() bool {
	return r.inner != nil
}

func (r *RouterTUN) SetPolicy(pe *isolation.PolicyEngine) {
	r.policy = pe
}

func (r *RouterTUN) SetPeerIPs(ips []string) {
	m := make(map[netip.Addr]bool, len(ips))
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil {
			m[a.Unmap()] = true
		}
	}
	r.peerIPs.Store(&m)
}

func (r *RouterTUN) forwardInnerEvents() {
	evCh := r.inner.Events()
	for {
		select {
		case <-r.closed:
			return
		case ev, ok := <-evCh:
			if !ok {
				return
			}
			select {
			case r.events <- ev:
			default:
			}
		}
	}
}

func (r *RouterTUN) pumpInnerReads() {
	bs := r.inner.BatchSize()
	if bs < 1 {
		bs = 1
	}
	const headroom = 32 // >= virtioNetHdrLen (10) and WireGuard transport header (16)
	bufs := make([][]byte, bs)
	sizes := make([]int, bs)
	for i := range bufs {
		bufs[i] = make([]byte, headroom+65535)
	}
	for {
		n, err := r.inner.Read(bufs, sizes, headroom)
		if err != nil {
			select {
			case <-r.closed:
				return
			default:
			}
			return
		}
		for i := 0; i < n; i++ {
			sz := sizes[i]
			if sz <= 0 {
				continue
			}
			raw := bufs[i][headroom : headroom+sz]
			if r.policy != nil && !r.policy.AllowPacket(raw) {
				r.DroppedPolicy.Add(1)
				continue
			}
			pkt := make([]byte, sz)
			copy(pkt, raw)
			select {
			case r.txCh <- pkt:
			case <-r.closed:
				return
			default:
				// Outbound queue full under extreme burst: drop tail without stalling reader
			}
		}
	}
}

func (r *RouterTUN) File() *os.File {
	if r.inner != nil {
		return r.inner.File()
	}
	return nil
}

func (r *RouterTUN) MTU() (int, error) {
	if r.inner != nil {
		return r.inner.MTU()
	}
	return r.mtu, nil
}

func (r *RouterTUN) Name() (string, error) {
	if r.inner != nil {
		return r.inner.Name()
	}
	return r.name, nil
}

func (r *RouterTUN) Events() <-chan tun.Event {
	return r.events
}

func (r *RouterTUN) BatchSize() int {
	if r.inner != nil {
		bs := r.inner.BatchSize()
		if bs > 0 {
			return bs
		}
	}
	return routerBatchMax
}

// Read supplies outgoing raw IP packets (from OS TUN, userspace mesh relay, or InjectPacket)
// to wireguard-go, draining queued packets in batches under concurrent load.
func (r *RouterTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-r.closed:
		return 0, os.ErrClosed
	case first := <-r.txCh:
		sizes[0] = copy(bufs[0][offset:], first)
		count := 1
		maxBatch := len(bufs)
		for count < maxBatch {
			select {
			case next := <-r.txCh:
				sizes[count] = copy(bufs[count][offset:], next)
				count++
			default:
				return count, nil
			}
		}
		return count, nil
	}
}

// Write receives decrypted raw IP packets from wireguard-go.
// IMPORTANT: preserves the caller's original slice prefix before offset when forwarding local
// packets to inner.Write so Linux IFF_VNET_HDR (offset - 10) never panics!
func (r *RouterTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-r.closed:
		return 0, os.ErrClosed
	default:
	}

	var localBufs [][]byte
	if r.inner != nil {
		localBufs = make([][]byte, 0, len(bufs))
	}
	peers := *r.peerIPs.Load()

	for _, fullBuf := range bufs {
		if offset < 0 || offset >= len(fullBuf) {
			continue
		}
		pkt := fullBuf[offset:]
		if len(pkt) < 20 {
			continue
		}

		// 1. Zero-trust userspace firewall check (covers host-bound AND peer-to-peer relayed traffic!)
		if r.policy != nil && !r.policy.AllowPacket(pkt) {
			r.DroppedPolicy.Add(1)
			continue
		}

		_, dst, ok := ParsePacketAddrs(pkt)
		if !ok {
			continue
		}
		dst = dst.Unmap()

		// 2. If server/router receives a packet addressed to another registered mesh peer, forward in userspace!
		if r.isRouter && r.localIP.IsValid() && dst != r.localIP && peers[dst] {
			if fwd, valid := ForwardCopy(pkt); valid {
				r.RelayedPackets.Add(1)
				select {
				case r.txCh <- fwd:
				default:
				}
			}
			continue
		}

		// 3. Notify in-process Ping waiters if ICMP Echo Reply
		if _, id, seq, _, isReply := ParseICMPEchoReply(pkt); isReply {
			r.pingMu.Lock()
			ch, waiting := r.waiters[pingKey{id: id, seq: seq}]
			r.pingMu.Unlock()
			if waiting {
				select {
				case ch <- time.Now():
				default:
				}
			}
		}

		// 4. Deliver to in-process subscribers (if any registered)
		r.deliverSubscribers(pkt)

		// 5. Deliver to OS TUN kernel interface OR answer ICMP Echo Request in userspace mode
		if r.inner != nil {
			localBufs = append(localBufs, fullBuf)
		} else if !r.localIP.IsValid() || dst == r.localIP {
			if rep, isEchoReq := BuildICMPEchoReply(pkt); isEchoReq {
				select {
				case r.txCh <- rep:
				default:
				}
			}
		}
	}

	if r.inner != nil && len(localBufs) > 0 {
		if _, err := r.inner.Write(localBufs, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

func (r *RouterTUN) deliverSubscribers(pkt []byte) {
	r.subMu.RLock()
	if len(r.subscribers) == 0 {
		r.subMu.RUnlock()
		return
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	for _, ch := range r.subscribers {
		select {
		case ch <- cp:
		default:
		}
	}
	r.subMu.RUnlock()
}

// Subscribe registers a channel receiving copies of all decrypted local packets arriving on this node.
func (r *RouterTUN) Subscribe(bufSize int) (ch <-chan []byte, unsubscribe func()) {
	if bufSize <= 0 {
		bufSize = 256
	}
	c := make(chan []byte, bufSize)
	r.subMu.Lock()
	r.nextSubID++
	id := r.nextSubID
	r.subscribers[id] = c
	r.subMu.Unlock()
	return c, func() {
		r.subMu.Lock()
		delete(r.subscribers, id)
		r.subMu.Unlock()
	}
}

// InjectPacket enqueues a raw IP packet directly into the WireGuard outbound encryption pipeline.
func (r *RouterTUN) InjectPacket(pkt []byte) error {
	if r.policy != nil && !r.policy.AllowPacket(pkt) {
		r.DroppedPolicy.Add(1)
		return fmt.Errorf("packet blocked by local isolation policy")
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case <-r.closed:
		return os.ErrClosed
	case r.txCh <- cp:
		return nil
	}
}

// Ping sends an encrypted ICMPv4 Echo Request over the WireGuard mesh tunnel to dstIP and measures real RTT.
func (r *RouterTUN) Ping(ctx context.Context, dstIP string, timeout time.Duration) (time.Duration, error) {
	dst, err := netip.ParseAddr(dstIP)
	if err != nil {
		return 0, fmt.Errorf("invalid destination ip %q: %w", dstIP, err)
	}
	if !r.localIP.IsValid() {
		return 0, fmt.Errorf("local mesh ip not configured")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	pk := pingKey{
		id:  binary.BigEndian.Uint16(rnd[0:2]),
		seq: binary.BigEndian.Uint16(rnd[2:4]),
	}
	replyCh := make(chan time.Time, 1)
	r.pingMu.Lock()
	r.waiters[pk] = replyCh
	r.pingMu.Unlock()
	defer func() {
		r.pingMu.Lock()
		delete(r.waiters, pk)
		r.pingMu.Unlock()
	}()

	reqPkt := BuildICMPEchoRequest(r.localIP, dst.Unmap(), pk.id, pk.seq, []byte("cerberus-mesh-ping"))
	start := time.Now()
	if err := r.InjectPacket(reqPkt); err != nil {
		return 0, err
	}

	retryInterval := 180 * time.Millisecond
	if timeout < retryInterval {
		retryInterval = timeout / 2
		if retryInterval < 25*time.Millisecond {
			retryInterval = 25 * time.Millisecond
		}
	}
	retryTicker := time.NewTicker(retryInterval)
	defer retryTicker.Stop()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case got := <-replyCh:
			return got.Sub(start), nil
		case <-deadline.C:
			return 0, fmt.Errorf("ping %s timed out after %s", dstIP, timeout)
		case <-retryTicker.C:
			_ = r.InjectPacket(reqPkt)
		}
	}
}

func (r *RouterTUN) Close() error {
	var closeErr error
	r.closeOnce.Do(func() {
		close(r.closed)
		if r.inner != nil {
			closeErr = r.inner.Close()
		}
	})
	return closeErr
}
