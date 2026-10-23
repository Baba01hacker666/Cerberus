package tunnel

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"sync"

	"crypto/sha256"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/unix"
)

const (
	IFF_TUN    = 0x0001
	IFF_NO_PI  = 0x1000
	MTU        = 1420
	NonceSize  = 24
	IndexSize  = 4
)

// GenerateKeyPair returns base64 X25519 private/public keys.
func GenerateKeyPair() (string, string, error) {
	priv := make([]byte, 32)
	if err := readRand(priv); err != nil {
		return "", "", err
	}
	// clamp
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

func readRand(b []byte) error {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.ReadFull(f, b)
	return err
}

type PeerConfig struct {
	Index     uint32
	PublicKey string
	Endpoint  string
	MeshIP    string
}

type TunnelConfig struct {
	Name       string
	PrivateKey string
	PublicKey  string
	MeshIP     string // with prefix
	ListenPort int
}

type peerState struct {
	Index     uint32
	PublicKey string
	Endpoint  string
	MeshIP    string
	SharedKey [32]byte
	hasKey    bool
}

type Tunnel struct {
	cfg    TunnelConfig
	mu     sync.RWMutex
	peers  map[string]*peerState // by mesh ip
	byIdx  map[uint32]*peerState
	nextIdx uint32

	conn *net.UDPConn
	tun  *os.File
	stop chan struct{}
	running bool

	counter uint64
}

func New(cfg TunnelConfig) *Tunnel {
	if cfg.Name == "" {
		cfg.Name = "cerberus0"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 51820
	}
	return &Tunnel{
		cfg:    cfg,
		peers:  map[string]*peerState{},
		byIdx:  map[uint32]*peerState{},
		stop:   make(chan struct{}),
	}
}

func (t *Tunnel) Available() bool {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return false
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return false
	}
	return true
}

func (t *Tunnel) Start(ctx interface{ Done() <-chan struct{} }) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return nil
	}
	if err := t.setupTUN(); err != nil {
		return fmt.Errorf("tun setup: %w", err)
	}
	addr := fmt.Sprintf("0.0.0.0:%d", t.cfg.ListenPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	t.conn = conn
	t.running = true
	go t.runTUN()
	go t.runUDP()
	go func() {
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.stop:
		}
	}()
	return nil
}

func (t *Tunnel) Stop() {
	close(t.stop)
	if t.conn != nil {
		_ = t.conn.Close()
	}
	if t.tun != nil {
		_ = t.tun.Close()
	}
}

func (t *Tunnel) UpdatePeers(peers []PeerConfig) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// rebuild
	t.peers = map[string]*peerState{}
	t.byIdx = map[uint32]*peerState{}
	for _, pc := range peers {
		if pc.PublicKey == "" || pc.MeshIP == "" {
			continue
		}
		idx := pc.Index
		if idx == 0 {
			t.nextIdx++
			idx = t.nextIdx
		}
		ps := &peerState{
			Index:     idx,
			PublicKey: pc.PublicKey,
			Endpoint:  pc.Endpoint,
			MeshIP:    pc.MeshIP,
		}
		// derive shared key
		key, err := deriveShared(t.cfg.PrivateKey, pc.PublicKey)
		if err == nil {
			ps.SharedKey = key
			ps.hasKey = true
		}
		t.peers[pc.MeshIP] = ps
		t.byIdx[idx] = ps
	}
}

func (t *Tunnel) setupTUN() error {
	// create interface via ip command
	_ = exec.Command("ip", "tuntap", "add", "dev", t.cfg.Name, "mode", "tun").Run()
	if t.cfg.MeshIP != "" {
		_ = exec.Command("ip", "addr", "add", t.cfg.MeshIP, "dev", t.cfg.Name).Run()
	}
	_ = exec.Command("ip", "link", "set", "dev", t.cfg.Name, "up").Run()
	_ = exec.Command("ip", "link", "set", "dev", t.cfg.Name, "mtu", fmt.Sprintf("%d", MTU)).Run()

	f, err := openTUN(t.cfg.Name)
	if err != nil {
		return err
	}
	t.tun = f
	return nil
}

func openTUN(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(IFF_TUN | IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (t *Tunnel) runTUN() {
	buf := make([]byte, 65535)
	for {
		n, err := t.tun.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		dst := dstIP(pkt)
		if dst == "" {
			continue
		}
		t.mu.RLock()
		ps := t.peers[dst]
		t.mu.RUnlock()
		if ps == nil || !ps.hasKey || ps.Endpoint == "" {
			continue
		}
		t.sendPacket(ps, pkt)
	}
}

func (t *Tunnel) sendPacket(ps *peerState, pkt []byte) {
	nonce := make([]byte, NonceSize)
	_, _ = rand.Read(nonce)
	aead, err := chacha20poly1305.NewX(ps.SharedKey[:])
	if err != nil {
		return
	}
	ct := aead.Seal(nil, nonce, pkt, nil)
	buf := make([]byte, IndexSize+NonceSize+len(ct))
	binary.BigEndian.PutUint32(buf[:IndexSize], ps.Index)
	copy(buf[IndexSize:], nonce)
	copy(buf[IndexSize+NonceSize:], ct)
	addr, err := net.ResolveUDPAddr("udp", ps.Endpoint)
	if err != nil {
		return
	}
	_, _ = t.conn.WriteToUDP(buf, addr)
}

func (t *Tunnel) runUDP() {
	buf := make([]byte, 65535)
	for {
		n, _, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < IndexSize+NonceSize {
			continue
		}
		idx := binary.BigEndian.Uint32(buf[:IndexSize])
		t.mu.RLock()
		ps := t.byIdx[idx]
		t.mu.RUnlock()
		if ps == nil || !ps.hasKey {
			continue
		}
		nonce := buf[IndexSize : IndexSize+NonceSize]
		ct := buf[IndexSize+NonceSize : n]
		aead, err := chacha20poly1305.NewX(ps.SharedKey[:])
		if err != nil {
			continue
		}
		pt, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			continue
		}
		_, _ = t.tun.Write(pt)
	}
}

func dstIP(pkt []byte) string {
	if len(pkt) == 0 {
		return ""
	}
	ver := pkt[0] >> 4
	if ver == 4 && len(pkt) >= 20 {
		return net.IP(pkt[16:20]).String()
	}
	if ver == 6 && len(pkt) >= 40 {
		return net.IP(pkt[24:40]).String()
	}
	return ""
}

func deriveShared(privB64, pubB64 string) ([32]byte, error) {
	var key [32]byte
	priv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return key, err
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return key, err
	}
	var privArr, pubArr [32]byte
	copy(privArr[:], priv)
	copy(pubArr[:], pub)
	shared, err := curve25519.X25519(privArr[:], pubArr[:])
	if err != nil {
		return key, err
	}
	hk := hkdf.New(sha256.New, shared, nil, []byte("cerberus-v1"))
	if _, err := io.ReadFull(hk, key[:]); err != nil {
		return key, err
	}
	return key, nil
}

func MeshIPWithPrefix(ip string, cidr string) string {
	// reuse logic from mesh package? avoid import cycle; simple
	if ip == "" {
		return ""
	}
	// if already has slash
	if len(ip) > 0 {
		for i := 0; i < len(ip); i++ {
			if ip[i] == '/' {
				return ip
			}
		}
	}
	// default /32
	return ip + "/32"
}

// Available reports whether the tunnel can run on this host.
func Available() bool {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return false
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return false
	}
	return true
}
