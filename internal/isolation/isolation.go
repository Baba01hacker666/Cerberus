package isolation

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Runner abstracts command execution so iptables policy generation can be verified deterministically in tests.
type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) ([]byte, error) {
	if name == "iptables" {
		name = iptablesBin()
	}
	return exec.Command(name, args...).CombinedOutput()
}

func iptablesBin() string {
	if p, err := exec.LookPath("iptables"); err == nil {
		return p
	}
	for _, candidate := range []string{"/usr/sbin/iptables", "/sbin/iptables"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return candidate
		}
	}
	return "iptables"
}

func iptablesRestoreBin() (string, bool) {
	if p, err := exec.LookPath("iptables-restore"); err == nil {
		return p, true
	}
	for _, candidate := range []string{"/usr/sbin/iptables-restore", "/sbin/iptables-restore"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return candidate, true
		}
	}
	return "", false
}

type pairKey struct {
	src string
	dst string
}

type compiledPolicy struct {
	enabled      bool
	defaultDeny  bool
	blockedPeers map[string]bool // single peer IP quarantined completely
	blockedPairs map[pairKey]bool
	allowedPairs map[pairKey]bool
}

type flowKey struct {
	proto   uint8
	srcIP   [16]byte
	dstIP   [16]byte
	srcPort uint16
	dstPort uint16
}

// PolicyEngine enforces zero-trust / block-list isolation rules in userspace at wire speed
// (using a lock-free atomic snapshot for rule lookup + sharded stateful flow tracking so return
// packets for allowed connections flow back seamlessly even under directional rules).
type PolicyEngine struct {
	policy atomic.Pointer[compiledPolicy]

	flowMu sync.RWMutex
	flows  map[flowKey]int64 // expiry unix nano
}

const (
	flowTTL = 120 * time.Second
	maxFlow = 16384
)

func NewPolicyEngine() *PolicyEngine {
	pe := &PolicyEngine{
		flows: make(map[flowKey]int64, 256),
	}
	pe.policy.Store(&compiledPolicy{enabled: false})
	return pe
}

// ResolvePeerRef converts a peer name, ID, or IP string into an IP if known.
func ResolvePeerRef(ref string, nameToIP map[string]string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if nameToIP != nil {
		if ip, ok := nameToIP[ref]; ok && ip != "" {
			return ip
		}
	}
	return ref
}

// ParseRuleEntry parses rule strings supported in config / CLI:
//   - "src->dst" (directional from src to dst)
//   - "src,dst" or "src<->dst" (bidirectional between src and dst)
//   - "peer" (single peer reference)
func ParseRuleEntry(entry string, nameToIP map[string]string) (pairs [][2]string, single string) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil, ""
	}
	if strings.Contains(entry, "<->") {
		parts := strings.SplitN(entry, "<->", 2)
		a := ResolvePeerRef(parts[0], nameToIP)
		b := ResolvePeerRef(parts[1], nameToIP)
		if a != "" && b != "" {
			return [][2]string{{a, b}, {b, a}}, ""
		}
		return nil, ""
	}
	if strings.Contains(entry, "->") {
		parts := strings.SplitN(entry, "->", 2)
		a := ResolvePeerRef(parts[0], nameToIP)
		b := ResolvePeerRef(parts[1], nameToIP)
		if a != "" && b != "" {
			return [][2]string{{a, b}}, ""
		}
		return nil, ""
	}
	if strings.Contains(entry, ",") {
		parts := strings.SplitN(entry, ",", 2)
		a := ResolvePeerRef(parts[0], nameToIP)
		b := ResolvePeerRef(parts[1], nameToIP)
		if a != "" && b != "" {
			return [][2]string{{a, b}, {b, a}}, ""
		}
		return nil, ""
	}
	return nil, ResolvePeerRef(entry, nameToIP)
}

// Configure atomically compiles and swaps the active isolation policy.
func (pe *PolicyEngine) Configure(
	enabled bool,
	defaultDeny bool,
	allowedEntries []string,
	blockedEntries []string,
	isolatedIPs []string,
	nameToIP map[string]string,
) {
	cp := &compiledPolicy{
		enabled:      enabled,
		defaultDeny:  defaultDeny,
		blockedPeers: make(map[string]bool),
		blockedPairs: make(map[pairKey]bool),
		allowedPairs: make(map[pairKey]bool),
	}
	for _, ip := range isolatedIPs {
		if ip != "" {
			cp.blockedPeers[ip] = true
		}
	}
	for _, entry := range blockedEntries {
		pairs, single := ParseRuleEntry(entry, nameToIP)
		for _, p := range pairs {
			cp.blockedPairs[pairKey{src: p[0], dst: p[1]}] = true
		}
		if single != "" {
			cp.blockedPeers[single] = true
		}
	}
	for _, entry := range allowedEntries {
		pairs, _ := ParseRuleEntry(entry, nameToIP)
		for _, p := range pairs {
			cp.allowedPairs[pairKey{src: p[0], dst: p[1]}] = true
		}
	}
	pe.policy.Store(cp)

	// Clear stale flow cache whenever policy changes so newly blocked flows stop immediately!
	pe.flowMu.Lock()
	pe.flows = make(map[flowKey]int64, 256)
	pe.flowMu.Unlock()
}

// BuildAllowedMatrix constructs a map[src][dst]bool matrix for OS iptables sync from the current policy.
func (pe *PolicyEngine) BuildAllowedMatrix(peers []string) (allowed map[string]map[string]bool, enabled bool, defaultDeny bool) {
	cp := pe.policy.Load()
	allowed = make(map[string]map[string]bool, len(peers))
	if cp == nil {
		return allowed, false, false
	}
	for _, src := range peers {
		allowed[src] = make(map[string]bool, len(peers))
		for _, dst := range peers {
			if src == dst {
				continue
			}
			if pe.AllowsPair(src, dst) {
				allowed[src][dst] = true
			}
		}
	}
	return allowed, cp.enabled, cp.defaultDeny
}

// AllowsPair reports whether new traffic initiated from src to dst is permitted.
func (pe *PolicyEngine) AllowsPair(src, dst string) bool {
	if src == "" || dst == "" || src == dst {
		return true
	}
	cp := pe.policy.Load()
	if cp == nil || !cp.enabled {
		return true
	}
	pk := pairKey{src: src, dst: dst}
	if cp.blockedPairs[pk] {
		return false
	}
	// Explicit allow overrides quarantine/defaultDeny (unless also explicitly pair-blocked above)
	if cp.allowedPairs[pk] {
		return true
	}
	if cp.blockedPeers[src] || cp.blockedPeers[dst] {
		return false
	}
	if cp.defaultDeny {
		return false
	}
	return true
}

// AllowPacket inspects an IPv4/IPv6 packet and enforces both stateless rules and stateful
// return-traffic tracking (TCP SYN/ACK, UDP replies, ICMP Echo Replies).
func (pe *PolicyEngine) AllowPacket(pkt []byte) bool {
	cp := pe.policy.Load()
	if cp == nil || !cp.enabled || len(pkt) < 20 {
		return true
	}

	fk, srcStr, dstStr, isReplyCandidate, ok := extractFlow(pkt)
	if !ok {
		return true
	}
	if srcStr == dstStr {
		return true
	}

	now := time.Now().UnixNano()

	// Check reverse tracked stateful flow first (only if reverse pair isn't explicitly blocked right now:
	// Note that Configure() clears pe.flows whenever a new block rule is added, so any entry present
	// in pe.flows was explicitly permitted when initiated!)
	if isReplyCandidate {
		rev := flowKey{
			proto:   fk.proto,
			srcIP:   fk.dstIP,
			dstIP:   fk.srcIP,
			srcPort: fk.dstPort,
			dstPort: fk.srcPort,
		}
		pe.flowMu.RLock()
		exp, exists := pe.flows[rev]
		pe.flowMu.RUnlock()
		if exists && exp > now {
			return true
		}
	}

	if !pe.AllowsPair(srcStr, dstStr) {
		return false
	}

	// Track outbound forward flow so replies back from dst -> src succeed seamlessly
	pe.flowMu.Lock()
	if len(pe.flows) >= maxFlow {
		for k, exp := range pe.flows {
			if exp <= now {
				delete(pe.flows, k)
			}
		}
		if len(pe.flows) >= maxFlow {
			pe.flows = make(map[flowKey]int64, 512)
		}
	}
	pe.flows[fk] = now + int64(flowTTL)
	pe.flowMu.Unlock()
	return true
}

func extractFlow(pkt []byte) (fk flowKey, srcStr, dstStr string, isReplyCandidate bool, ok bool) {
	ver := pkt[0] >> 4
	var l4 []byte
	switch ver {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < ihl || ihl < 20 {
			return fk, "", "", false, false
		}
		src, _ := netip.AddrFromSlice(pkt[12:16])
		dst, _ := netip.AddrFromSlice(pkt[16:20])
		fk.proto = pkt[9]
		fk.srcIP = src.As16()
		fk.dstIP = dst.As16()
		srcStr = src.String()
		dstStr = dst.String()
		l4 = pkt[ihl:]
	case 6:
		if len(pkt) < 40 {
			return fk, "", "", false, false
		}
		src, _ := netip.AddrFromSlice(pkt[8:24])
		dst, _ := netip.AddrFromSlice(pkt[24:40])
		fk.proto = pkt[6]
		fk.srcIP = src.As16()
		fk.dstIP = dst.As16()
		srcStr = src.String()
		dstStr = dst.String()
		l4 = pkt[40:]
	default:
		return fk, "", "", false, false
	}

	switch fk.proto {
	case 6: // TCP
		if len(l4) >= 14 {
			fk.srcPort = binary.BigEndian.Uint16(l4[0:2])
			fk.dstPort = binary.BigEndian.Uint16(l4[2:4])
			flags := l4[13]
			// Any packet carrying ACK (or RST) can be part of an established/reply TCP exchange; pure SYN without ACK cannot!
			isReplyCandidate = (flags & 0x10) != 0
		}
	case 17: // UDP
		if len(l4) >= 4 {
			fk.srcPort = binary.BigEndian.Uint16(l4[0:2])
			fk.dstPort = binary.BigEndian.Uint16(l4[2:4])
			isReplyCandidate = true
		}
	case 1: // ICMPv4
		if len(l4) >= 8 {
			icmpType := l4[0]
			id := binary.BigEndian.Uint16(l4[4:6])
			fk.srcPort = id
			fk.dstPort = id
			// ICMPv4 Echo Reply (type 0) is a reply to Echo Request (type 8)
			isReplyCandidate = (icmpType == 0)
		}
	case 58: // ICMPv6
		if len(l4) >= 8 {
			icmpType := l4[0]
			id := binary.BigEndian.Uint16(l4[4:6])
			fk.srcPort = id
			fk.dstPort = id
			isReplyCandidate = (icmpType == 129)
		}
	}
	return fk, srcStr, dstStr, isReplyCandidate, true
}

// Manager manages host-level iptables rules (used alongside userspace PolicyEngine when root + iptables are available).
type Manager struct {
	mu     sync.Mutex
	Chain  string
	Runner Runner
}

func New(chain string) *Manager {
	if chain == "" {
		chain = "CERBERUS"
	}
	return &Manager{
		Chain:  chain,
		Runner: execRunner{},
	}
}

func NewWithRunner(chain string, r Runner) *Manager {
	m := New(chain)
	if r != nil {
		m.Runner = r
	}
	return m
}

func (m *Manager) ensureChainLocked() error {
	_, _ = m.Runner.Run("iptables", "-N", m.Chain)
	for _, hook := range []string{"FORWARD", "INPUT", "OUTPUT"} {
		if _, err := m.Runner.Run("iptables", "-C", hook, "-j", m.Chain); err != nil {
			if out, err := m.Runner.Run("iptables", "-I", hook, "-j", m.Chain); err != nil {
				return fmt.Errorf("iptables hook %s: %w: %s", hook, err, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

func (m *Manager) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureChainLocked(); err != nil {
		return err
	}
	out, err := m.Runner.Run("iptables", "-F", m.Chain)
	if err != nil {
		return fmt.Errorf("iptables flush: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *Manager) Block(src, dst string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureChainLocked(); err != nil {
		return err
	}
	// Insert block rules at the top of chain (ahead of established/accept rules) so blocks take immediate effect!
	out, err := m.Runner.Run("iptables", "-I", m.Chain, "1", "-s", src, "-d", dst, "-j", "DROP")
	if err != nil {
		return fmt.Errorf("iptables block: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *Manager) Allow(src, dst string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureChainLocked(); err != nil {
		return err
	}
	// Ensure stateful return traffic is permitted in chain
	if _, err := m.Runner.Run("iptables", "-C", m.Chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		_, _ = m.Runner.Run("iptables", "-I", m.Chain, "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	}
	out, err := m.Runner.Run("iptables", "-A", m.Chain, "-s", src, "-d", dst, "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("iptables allow: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *Manager) DefaultPolicy(deny bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureChainLocked(); err != nil {
		return err
	}
	target := "RETURN"
	if deny {
		target = "DROP"
	}
	out, err := m.Runner.Run("iptables", "-A", m.Chain, "-j", target)
	if err != nil {
		return fmt.Errorf("iptables default: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ApplyPolicy atomically rebuilds the CERBERUS chain with stateful connection tracking so replies
// to allowed flows work properly while disallowed pairs are strictly dropped.
func (m *Manager) ApplyPolicy(peers []string, allowed map[string]map[string]bool, defaultDeny bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureChainLocked(); err != nil {
		return err
	}

	// Fast path on real Linux hosts: apply entire chain in a SINGLE atomic kernel syscall via `iptables-restore --noflush` (~1.5ms even for 5,000 rules!)
	if _, isRealExec := m.Runner.(execRunner); isRealExec {
		if restoreBin, ok := iptablesRestoreBin(); ok {
			var sb strings.Builder
			sb.WriteString("*filter\n")
			sb.WriteString(fmt.Sprintf(":%s - [0:0]\n", m.Chain))
			sb.WriteString(fmt.Sprintf("-F %s\n", m.Chain))
			for i, src := range peers {
				for j, dst := range peers {
					if i == j {
						continue
					}
					isAllowed := allowed != nil && allowed[src] != nil && allowed[src][dst]
					if !defaultDeny && !isAllowed {
						sb.WriteString(fmt.Sprintf("-A %s -s %s -d %s -j DROP\n", m.Chain, src, dst))
					}
				}
			}
			sb.WriteString(fmt.Sprintf("-A %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", m.Chain))
			if defaultDeny {
				for i, src := range peers {
					for j, dst := range peers {
						if i == j {
							continue
						}
						if allowed != nil && allowed[src] != nil && allowed[src][dst] {
							sb.WriteString(fmt.Sprintf("-A %s -s %s -d %s -j ACCEPT\n", m.Chain, src, dst))
						} else {
							sb.WriteString(fmt.Sprintf("-A %s -s %s -d %s -j DROP\n", m.Chain, src, dst))
						}
					}
				}
			}
			sb.WriteString(fmt.Sprintf("-A %s -j RETURN\n", m.Chain))
			sb.WriteString("COMMIT\n")

			cmd := exec.Command(restoreBin, "--noflush")
			cmd.Stdin = strings.NewReader(sb.String())
			if out, err := cmd.CombinedOutput(); err == nil {
				return nil
			} else {
				_ = out
				// Fall through to individual iptables invocations if backend doesn't support --noflush
			}
		}
	}

	if out, err := m.Runner.Run("iptables", "-F", m.Chain); err != nil {
		return fmt.Errorf("iptables flush: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// First drop explicitly forbidden pairs BEFORE conntrack ESTABLISHED so active sessions are severed immediately on block
	for i, src := range peers {
		for j, dst := range peers {
			if i == j {
				continue
			}
			isAllowed := allowed != nil && allowed[src] != nil && allowed[src][dst]
			if !defaultDeny && !isAllowed {
				if out, err := m.Runner.Run("iptables", "-A", m.Chain, "-s", src, "-d", dst, "-j", "DROP"); err != nil {
					return fmt.Errorf("iptables drop %s->%s: %w: %s", src, dst, err, strings.TrimSpace(string(out)))
				}
			}
		}
	}
	// Allow return packets for established flows
	_, _ = m.Runner.Run("iptables", "-A", m.Chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")

	for i, src := range peers {
		for j, dst := range peers {
			if i == j {
				continue
			}
			isAllowed := allowed != nil && allowed[src] != nil && allowed[src][dst]
			if isAllowed {
				if out, err := m.Runner.Run("iptables", "-A", m.Chain, "-s", src, "-d", dst, "-j", "ACCEPT"); err != nil {
					return fmt.Errorf("iptables accept %s->%s: %w: %s", src, dst, err, strings.TrimSpace(string(out)))
				}
			} else if defaultDeny {
				if out, err := m.Runner.Run("iptables", "-A", m.Chain, "-s", src, "-d", dst, "-j", "DROP"); err != nil {
					return fmt.Errorf("iptables drop %s->%s: %w: %s", src, dst, err, strings.TrimSpace(string(out)))
				}
			}
		}
	}
	// Non-mesh host traffic returns untouched to parent chain!
	_, _ = m.Runner.Run("iptables", "-A", m.Chain, "-j", "RETURN")
	return nil
}

func HasIptables() bool {
	if _, err := exec.LookPath("iptables"); err == nil {
		return true
	}
	for _, candidate := range []string{"/usr/sbin/iptables", "/sbin/iptables"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return true
		}
	}
	return false
}

func CanUseIptables() bool {
	if !HasIptables() {
		return false
	}
	return exec.Command(iptablesBin(), "-L", "-n").Run() == nil
}

func (m *Manager) EnsureChainNoErr() {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.ensureChainLocked()
}
