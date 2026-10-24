package isolation

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func buildTestTCPPacket(src, dst string, sport, dport uint16, flags byte) []byte {
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	pkt[32] = 0x50 // 20-byte TCP header
	pkt[33] = flags
	return pkt
}

func TestPolicyEngineStatefulZeroTrustAndInstantBlockRevocation(t *testing.T) {
	pe := NewPolicyEngine()
	names := map[string]string{
		"web": "10.77.0.2",
		"db":  "10.77.0.3",
		"bad": "10.77.0.4",
	}

	// Zero-trust default deny: ONLY web -> db is allowed!
	pe.Configure(true, true, []string{"web->db"}, nil, nil, names)

	synWebToDB := buildTestTCPPacket("10.77.0.2", "10.77.0.3", 51000, 5432, 0x02)    // SYN
	synAckDBToWeb := buildTestTCPPacket("10.77.0.3", "10.77.0.2", 5432, 51000, 0x12) // SYN+ACK reply!
	synDBToWebNew := buildTestTCPPacket("10.77.0.3", "10.77.0.2", 44000, 8080, 0x02) // Unsolicited SYN from db -> web!
	synBadToDB := buildTestTCPPacket("10.77.0.4", "10.77.0.3", 52000, 5432, 0x02)

	if !pe.AllowPacket(synWebToDB) {
		t.Fatalf("expected allowed forward SYN web -> db")
	}
	if !pe.AllowPacket(synAckDBToWeb) {
		t.Fatalf("expected stateful return SYN-ACK db -> web to be allowed!")
	}
	if pe.AllowPacket(synDBToWebNew) {
		t.Fatalf("expected unsolicited reverse SYN db -> web to be blocked!")
	}
	if pe.AllowPacket(synBadToDB) {
		t.Fatalf("expected unauthorized peer SYN bad -> db to be blocked!")
	}

	// Now explicitly block web -> db dynamically: both new packets AND existing flow ACKs must drop immediately!
	pe.Configure(true, true, nil, []string{"web->db"}, nil, names)
	if pe.AllowPacket(synWebToDB) {
		t.Fatalf("expected revoked web -> db SYN to be dropped immediately")
	}
	if pe.AllowPacket(synAckDBToWeb) {
		t.Fatalf("expected stale tracked flow to be purged immediately on policy change")
	}
}

type mockRunner struct {
	mu   sync.Mutex
	cmds []string
}

func (m *mockRunner) Run(name string, args ...string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cmds = append(m.cmds, name+" "+strings.Join(args, " "))
	return nil, nil
}

func TestIptablesManagerOrderingAndConcurrency(t *testing.T) {
	mr := &mockRunner{}
	mgr := NewWithRunner("CERBERUS", mr)

	peers := []string{"10.77.0.2", "10.77.0.3"}
	allowed := map[string]map[string]bool{
		"10.77.0.2": {"10.77.0.3": true},
		"10.77.0.3": {},
	}
	if err := mgr.ApplyPolicy(peers, allowed, false); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}

	joined := strings.Join(mr.cmds, "\n")
	// 3->2 is a directional block (reverse 2->3 is allowed), so it must only
	// drop NEW packets and still let replies to the permitted flow through.
	dropIdx := strings.Index(joined, "-A CERBERUS -s 10.77.0.3 -d 10.77.0.2 -m conntrack --ctstate NEW -j DROP")
	ctIdx := strings.Index(joined, "ESTABLISHED,RELATED")
	accIdx := strings.Index(joined, "-A CERBERUS -s 10.77.0.2 -d 10.77.0.3 -j ACCEPT")
	if dropIdx < 0 || ctIdx < 0 || accIdx < 0 || dropIdx >= ctIdx || ctIdx >= accIdx {
		t.Fatalf("expected NEW-only directional DROP before ESTABLISHED conntrack before ACCEPT, got:\n%s", joined)
	}

	// A bidirectional/quarantine block must still be unconditional so existing
	// sessions are severed immediately.
	mr.mu.Lock()
	mr.cmds = nil
	mr.mu.Unlock()
	quarantine := map[string]map[string]bool{
		"10.77.0.2": {},
		"10.77.0.3": {},
	}
	if err := mgr.ApplyPolicy(peers, quarantine, false); err != nil {
		t.Fatalf("ApplyPolicy quarantine: %v", err)
	}
	qJoined := strings.Join(mr.cmds, "\n")
	qDrop := "-A CERBERUS -s 10.77.0.2 -d 10.77.0.3 -j DROP"
	if !strings.Contains(qJoined, qDrop) {
		t.Fatalf("expected unconditional DROP for bidirectional/quarantine block, got:\n%s", qJoined)
	}

	// Parallel packet evaluation + hot policy swap under -race
	pe := NewPolicyEngine()
	pe.Configure(true, false, nil, []string{"10.77.0.9"}, nil, nil)
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if i%50 == 0 && id == 0 {
					pe.Configure(true, i%100 == 0, []string{"10.77.0.2->10.77.0.3"}, []string{"10.77.0.9"}, nil, nil)
				}
				pkt := buildTestTCPPacket("10.77.0.2", "10.77.0.3", uint16(10000+id), 80, 0x02)
				_ = pe.AllowPacket(pkt)
			}
		}(g)
	}
	wg.Wait()
}
