package store

import (
	"fmt"
	"sync"
	"testing"
)

func TestStoreDeepCopySecretRedactionAndConcurrentSave(t *testing.T) {
	dir := t.TempDir()
	st := New(dir)

	var wg sync.WaitGroup
	for g := 0; g < 40; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			peerID := fmt.Sprintf("node-%03d", id)
			p := Peer{
				ID:           peerID,
				Name:         peerID,
				PublicKey:    fmt.Sprintf("pub-%03d", id),
				PresharedKey: "super-secret-psk",
				PeerSecret:   "super-secret-token",
				MeshIP:       fmt.Sprintf("10.77.1.%d", id+2),
				AllowedIPs:   []string{fmt.Sprintf("10.77.1.%d/32", id+2)},
				Labels:       map[string]string{"role": "worker"},
			}
			if err := st.Add(p); err != nil {
				t.Errorf("Add: %v", err)
			}
			st.UpdateLastSeen(peerID, 123456, "198.51.100.10:51820")
			if err := st.Save(); err != nil {
				t.Errorf("concurrent Save failed: %v", err)
			}
			_ = st.List()
			_ = st.PublicList()
		}(g)
	}
	wg.Wait()

	// Verify PublicList redacts secrets while preserving internal Store secrets on reload
	pub := st.PublicList()
	if len(pub) != 40 {
		t.Fatalf("expected 40 peers, got %d", len(pub))
	}
	for i, p := range pub {
		if p.PeerSecret != "" || p.PresharedKey != "" {
			t.Fatalf("PublicList leaked secret on %s", p.ID)
		}
		if i > 0 && pub[i-1].ID >= p.ID {
			t.Fatalf("List not deterministically sorted: %s before %s", pub[i-1].ID, p.ID)
		}
	}

	// Mutating returned slice/map must not mutate internal state
	got, ok := st.Get("node-000")
	if !ok {
		t.Fatalf("missing node-000")
	}
	got.Labels["role"] = "tampered"
	got.AllowedIPs[0] = "0.0.0.0/0"

	gotAgain, _ := st.Get("node-000")
	if gotAgain.Labels["role"] != "worker" || gotAgain.AllowedIPs[0] == "0.0.0.0/0" {
		t.Fatalf("Store failed to isolate internal memory via deep copy")
	}

	// Reload from disk and confirm secrets survived atomic writes intact
	reloaded := New(dir)
	r0, ok := reloaded.Get("node-000")
	if !ok || r0.PeerSecret != "super-secret-token" || r0.PresharedKey != "super-secret-psk" {
		t.Fatalf("reload corrupted peer: %+v", r0)
	}
}
