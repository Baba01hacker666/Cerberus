package mesh

import (
	"fmt"
	"sync"
	"testing"
)

func TestAllocatorExhaustionWrapAndOwnerIdempotency(t *testing.T) {
	// 10.77.0.0/29 has addresses .0 (network), .1 (server), .2..6 (5 usable client hosts), .7 (broadcast)
	a, err := NewAllocator("10.77.0.0/29")
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if a.ServerIP() != "10.77.0.1" {
		t.Fatalf("expected server IP 10.77.0.1, got %s", a.ServerIP())
	}

	// Attempting to request server IP (.1) or network (.0) or broadcast (.7) must never assign them!
	ipA, err := a.AllocateForOwner("peer-a", "10.77.0.1")
	if err != nil {
		t.Fatalf("allocate peer-a: %v", err)
	}
	if ipA == "10.77.0.1" || ipA == "10.77.0.0" || ipA == "10.77.0.7" {
		t.Fatalf("reserved address handed out: %s", ipA)
	}

	// Re-allocating for same owner returns identical IP without consuming more addresses
	for i := 0; i < 10; i++ {
		same, err := a.AllocateForOwner("peer-a", "")
		if err != nil || same != ipA {
			t.Fatalf("expected idempotent IP %s, got %s (err=%v)", ipA, same, err)
		}
	}

	// Fill remaining 4 usable slots
	seen := map[string]bool{ipA: true}
	for i := 2; i <= 5; i++ {
		ip, err := a.AllocateForOwner(fmt.Sprintf("peer-%d", i), "")
		if err != nil {
			t.Fatalf("slot %d failed: %v", i, err)
		}
		if seen[ip] {
			t.Fatalf("duplicate IP %s", ip)
		}
		seen[ip] = true
	}

	// 6th distinct client must get exhaustion error
	if _, err := a.AllocateForOwner("peer-overflow", ""); err == nil {
		t.Fatalf("expected subnet exhaustion error")
	}

	// Release two peers and verify wrap-around re-allocates cleanly
	a.ReleaseOwner("peer-2")
	a.ReleaseOwner("peer-4")

	for i := 0; i < 2; i++ {
		ip, err := a.AllocateForOwner(fmt.Sprintf("new-peer-%d", i), "")
		if err != nil {
			t.Fatalf("re-allocate after release failed: %v", err)
		}
		if !a.Contains(ip) || ip == a.ServerIP() {
			t.Fatalf("invalid recycled IP: %s", ip)
		}
	}
}

func TestAllocatorHighConcurrency(t *testing.T) {
	a, err := NewAllocator("10.77.0.0/16")
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	const workers = 100
	results := make([]string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			owner := fmt.Sprintf("worker-%d", idx)
			ip1, err := a.AllocateForOwner(owner, "")
			if err != nil {
				t.Errorf("worker %d alloc error: %v", idx, err)
				return
			}
			// Concurrent duplicate heartbeats must return identical IP
			ip2, err := a.AllocateForOwner(owner, ip1)
			if err != nil || ip1 != ip2 {
				t.Errorf("worker %d mismatch: %s vs %s (err=%v)", idx, ip1, ip2, err)
				return
			}
			results[idx] = ip1
		}(i)
	}
	wg.Wait()

	unique := make(map[string]int, workers)
	for idx, ip := range results {
		if prev, dup := unique[ip]; dup {
			t.Fatalf("duplicate IP %s assigned to worker %d and %d", ip, prev, idx)
		}
		unique[ip] = idx
	}
	if a.AllocatedCount() != workers {
		t.Fatalf("expected %d allocated, got %d", workers, a.AllocatedCount())
	}
}
