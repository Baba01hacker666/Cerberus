package control

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Baba01hacker666/cerberus/internal/config"
	"github.com/Baba01hacker666/cerberus/internal/store"
)

func TestZeroConfigJoinDuplicateHostnamesAuthAndConcurrentStorm(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultServerConfig()
	cfg.DataDir = dir
	cfg.MeshCIDR = "10.99.0.0/16"
	cfg.AuthToken = "secret-mesh-token"

	st := store.New(dir)
	state, err := NewState(cfg, st)
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	ts := httptest.NewServer(state.Handler())
	defer ts.Close()

	// 1. Unauthenticated client must receive error when AuthToken is configured
	unauthClient := NewClient(ts.URL)
	if _, err := unauthClient.Join(RegisterReq{Name: "intruder"}); err == nil {
		t.Fatalf("expected unauthenticated Join to fail")
	}

	// 2. Zero-config smart client Join with NO keys and NO IP auto-provisions everything
	authed := NewClient(ts.URL)
	authed.AuthToken = "secret-mesh-token"

	jr1, err := authed.Join(RegisterReq{})
	if err != nil {
		t.Fatalf("zero-setup Join failed: %v", err)
	}
	if jr1.PrivateKey == "" || jr1.Peer.PublicKey == "" || jr1.PresharedKey == "" || jr1.PeerSecret == "" {
		t.Fatalf("expected full auto-generated crypto material: %+v", jr1)
	}
	if jr1.Peer.MeshIP != "10.99.0.2" {
		t.Fatalf("expected first client IP 10.99.0.2 (since .1 is server), got %s", jr1.Peer.MeshIP)
	}

	// 3. Reconnecting with same PeerID + PeerSecret preserves exact IP & identity
	reconn, err := authed.Join(RegisterReq{
		PeerID:     jr1.Peer.ID,
		PeerSecret: jr1.PeerSecret,
		PublicKey:  jr1.Peer.PublicKey,
	})
	if err != nil {
		t.Fatalf("reconnect Join failed: %v", err)
	}
	if reconn.Peer.MeshIP != jr1.Peer.MeshIP || reconn.Peer.ID != jr1.Peer.ID {
		t.Fatalf("reconnect changed identity/IP: %+v vs %+v", reconn.Peer, jr1.Peer)
	}

	// 4. Multiple machines sharing default hostname "ubuntu" get disambiguated IDs & unique IPs without hijacking!
	seenIDs := map[string]bool{}
	seenIPs := map[string]bool{}
	for i := 0; i < 5; i++ {
		cl := NewClient(ts.URL)
		cl.AuthToken = "secret-mesh-token"
		res, err := cl.Join(RegisterReq{Name: "ubuntu"})
		if err != nil {
			t.Fatalf("ubuntu #%d join failed: %v", i, err)
		}
		if seenIDs[res.Peer.ID] || seenIPs[res.Peer.MeshIP] {
			t.Fatalf("hostname collision caused hijack/duplicate: %+v", res.Peer)
		}
		seenIDs[res.Peer.ID] = true
		seenIPs[res.Peer.MeshIP] = true
	}

	// 5. Real-time SSE /events push notification + 50 concurrent joins/heartbeats
	sseCtx, sseCancel := context.WithCancel(context.Background())
	defer sseCancel()
	eventReceived := make(chan uint64, 16)
	go func() {
		_ = authed.WatchEvents(sseCtx, func(v uint64) {
			select {
			case eventReceived <- v:
			default:
			}
		})
	}()

	var wg sync.WaitGroup
	const concurrentClients = 50
	for i := 0; i < concurrentClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cl := NewClient(ts.URL)
			cl.AuthToken = "secret-mesh-token"
			jr, err := cl.Join(RegisterReq{Name: fmt.Sprintf("worker-%d", idx)})
			if err != nil {
				t.Errorf("concurrent Join %d failed: %v", idx, err)
				return
			}
			if _, err := cl.Heartbeat(""); err != nil {
				t.Errorf("concurrent Heartbeat %d failed: %v", idx, err)
			}
			_ = jr
		}(i)
	}
	wg.Wait()

	select {
	case <-eventReceived:
	case <-time.After(3 * time.Second):
		t.Fatalf("expected SSE /events version notification")
	}
}
