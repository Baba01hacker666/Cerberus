package tunnel

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestKeysAndPacketUtilities(t *testing.T) {
	priv1, pub1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv2, pub2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 2: %v", err)
	}
	if priv1 == priv2 || pub1 == pub2 {
		t.Fatalf("generated duplicate keys!")
	}
	derivedPub, err := PublicKeyFromPrivate(priv1)
	if err != nil || derivedPub != pub1 {
		t.Fatalf("PublicKeyFromPrivate mismatch: %s vs %s (%v)", derivedPub, pub1, err)
	}
	hexKey, err := KeyToHex(pub1)
	if err != nil || len(hexKey) != 64 {
		t.Fatalf("KeyToHex invalid: %s (%v)", hexKey, err)
	}
	roundTrip, err := HexToKey(hexKey)
	if err != nil || roundTrip != pub1 {
		t.Fatalf("HexToKey round-trip mismatch: %s vs %s (%v)", roundTrip, pub1, err)
	}
	if _, err := ValidatePublicKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); err == nil {
		t.Fatalf("expected all-zero public key to fail validation")
	}

	// Verify ForwardCopy TTL decrement and RFC 1071 IPv4 checksum integrity
	req := BuildICMPEchoRequest(netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.3"), 42, 7, []byte("hello"))
	fwd, ok := ForwardCopy(req)
	if !ok {
		t.Fatalf("ForwardCopy failed")
	}
	if fwd[8] != req[8]-1 {
		t.Fatalf("expected TTL %d, got %d", req[8]-1, fwd[8])
	}
	if internetChecksum(fwd[:20]) != 0 {
		t.Fatalf("IPv4 header checksum after TTL decrement failed verification!")
	}
	// Verify TTL=1 drops instead of looping forever
	fwd[8] = 1
	if _, ok := ForwardCopy(fwd); ok {
		t.Fatalf("expected TTL=1 packet to be dropped")
	}
	_ = binary.BigEndian
}

func TestDirectWireGuardTunnelEncryptionAndStats(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	privA, pubA, _ := GenerateKeyPair()
	privB, pubB, _ := GenerateKeyPair()
	psk, _ := GeneratePresharedKey()

	tunA := New(TunnelConfig{
		Name:          "wgtest0",
		PrivateKey:    privA,
		PublicKey:     pubA,
		MeshIP:        "10.88.0.1/24",
		ListenPort:    0,
		UserspaceOnly: true,
	})
	tunB := New(TunnelConfig{
		Name:          "wgtest1",
		PrivateKey:    privB,
		PublicKey:     pubB,
		MeshIP:        "10.88.0.2/24",
		ListenPort:    0,
		UserspaceOnly: true,
	})

	if err := tunA.Start(ctx); err != nil {
		t.Fatalf("tunA Start: %v", err)
	}
	defer tunA.Stop()
	if err := tunB.Start(ctx); err != nil {
		t.Fatalf("tunB Start: %v", err)
	}
	defer tunB.Stop()

	// Configure responder (tunB) first, then initiator (tunA) — matching Server -> Client flow cleanly
	tunB.UpdatePeers([]PeerConfig{{
		PublicKey:    pubA,
		PresharedKey: psk,
		Endpoint:     "127.0.0.1:" + uitoa(tunA.ActualUDPPort()),
		AllowedIPs:   []string{"10.88.0.1/32"},
	}})
	tunA.UpdatePeers([]PeerConfig{{
		PublicKey:    pubB,
		PresharedKey: psk,
		Endpoint:     "127.0.0.1:" + uitoa(tunB.ActualUDPPort()),
		AllowedIPs:   []string{"10.88.0.2/32"},
		Keepalive:    15,
	}})

	rtt, err := tunA.Ping(ctx, "10.88.0.2", 3*time.Second)
	if err != nil {
		t.Fatalf("encrypted WireGuard ping failed: %v", err)
	}
	t.Logf("WireGuard Noise_IKpsk2 RTT: %v", rtt)

	stats, err := tunA.PeerStats()
	if err != nil || len(stats) != 1 || stats[0].TxBytes == 0 || stats[0].RxBytes == 0 {
		t.Fatalf("expected live non-zero TxBytes/RxBytes in PeerStats, got %+v (err=%v)", stats, err)
	}
}
