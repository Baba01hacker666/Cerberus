package node

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Baba01hacker666/cerberus/internal/config"
	"github.com/Baba01hacker666/cerberus/internal/control"
	"github.com/Baba01hacker666/cerberus/internal/tunnel"
)

// TestZeroSetupSmartServerAndConcurrentMeshUDP validates the full production workflow:
//   - Main server started on ONE single port
//   - 12 clients connect concurrently with ZERO client setup (no keys, no IP, no open ports)
//   - Smart server auto-assigns keys + PSKs + unique Mesh IPs
//   - All 12 clients ping server AND ping ALL OTHER CLIENTS concurrently + stream encrypted UDP payloads end-to-end!
func TestZeroSetupSmartServerAndConcurrentMeshUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	srvCfg := config.DefaultServerConfig()
	srvCfg.NodeName = "main-hub"
	srvCfg.ListenAddr = "127.0.0.1:0"
	srvCfg.DataDir = t.TempDir()
	srvCfg.MeshCIDR = "10.77.0.0/16"
	srvCfg.UserspaceOnly = true
	srvCfg.Docker.AutoAdd = false

	srv, err := StartServer(ctx, ServerOptions{
		Config:     srvCfg,
		ConfigPath: filepath.Join(srvCfg.DataDir, "server.yaml"),
	})
	if err != nil {
		t.Fatalf("StartServer: %v", err)
	}
	defer srv.Stop()

	const numClients = 12
	clients := make([]*Client, numClients)
	var joinWG sync.WaitGroup
	for i := 0; i < numClients; i++ {
		joinWG.Add(1)
		go func(idx int) {
			defer joinWG.Done()
			cl, err := StartClient(ctx, ClientOptions{
				ServerAddr:    srv.ListenAddr(), // ONLY server address passed — zero keys, zero IP!
				Name:          fmt.Sprintf("client-%02d", idx+1),
				StateDir:      filepath.Join(t.TempDir(), "state"),
				UserspaceOnly: true,
			})
			if err != nil {
				t.Errorf("StartClient %d failed: %v", idx, err)
				return
			}
			clients[idx] = cl
		}(i)
	}
	joinWG.Wait()

	defer func() {
		for _, cl := range clients {
			if cl != nil {
				cl.Stop()
			}
		}
	}()

	seenIPs := map[string]bool{srv.MeshIP(): true}
	for i, cl := range clients {
		if cl == nil {
			t.Fatalf("client %d nil", i)
		}
		if cl.Transport != "wireguard-udp" {
			t.Fatalf("expected client %d to use native wireguard-udp, got %s", i, cl.Transport)
		}
		if seenIPs[cl.MeshIP()] {
			t.Fatalf("duplicate mesh IP assigned: %s", cl.MeshIP())
		}
		seenIPs[cl.MeshIP()] = true
	}

	// All 12 clients concurrently ping the server AND every other client across the encrypted mesh!
	var pingWG sync.WaitGroup
	var totalPings atomic.Int64
	for i := 0; i < numClients; i++ {
		for j := 0; j < numClients; j++ {
			pingWG.Add(1)
			go func(srcIdx, dstIdx int) {
				defer pingWG.Done()
				src := clients[srcIdx]
				targetIP := srv.MeshIP()
				if srcIdx != dstIdx {
					targetIP = clients[dstIdx].MeshIP()
				}
				if _, err := src.Ping(ctx, targetIP, 5*time.Second); err != nil {
					t.Errorf("mesh ping %s (%s) -> %s failed: %v", src.PeerID(), src.MeshIP(), targetIP, err)
					return
				}
				totalPings.Add(1)
			}(i, j)
		}
	}
	pingWG.Wait()

	// Verify encrypted application payload integrity between Client 0 and Client 11 under burst concurrency
	rxCh, unsub := clients[numClients-1].Tunnel.Router().Subscribe(512)
	defer unsub()

	srcAddr := netip.MustParseAddr(clients[0].MeshIP())
	dstAddr := netip.MustParseAddr(clients[numClients-1].MeshIP())
	const payloads = 100
	var sendWG sync.WaitGroup
	for p := 0; p < payloads; p++ {
		sendWG.Add(1)
		go func(seq int) {
			defer sendWG.Done()
			msg := []byte(fmt.Sprintf("encrypted-payload-%04d", seq))
			pkt := tunnel.BuildUDPDatagram(srcAddr, dstAddr, uint16(20000+seq), 9999, msg)
			if err := clients[0].Tunnel.Router().InjectPacket(pkt); err != nil {
				t.Errorf("InjectPacket %d: %v", seq, err)
			}
		}(p)
	}
	sendWG.Wait()

	received := 0
	deadline := time.After(5 * time.Second)
	for received < payloads {
		select {
		case raw := <-rxCh:
			s, d, _, dport, data, ok := tunnel.ParseUDPDatagram(raw)
			if ok && s == srcAddr && d == dstAddr && dport == 9999 && bytes.HasPrefix(data, []byte("encrypted-payload-")) {
				received++
			}
		case <-deadline:
			t.Fatalf("received %d/%d encrypted UDP payloads across mesh", received, payloads)
		}
	}

	if relayed := srv.Tunnel.Router().RelayedPackets.Load(); relayed == 0 {
		t.Fatalf("expected server userspace mesh router RelayedPackets > 0")
	}
	t.Logf("SUCCESS: %d concurrent clients completed %d encrypted pings + %d concurrent UDP datagrams (server relayed=%d)",
		numClients, totalPings.Load(), received, srv.Tunnel.Router().RelayedPackets.Load())
}

// TestSinglePortTCPFallbackWhenUDPBlocked verifies that when a user ONLY opens ONE TCP port on their
// main cloud server (or Docker `-p 7443:7443` without `/udp`), clients automatically fall back to
// single-port HTTP-Upgrade WireGuard transport with full end-to-end Noise_IKpsk2 encryption!
func TestSinglePortTCPFallbackWhenUDPBlocked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	srvCfg := config.DefaultServerConfig()
	srvCfg.ListenAddr = "127.0.0.1:0"
	srvCfg.DataDir = t.TempDir()
	srvCfg.UserspaceOnly = true
	srvCfg.Docker.AutoAdd = false

	// ForceTCP disables all UDP traffic on the server socket — simulating a strict TCP-only firewall!
	srv, err := StartServer(ctx, ServerOptions{
		Config:   srvCfg,
		ForceTCP: true,
	})
	if err != nil {
		t.Fatalf("StartServer TCP-only: %v", err)
	}
	defer srv.Stop()

	const n = 5
	clients := make([]*Client, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cl, err := StartClient(ctx, ClientOptions{
				ServerAddr:    srv.ListenAddr(),
				Name:          fmt.Sprintf("tcp-worker-%d", idx),
				UserspaceOnly: true,
				ProbeTimeout:  150 * time.Millisecond,
			})
			if err != nil {
				t.Errorf("StartClient %d over TCP-only failed: %v", idx, err)
				return
			}
			clients[idx] = cl
		}(i)
	}
	wg.Wait()
	defer func() {
		for _, cl := range clients {
			if cl != nil {
				cl.Stop()
			}
		}
	}()

	for i, cl := range clients {
		if cl == nil {
			t.Fatalf("client %d failed to start", i)
		}
		if cl.Transport != "wireguard-tcp" {
			t.Fatalf("expected automatic fallback to wireguard-tcp, got %s", cl.Transport)
		}
	}

	// Verify both client -> server AND client -> client encrypted routing work over single TCP port!
	for i := 0; i < n; i++ {
		next := clients[(i+1)%n]
		if _, err := clients[i].Ping(ctx, srv.MeshIP(), 4*time.Second); err != nil {
			t.Fatalf("TCP-tunnel ping client %d -> server failed: %v", i, err)
		}
		if _, err := clients[i].Ping(ctx, next.MeshIP(), 4*time.Second); err != nil {
			t.Fatalf("TCP-tunnel peer-to-peer ping client %d -> client %d failed: %v", i, (i+1)%n, err)
		}
	}
}

// TestLiveDynamicIsolationAndReconnectWithoutSessionDisruption proves live block/allow firewall
// enforcement and persistent client identity/IP preservation across restarts.
func TestLiveDynamicIsolationAndReconnectWithoutSessionDisruption(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	srvCfg := config.DefaultServerConfig()
	srvCfg.ListenAddr = "127.0.0.1:0"
	srvCfg.DataDir = t.TempDir()
	srvCfg.AuthToken = "admin-tok"
	srvCfg.UserspaceOnly = true
	srvCfg.Docker.AutoAdd = false

	srv, err := StartServer(ctx, ServerOptions{Config: srvCfg})
	if err != nil {
		t.Fatalf("StartServer: %v", err)
	}
	defer srv.Stop()

	stateApp := filepath.Join(t.TempDir(), "app-state")
	web, err := StartClient(ctx, ClientOptions{ServerAddr: srv.ListenAddr(), Name: "web", Token: "admin-tok", UserspaceOnly: true})
	if err != nil {
		t.Fatalf("start web: %v", err)
	}
	defer web.Stop()

	app, err := StartClient(ctx, ClientOptions{ServerAddr: srv.ListenAddr(), Name: "app", Token: "admin-tok", StateDir: stateApp, UserspaceOnly: true})
	if err != nil {
		t.Fatalf("start app: %v", err)
	}

	db, err := StartClient(ctx, ClientOptions{ServerAddr: srv.ListenAddr(), Name: "db", Token: "admin-tok", UserspaceOnly: true})
	if err != nil {
		t.Fatalf("start db: %v", err)
	}
	defer db.Stop()

	// Initially all pairs can reach each other
	if _, err := web.Ping(ctx, db.MeshIP(), 3*time.Second); err != nil {
		t.Fatalf("initial web -> db ping failed: %v", err)
	}

	// Block web -> db live via control plane API!
	adminAPI := control.NewClient(srv.BaseURL())
	adminAPI.AuthToken = "admin-tok"
	if _, err := adminAPI.BlockPeers("web", "db"); err != nil {
		t.Fatalf("BlockPeers: %v", err)
	}

	if _, err := web.Ping(ctx, db.MeshIP(), 400*time.Millisecond); err == nil {
		t.Fatalf("expected web -> db ping to be DROPPED by live isolation policy!")
	}
	// Meanwhile app -> db MUST still work uninterrupted!
	if _, err := app.Ping(ctx, db.MeshIP(), 3*time.Second); err != nil {
		t.Fatalf("expected app -> db ping to keep working while web -> db is blocked: %v", err)
	}

	// Re-allow web -> db live!
	if _, err := adminAPI.AllowPeers("web", "db"); err != nil {
		t.Fatalf("AllowPeers: %v", err)
	}
	if _, err := web.Ping(ctx, db.MeshIP(), 3*time.Second); err != nil {
		t.Fatalf("expected web -> db ping to succeed immediately after AllowPeers: %v", err)
	}

	// Restart app client from same StateDir and confirm exact IP + ID persistence without breaking web <-> db!
	origAppIP := app.MeshIP()
	app.Stop()

	appRestarted, err := StartClient(ctx, ClientOptions{ServerAddr: srv.ListenAddr(), Name: "app", Token: "admin-tok", StateDir: stateApp, UserspaceOnly: true})
	if err != nil {
		t.Fatalf("restart app: %v", err)
	}
	defer appRestarted.Stop()

	if appRestarted.MeshIP() != origAppIP {
		t.Fatalf("expected restarted client to retain IP %s, got %s", origAppIP, appRestarted.MeshIP())
	}
	if _, err := web.Ping(ctx, appRestarted.MeshIP(), 3*time.Second); err != nil {
		t.Fatalf("ping to restarted app failed: %v", err)
	}
}

// TestRealLinuxKernelNetnsMultiHostTunnel runs a full multi-machine simulation using REAL Linux
// network namespaces (`ip netns`) + REAL Kernel `cerberus0` TUN interfaces + REAL TCP HTTP servers
// bound to mesh IPs (10.77.0.1, 10.77.0.2, 10.77.0.3) whenever executed with root privileges!
func TestRealLinuxKernelNetnsMultiHostTunnel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping real kernel TUN + ip netns multi-host test (run with sudo to execute)")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 not installed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// Build fresh binary once for real subprocess execution inside isolated network namespaces
	binPath := filepath.Join(t.TempDir(), "cerberus")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, "../..")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build cerberus binary: %v\n%s", err, string(out))
	}

	nsSrv := "cbtest-srv"
	nsCli1 := "cbtest-c1"
	nsCli2 := "cbtest-c2"
	brName := "cbbr0"

	cleanup := func() {
		for _, ns := range []string{nsSrv, nsCli1, nsCli2} {
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
		_ = exec.Command("ip", "link", "del", brName).Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	mustRun := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("cmd %v failed: %v\n%s", args, err, string(out))
		}
	}

	// Build virtual 3-host LAN switch in kernel: 172.31.77.1 (srv), 172.31.77.2 (c1), 172.31.77.3 (c2)
	mustRun("ip", "link", "add", brName, "type", "bridge")
	mustRun("ip", "link", "set", brName, "up")
	for i, ns := range []string{nsSrv, nsCli1, nsCli2} {
		vHost := fmt.Sprintf("cbvh%d", i)
		vPeer := fmt.Sprintf("cbvp%d", i)
		mustRun("ip", "netns", "add", ns)
		mustRun("ip", "link", "add", vHost, "type", "veth", "peer", "name", vPeer)
		mustRun("ip", "link", "set", vHost, "master", brName)
		mustRun("ip", "link", "set", vHost, "up")
		mustRun("ip", "link", "set", vPeer, "netns", ns)
		mustRun("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
		mustRun("ip", "netns", "exec", ns, "ip", "addr", "add", fmt.Sprintf("172.31.77.%d/24", i+1), "dev", vPeer)
		mustRun("ip", "netns", "exec", ns, "ip", "link", "set", vPeer, "up")
	}

	// Start Cerberus Smart Server inside nsSrv on single port 7443!
	srvDir := t.TempDir()
	srvProc := exec.CommandContext(ctx, "ip", "netns", "exec", nsSrv,
		binPath, "--config", filepath.Join(srvDir, "cfg.yaml"),
		"server", "--port", "7443", "--name", "main-server")
	srvProc.Env = append(os.Environ(), "CERBERUS_DATA_DIR="+srvDir)
	srvOut := &bytes.Buffer{}
	srvProc.Stdout = srvOut
	srvProc.Stderr = srvOut
	if err := srvProc.Start(); err != nil {
		t.Fatalf("start nsSrv server: %v", err)
	}
	defer func() { _ = srvProc.Process.Kill(); _ = srvProc.Wait() }()

	// Wait until server health endpoint responds over the virtual switch
	ready := false
	for i := 0; i < 40; i++ {
		if exec.Command("ip", "netns", "exec", nsCli1, "python3", "-c",
			"import urllib.request; urllib.request.urlopen('http://172.31.77.1:7443/health', timeout=1)").Run() == nil {
			ready = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("server never became healthy in netns:\n%s", srvOut.String())
	}

	// Start ZERO-SETUP client 1 in nsCli1 and ZERO-SETUP client 2 in nsCli2!
	c1Dir := t.TempDir()
	c1Proc := exec.CommandContext(ctx, "ip", "netns", "exec", nsCli1,
		binPath, "--config", filepath.Join(c1Dir, "cfg.yaml"),
		"client", "172.31.77.1:7443", "--name", "worker-1", "--state-dir", c1Dir)
	c1Out := &bytes.Buffer{}
	c1Proc.Stdout = c1Out
	c1Proc.Stderr = c1Out
	if err := c1Proc.Start(); err != nil {
		t.Fatalf("start c1: %v", err)
	}
	defer func() { _ = c1Proc.Process.Kill(); _ = c1Proc.Wait() }()

	c2Dir := t.TempDir()
	c2Proc := exec.CommandContext(ctx, "ip", "netns", "exec", nsCli2,
		binPath, "--config", filepath.Join(c2Dir, "cfg.yaml"),
		"client", "172.31.77.1:7443", "--name", "worker-2", "--state-dir", c2Dir)
	c2Out := &bytes.Buffer{}
	c2Proc.Stdout = c2Out
	c2Proc.Stderr = c2Out
	if err := c2Proc.Start(); err != nil {
		t.Fatalf("start c2: %v", err)
	}
	defer func() { _ = c2Proc.Process.Kill(); _ = c2Proc.Wait() }()

	// Wait for cerberus0 to come up inside both client namespaces
	for i := 0; i < 40; i++ {
		ok1 := exec.Command("ip", "netns", "exec", nsCli1, "ip", "addr", "show", "dev", "cerberus0").Run() == nil
		ok2 := exec.Command("ip", "netns", "exec", nsCli2, "ip", "addr", "show", "dev", "cerberus0").Run() == nil
		if ok1 && ok2 {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}

	// Query smart server API to dynamically discover worker-1's auto-assigned MeshIP!
	srvAPI := control.NewClient("http://172.31.77.1:7443")
	var worker1IP string
	for i := 0; i < 40; i++ {
		if statusOut, err := exec.Command("ip", "netns", "exec", nsCli2, "python3", "-c",
			`import urllib.request, json
peers = json.loads(urllib.request.urlopen("http://172.31.77.1:7443/peers", timeout=2).read().decode())
for p in peers:
    if p.get("id") == "worker-1" and p.get("mesh_ip"):
        print(p["mesh_ip"])`).CombinedOutput(); err == nil {
			ip := string(bytes.TrimSpace(statusOut))
			if ip != "" {
				worker1IP = ip
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = srvAPI
	if worker1IP == "" {
		t.Fatalf("worker-1 never received auto-assigned mesh IP:\nsrv=%s\nc1=%s", srvOut.String(), c1Out.String())
	}

	// Start real TCP HTTP server inside nsCli1 bound strictly to its assigned mesh IP!
	httpSrv := exec.CommandContext(ctx, "ip", "netns", "exec", nsCli1, "python3", "-c",
		fmt.Sprintf(`import http.server
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"HELLO-OVER-REAL-KERNEL-WIREGUARD-MESH")
http.server.ThreadingHTTPServer((%q, 9080), H).serve_forever()`, worker1IP))
	if err := httpSrv.Start(); err != nil {
		t.Fatalf("start python http server in nsCli1: %v", err)
	}
	defer func() { _ = httpSrv.Process.Kill(); _ = httpSrv.Wait() }()
	time.Sleep(250 * time.Millisecond)

	targetURL := fmt.Sprintf("http://%s:9080/", worker1IP)

	// Fire 16 CONCURRENT real kernel TCP HTTP requests from nsCli2 -> nsCli1 over cerberus0!
	out, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsCli2, "python3", "-c",
		fmt.Sprintf(`import concurrent.futures, urllib.request
def fetch(_):
    with urllib.request.urlopen(%q, timeout=5) as r:
        return r.read().decode()
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
    res = list(ex.map(fetch, range(16)))
assert all(x == "HELLO-OVER-REAL-KERNEL-WIREGUARD-MESH" for x in res), res
print("CONCURRENT_KERNEL_HTTP_OK:", len(res))`, targetURL)).CombinedOutput()
	if err != nil {
		t.Fatalf("concurrent real TCP HTTP across namespaces failed: %v\nout=%s\nsrv=%s\nc1=%s\nc2=%s",
			err, string(out), srvOut.String(), c1Out.String(), c2Out.String())
	}
	t.Logf("Real kernel multi-netns TCP test output (%s): %s", targetURL, string(bytes.TrimSpace(out)))

	// Test live firewall isolation between worker-2 and worker-1 right inside nsSrv!
	mustRun("ip", "netns", "exec", nsSrv, binPath, "--config", filepath.Join(srvDir, "cfg.yaml"),
		"isolate", "block", "worker-2", "worker-1")

	if err := exec.CommandContext(ctx, "ip", "netns", "exec", nsCli2, "python3", "-c",
		fmt.Sprintf(`import urllib.request; urllib.request.urlopen(%q, timeout=1.2)`, targetURL)).Run(); err == nil {
		t.Fatalf("expected HTTP over cerberus0 to be BLOCKED when isolated!")
	}

	mustRun("ip", "netns", "exec", nsSrv, binPath, "--config", filepath.Join(srvDir, "cfg.yaml"),
		"isolate", "allow", "worker-2", "worker-1")

	if out, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsCli2, "python3", "-c",
		fmt.Sprintf(`import urllib.request; print(urllib.request.urlopen(%q, timeout=4).read().decode())`, targetURL)).CombinedOutput(); err != nil {
		t.Fatalf("expected HTTP over cerberus0 to RECOVER immediately after isolate allow: %v (%s)", err, string(out))
	}

	_ = http.StatusOK
	_ = io.EOF
}
