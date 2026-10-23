# Cerberus

Cerberus is a **zero-setup WireGuard mesh & private network engine** written in pure Go (single static binary, zero external `wg` / `wireguard-tools` dependency).

Deploy Cerberus on **one main server** and open **a single port** (`7443` by default). Every client machine or container connects with **one command and zero setup** — the Smart Server automatically generates X25519 + 256-bit PresharedKey credentials, allocates unique mesh IPs, configures kernel/userspace WireGuard tunnels, routes peer-to-peer traffic across NATs, automatically falls back from UDP to single-port TCP transport when UDP is blocked by firewalls, and enforces real-time stateful isolation policies.

---

## 30-Second Quick Start

### 1. Main Server (open ONE port — e.g. `7443`)

```bash
# Build from source
make build

# Start the Smart Server on port 7443 (handles control API + WireGuard UDP + TCP fallback!)
sudo ./cerberus server --port 7443
```

Optional token authentication:

```bash
sudo ./cerberus server --port 7443 --token my-secret-token
```

### 2. Any Client (ZERO setup — auto-assigned keys, PSK & mesh IP!)

No `init`, no manual key copying, no inbound ports needed on clients:

```bash
sudo ./cerberus client <SERVER_IP>:7443
```

If `--token` was set on the server:

```bash
sudo ./cerberus client <SERVER_IP>:7443 --token my-secret-token
```

Every connected node immediately joins `10.77.0.0/16` (`10.77.0.1` server gateway, `10.77.0.2`, `10.77.0.3`, ...) and can reach both the server and every other client (`ping`, `ssh`, `http`, `postgres`, Docker services, etc.) even when all clients sit behind strict symmetric NATs.

---

## One-Liner Install

```bash
# Main Server (installs systemd unit and starts immediately on port 7443):
curl -fsSL https://raw.githubusercontent.com/Baba01hacker666/Cerberus/main/scripts/install.sh | sudo bash -s -- --server --port 7443

# Any Client (installs systemd unit and joins server with zero setup):
curl -fsSL https://raw.githubusercontent.com/Baba01hacker666/Cerberus/main/scripts/install.sh | sudo bash -s -- --client <SERVER_IP>:7443
```

---

## Architecture & Security

```
                  Single Open Port (:7443)
          +---------------------------------------+
          |       Cerberus Smart Server           |
          |  10.77.0.1/16  (Hub + Mesh Router)    |
          |                                       |
          |  - Auto X25519 + 256b PSK issuer      |
          |  - Atomic concurrent IPAM             |
          |  - Official wireguard-go engine       |
          |  - Stateful zero-trust PolicyEngine   |
          |  - SSE real-time topology stream      |
          +---------+-------------------+---------+
                    ^                   ^
     WireGuard UDP  |                   |  WireGuard over TCP Upgrade
   (line-rate fast  |                   |  (auto fallback when cloud /
     path on :7443) |                   |   corporate firewall blocks UDP!)
                    v                   v
        +-----------+---+           +---+-----------+
        | Client Node A |           | Client Node B |
        |  10.77.0.2    | <=======> |  10.77.0.3    |
        | (Behind NAT)  | Encrypted | (Behind NAT)  |
        +---------------+ Peer Mesh +---------------+
```

### Key Capabilities

- **Battle-Tested Cryptography (`golang.zx2c4.com/wireguard`)**: Full WireGuard `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` protocol with ephemeral keys, Perfect Forward Secrecy, automatic rekeying, 64-bit replay counters, DoS cookies, and per-peer 256-bit PresharedKeys generated via `crypto/rand`.
- **Single-Port Dual Transport (`HybridBind`)**: Runs HTTP/2 control + real-time SSE + native WireGuard UDP on the exact same port (`7443`). On startup, clients probe UDP reachability and automatically tunnel encrypted WireGuard frames over `HTTP/1.1 Upgrade: cerberus-wg/1` TCP if UDP is blocked (e.g. TCP-only cloud security groups or `docker run -p 7443:7443`).
- **Smart Auto-Provisioning & Anti-Hijack Identity**: Clients need zero pre-configuration. Reconnecting nodes preserve their exact IP & identity using per-peer cryptographic secrets (`0600` state files), while distinct hosts sharing hostnames (e.g. multiple `ubuntu` VMs) are automatically disambiguated (`ubuntu`, `ubuntu-2`, ...).
- **Zero-Disruption Incremental Reconciler**: Differential WireGuard UAPI updates add/remove peers live without resetting active Noise handshakes or learned NAT roaming endpoints.
- **Stateful Container & Peer Isolation**: Lock-free userspace `PolicyEngine` (`atomic.Pointer` + stateful TCP/UDP/ICMP return-flow tracking) paired with host `iptables` enforcement.

---

## CLI Reference

```bash
# Run main server
cerberus server --port 7443 [--cidr 10.77.0.0/16] [--token SECRET] [--default-deny]

# Join mesh from any client (alias: `cerberus up`)
cerberus client <SERVER_IP>:7443 [--name web-1] [--token SECRET] [--write-wg-conf ./wg0.conf]

# Inspect live daemon telemetry (handshakes, rx/tx bytes, relayed packets, policy drops)
cerberus status

# Ping a mesh IP or peer name through the tunnel
cerberus ping worker-1

# Real-time firewall isolation between peers/containers
cerberus isolate block worker-2 db-1
cerberus isolate allow worker-2 db-1
cerberus isolate status

# Manage peers manually
cerberus peer list
cerberus peer remove worker-2
```

---

## Testing

```bash
# Full unit, concurrency & race-detector suite (no root required)
make test

# Full suite INCLUDING real Linux multi-netns + kernel TUN TCP/firewall integration tests
make test-root
```

## License

MIT - apt235 / baba01hacker
