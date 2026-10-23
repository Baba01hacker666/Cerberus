# Cerberus

Cerberus is a WireGuard-inspired mesh networking tool built for Docker containers.
It auto-discovers containers, assigns mesh IPs, coordinates peers over a modern
HTTP/2 control plane, tunnels traffic with a custom encrypted UDP protocol (X25519 + ChaCha20-Poly1305), and can isolate containers
from each other with firewall policies.

## One-liner install

```bash
curl -fsSL https://raw.githubusercontent.com/Baba01hacker666/cerberus/main/scripts/install.sh | bash
```

## Build from source

```bash
go build -o cerberus .
```

## Quick start

```bash
# Initialize node (generates keys)
cerberus init

# Run daemon
cerberus daemon

# Peer with another node
cerberus peer add http://peer-host:7443

# Manual peer
cerberus peer add --pubkey <key> --endpoint host:51820 --ip 10.77.0.5 --name peer1

# Client mode (join mesh from a container/host)
cerberus client --server http://hub:7443 --name worker1

# Isolation
cerberus isolate block 10.77.0.2 10.77.0.3
cerberus isolate allow 10.77.0.2 10.77.0.3
cerberus isolate apply
```

## Container auto-add

Containers labeled `cerberus.enable=true` are automatically added to the mesh.
Optional label `cerberus.public-key=<x25519 pubkey>`.

```bash
docker run -d --label cerberus.enable=true --label cerberus.public-key=<pub> nginx
```

## Features

- Auto peer discovery & registration
 - Custom data plane: X25519 key exchange + ChaCha20-Poly1305 over UDP (WireGuard-inspired, no wg dependency)
- HTTP/2 JSON control plane
- Docker container auto-add via labels
- Mesh IP allocation from CIDR
- Isolation: block/allow between containers, default-deny policies
- iptables-based enforcement
- One-liner installer + systemd service
- GitHub Actions build & push (binaries + Docker image)

## Architecture

```
+-----------+        HTTP/2 (control)        +-----------+
| cerberus  |<---------------------------->| cerberus  |
|  daemon   |                              |  daemon   |
+-----+-----+                              +-----+-----+
      |                                          |
      | Encrypted UDP tunnel (X25519+ChaCha20)   |
      +------------------------------------------+
```

## License

MIT - apt235 / baba01hacker
