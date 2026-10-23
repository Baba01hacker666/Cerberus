# Cerberus

Cerberus is a WireGuard-like mesh networking tool built for Docker containers.
It auto-discovers containers, assigns mesh IPs, coordinates peers over a modern
HTTP/2 control plane, tunnels traffic with WireGuard, and can isolate containers
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

# Isolation
cerberus isolate block 10.77.0.2 10.77.0.3
cerberus isolate allow 10.77.0.2 10.77.0.3
cerberus isolate apply
```

## Container auto-add

Containers labeled `cerberus.enable=true` are automatically added to the mesh.
Optional label `cerberus.public-key=<wireguard pubkey>`.

```bash
docker run -d --label cerberus.enable=true --label cerberus.public-key=<pub> nginx
```

## Features

- Auto peer discovery & registration
- WireGuard data plane (modern Noise protocol)
- HTTP/2 JSON control plane
- Docker container auto-add via labels
- Mesh IP allocation from CIDR
- Isolation: block/allow between containers, default-deny policies
- iptables-based enforcement
- One-liner installer + systemd service
- GitHub Actions build & push (binaries + Docker image)

## Architecture

```
+-----------+        HTTP/2        +-----------+
| cerberus  |<------------------>| cerberus  |
|  daemon   |   control plane     |  daemon   |
+-----+-----+                     +-----+-----+
      |                                 |
      | WireGuard (UDP)                 |
      +---------------------------------+
```

## License

MIT - apt235 / baba01hacker
