package mesh

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// Allocator hands out unique mesh IPv4 addresses from a CIDR safely across goroutines.
// It supports idempotent per-owner allocation so re-registering peers always retain their IP
// without leaking addresses under concurrent heartbeats or retries.
type Allocator struct {
	mu      sync.RWMutex
	cidr    string
	network *net.IPNet
	base    uint32 // network address (e.g. 10.77.0.0)
	bcast   uint32 // broadcast address (e.g. 10.77.255.255)
	server  uint32 // first usable host IP reserved for server (.1)
	cursor  uint32 // roving allocation pointer starting at .2
	used    map[uint32]string // ip -> owner key ("" if anonymous)
	byOwner map[string]uint32 // owner key -> ip
}

func NewAllocator(cidr string) (*Allocator, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid mesh cidr %q: %w", cidr, err)
	}
	ip4 := n.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("ipv4 cidr required, got %q", cidr)
	}
	mask := binary.BigEndian.Uint32(n.Mask)
	base := binary.BigEndian.Uint32(ip4) & mask
	bcast := base | ^mask
	if bcast-base < 3 {
		return nil, fmt.Errorf("mesh cidr %q too small (need at least /29 or /30 with usable hosts)", cidr)
	}
	server := base + 1
	start := base + 2
	return &Allocator{
		cidr:    n.String(),
		network: n,
		base:    base,
		bcast:   bcast,
		server:  server,
		cursor:  start,
		used:    map[uint32]string{server: "__server__"},
		byOwner: map[string]uint32{"__server__": server},
	}, nil
}

func uint32ToIPString(v uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func parseIPv4Uint32(s string) (uint32, bool) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip4), true
}

// ServerIP returns the primary gateway/server IP in the subnet (e.g. 10.77.0.1).
func (a *Allocator) ServerIP() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return uint32ToIPString(a.server)
}

// CIDR returns the normalized subnet CIDR string.
func (a *Allocator) CIDR() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cidr
}

// Contains reports whether ip belongs to the mesh subnet (including server IP).
func (a *Allocator) Contains(ipStr string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	u, ok := parseIPv4Uint32(ipStr)
	if !ok {
		return false
	}
	return u > a.base && u < a.bcast
}

func (a *Allocator) usableLocked(u uint32) bool {
	return u > a.base && u < a.bcast && u != a.server
}

// Reserve marks an existing peer's IP as used without allocating a fallback if invalid.
func (a *Allocator) Reserve(ipStr string) error {
	return a.ReserveForOwner("", ipStr)
}

// ReserveForOwner marks ipStr as owned by owner.
func (a *Allocator) ReserveForOwner(owner, ipStr string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, ok := parseIPv4Uint32(ipStr)
	if !ok || !a.usableLocked(u) {
		return fmt.Errorf("ip %q outside usable range of %s", ipStr, a.cidr)
	}
	if prevOwner, taken := a.used[u]; taken && (owner == "" || prevOwner != owner) {
		return fmt.Errorf("ip %s already allocated", ipStr)
	}
	if owner != "" {
		if oldIP, had := a.byOwner[owner]; had && oldIP != u {
			delete(a.used, oldIP)
		}
		a.byOwner[owner] = u
	}
	a.used[u] = owner
	return nil
}

// Allocate allocates preferred if available, or the next free IP in the subnet.
func (a *Allocator) Allocate(preferred string) (string, error) {
	return a.AllocateForOwner("", preferred)
}

// AllocateForOwner allocates an IP idempotently for owner:
//   - If owner already owns an IP (and preferred matches or is empty), returns that same IP.
//   - If preferred is valid & free (or owned by owner), assigns preferred.
//   - Otherwise scans around the ring (wrapping around after released IPs!) so freed IPs can be reused cleanly.
func (a *Allocator) AllocateForOwner(owner, preferred string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if owner != "" {
		if existing, ok := a.byOwner[owner]; ok {
			if preferred == "" {
				return uint32ToIPString(existing), nil
			}
			if prefU, pok := parseIPv4Uint32(preferred); pok && prefU == existing {
				return uint32ToIPString(existing), nil
			}
			// Owner explicitly requested a different valid free IP: migrate cleanly
			if prefU, pok := parseIPv4Uint32(preferred); pok && a.usableLocked(prefU) {
				if curOwner, taken := a.used[prefU]; !taken || curOwner == owner {
					delete(a.used, existing)
					a.used[prefU] = owner
					a.byOwner[owner] = prefU
					return uint32ToIPString(prefU), nil
				}
			}
			return uint32ToIPString(existing), nil
		}
	}

	if preferred != "" {
		if prefU, ok := parseIPv4Uint32(preferred); ok && a.usableLocked(prefU) {
			if _, taken := a.used[prefU]; !taken {
				a.used[prefU] = owner
				if owner != "" {
					a.byOwner[owner] = prefU
				}
				return uint32ToIPString(prefU), nil
			}
		}
	}

	firstHost := a.base + 2
	lastHost := a.bcast - 1
	totalHosts := uint64(lastHost-firstHost) + 1
	cur := a.cursor
	if cur < firstHost || cur > lastHost {
		cur = firstHost
	}

	for checked := uint64(0); checked < totalHosts; checked++ {
		if _, taken := a.used[cur]; !taken {
			a.used[cur] = owner
			if owner != "" {
				a.byOwner[owner] = cur
			}
			if cur == lastHost {
				a.cursor = firstHost
			} else {
				a.cursor = cur + 1
			}
			return uint32ToIPString(cur), nil
		}
		if cur == lastHost {
			cur = firstHost
		} else {
			cur++
		}
	}
	return "", fmt.Errorf("mesh subnet %s exhausted (%d hosts allocated)", a.cidr, len(a.used)-1)
}

// Release frees an IP address back to the pool.
func (a *Allocator) Release(ipStr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, ok := parseIPv4Uint32(ipStr)
	if !ok || u == a.server {
		return
	}
	if owner, exists := a.used[u]; exists {
		delete(a.used, u)
		if owner != "" {
			delete(a.byOwner, owner)
		}
	}
}

// ReleaseOwner frees any IP associated with owner.
func (a *Allocator) ReleaseOwner(owner string) {
	if owner == "" || owner == "__server__" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if u, ok := a.byOwner[owner]; ok {
		delete(a.byOwner, owner)
		delete(a.used, u)
	}
}

// AllocatedCount returns the number of client IPs currently allocated (excluding the server IP).
func (a *Allocator) AllocatedCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.used) <= 1 {
		return 0
	}
	return len(a.used) - 1
}

// MeshIPWithPrefix returns ip/prefix based on network mask (e.g. "10.77.0.2/16").
func MeshIPWithPrefix(ip string, cidr string) string {
	if ip == "" {
		return ""
	}
	if idx := len(ip); idx > 0 {
		for i := 0; i < len(ip); i++ {
			if ip[i] == '/' {
				return ip
			}
		}
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return ip + "/32"
	}
	ones, _ := n.Mask.Size()
	return fmt.Sprintf("%s/%d", ip, ones)
}
