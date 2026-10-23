package mesh

import (
	"fmt"
	"net"
	"sync"
)

// Allocator hands out IPs from a CIDR.
type Allocator struct {
	mu      sync.Mutex
	network *net.IPNet
	used    map[string]bool
	next    net.IP
}

func NewAllocator(cidr string) (*Allocator, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	a := &Allocator{network: n, used: map[string]bool{}, next: cloneIP(n.IP)}
	// skip network address and the node's own address (.1)
	a.next = inc(a.next)
	a.next = inc(a.next)
	return a, nil
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func inc(ip net.IP) net.IP {
	out := cloneIP(ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

func (a *Allocator) Allocate(preferred string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if preferred != "" {
		ip := net.ParseIP(preferred)
		if ip != nil && a.network.Contains(ip) && !a.used[ip.String()] {
			a.used[ip.String()] = true
			return ip.String(), nil
		}
	}
	for {
		if !a.network.Contains(a.next) {
			return "", fmt.Errorf("mesh subnet exhausted")
		}
		// skip broadcast
		if isBroadcast(a.next, a.network) {
			a.next = inc(a.next)
			continue
		}
		ipstr := a.next.String()
		if !a.used[ipstr] {
			a.used[ipstr] = true
			allocated := ipstr
			a.next = inc(a.next)
			return allocated, nil
		}
		a.next = inc(a.next)
	}
}

func (a *Allocator) Release(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.used, ip)
}

func isBroadcast(ip net.IP, n *net.IPNet) bool {
	ones, bits := n.Mask.Size()
	if ones == bits {
		return false
	}
	// broadcast = network | ^mask
	bcast := make(net.IP, len(ip))
	copy(bcast, n.IP)
	for i := 0; i < len(bcast); i++ {
		bcast[i] |= ^n.Mask[i]
	}
	return ip.Equal(bcast)
}

// MeshIPWithPrefix returns ip/cidr-prefix based on network mask.
func MeshIPWithPrefix(ip string, cidr string) string {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return ip + "/32"
	}
	ones, _ := n.Mask.Size()
	return fmt.Sprintf("%s/%d", ip, ones)
}
