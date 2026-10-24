//go:build !linux && !darwin

package tunnel

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

func osTunnelSupported() bool {
	return false
}

func createAndConfigureOSTUN(name, meshIPPrefix string, mtu int) (tun.Device, string, error) {
	return nil, "", fmt.Errorf("os tun device not supported on this platform; using userspace mode")
}
