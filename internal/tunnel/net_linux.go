//go:build linux

package tunnel

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

func osTunnelSupported() bool {
	if os.Geteuid() != 0 {
		// Check if process still has permissions to open /dev/net/tun (e.g. CAP_NET_ADMIN container)
		f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
		if err != nil {
			return false
		}
		_ = f.Close()
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return false
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return false
	}
	return true
}

func createAndConfigureOSTUN(name, meshIPPrefix string, mtu int) (tun.Device, string, error) {
	// Clean up stale residual TUN interface with same name if leftover from crashed process
	_ = exec.Command("ip", "link", "del", "dev", name).Run()

	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, "", fmt.Errorf("create linux tun %s: %w", name, err)
	}
	realName, err := dev.Name()
	if err != nil || realName == "" {
		realName = name
	}

	if out, err := exec.Command("ip", "link", "set", "dev", realName, "mtu", fmt.Sprintf("%d", mtu)).CombinedOutput(); err != nil {
		_ = dev.Close()
		return nil, "", fmt.Errorf("ip link set mtu on %s: %w: %s", realName, err, strings.TrimSpace(string(out)))
	}
	if meshIPPrefix != "" {
		_ = exec.Command("ip", "addr", "flush", "dev", realName).Run()
		if out, err := exec.Command("ip", "addr", "add", meshIPPrefix, "dev", realName).CombinedOutput(); err != nil {
			_ = dev.Close()
			return nil, "", fmt.Errorf("ip addr add %s dev %s: %w: %s", meshIPPrefix, realName, err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := exec.Command("ip", "link", "set", "dev", realName, "up").CombinedOutput(); err != nil {
		_ = dev.Close()
		return nil, "", fmt.Errorf("ip link set up %s: %w: %s", realName, err, strings.TrimSpace(string(out)))
	}
	return dev, realName, nil
}
