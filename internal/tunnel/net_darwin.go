//go:build darwin

package tunnel

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

func osTunnelSupported() bool {
	if os.Geteuid() != 0 {
		return false
	}
	_, err := exec.LookPath("ifconfig")
	return err == nil
}

func createAndConfigureOSTUN(name, meshIPPrefix string, mtu int) (tun.Device, string, error) {
	utunName := name
	if !strings.HasPrefix(utunName, "utun") {
		utunName = "utun"
	}
	dev, err := tun.CreateTUN(utunName, mtu)
	if err != nil {
		return nil, "", fmt.Errorf("create darwin utun: %w", err)
	}
	realName, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, "", err
	}
	if meshIPPrefix != "" {
		ip, ipNet, err := net.ParseCIDR(meshIPPrefix)
		if err == nil {
			if out, err := exec.Command("ifconfig", realName, "inet", ip.String(), ip.String(), "mtu", fmt.Sprintf("%d", mtu), "up").CombinedOutput(); err != nil {
				_ = dev.Close()
				return nil, "", fmt.Errorf("ifconfig %s: %w: %s", realName, err, strings.TrimSpace(string(out)))
			}
			_ = exec.Command("route", "-q", "-n", "add", "-inet", ipNet.String(), "-interface", realName).Run()
		}
	}
	return dev, realName, nil
}
