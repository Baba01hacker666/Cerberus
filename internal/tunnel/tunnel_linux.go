//go:build linux

package tunnel

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

const (
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
)

func (t *Tunnel) setupTUN() error {
	_ = exec.Command("ip", "tuntap", "add", "dev", t.cfg.Name, "mode", "tun").Run()
	if t.cfg.MeshIP != "" {
		_ = exec.Command("ip", "addr", "add", t.cfg.MeshIP, "dev", t.cfg.Name).Run()
	}
	_ = exec.Command("ip", "link", "set", "dev", t.cfg.Name, "up").Run()
	_ = exec.Command("ip", "link", "set", "dev", t.cfg.Name, "mtu", fmt.Sprintf("%d", MTU)).Run()

	f, err := openTUN(t.cfg.Name)
	if err != nil {
		return err
	}
	t.tun = f
	return nil
}

func openTUN(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(IFF_TUN | IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
