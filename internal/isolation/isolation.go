package isolation

import (
	"fmt"
	"os/exec"
	"strings"
)

type Manager struct {
	Chain string
}

func New(chain string) *Manager {
	if chain == "" {
		chain = "CERBERUS"
	}
	return &Manager{Chain: chain}
}

func (m *Manager) ensureChain() error {
	// create chain if not exists
	cmd := exec.Command("iptables", "-N", m.Chain)
	_ = cmd.Run() // ignore exists
	// jump from FORWARD
	check := exec.Command("iptables", "-C", "FORWARD", "-j", m.Chain)
	if err := check.Run(); err != nil {
		c := exec.Command("iptables", "-I", "FORWARD", "-j", m.Chain)
		if err := c.Run(); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Flush() error {
	if err := m.ensureChain(); err != nil {
		return err
	}
	cmd := exec.Command("iptables", "-F", m.Chain)
	return cmd.Run()
}

func (m *Manager) Block(src, dst string) error {
	if err := m.ensureChain(); err != nil {
		return err
	}
	cmd := exec.Command("iptables", "-A", m.Chain, "-s", src, "-d", dst, "-j", "DROP")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables block: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *Manager) Allow(src, dst string) error {
	if err := m.ensureChain(); err != nil {
		return err
	}
	cmd := exec.Command("iptables", "-A", m.Chain, "-s", src, "-d", dst, "-j", "ACCEPT")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables allow: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *Manager) DefaultPolicy(deny bool) error {
	if err := m.ensureChain(); err != nil {
		return err
	}
	target := "ACCEPT"
	if deny {
		target = "DROP"
	}
	cmd := exec.Command("iptables", "-A", m.Chain, "-j", target)
	return cmd.Run()
}

// ApplyPolicy rebuilds the chain from an allow-list. allowed contains peer mesh IPs that
// may talk to each other; all other inter-mesh traffic is dropped when defaultDeny.
func (m *Manager) ApplyPolicy(peers []string, allowed map[string]map[string]bool, defaultDeny bool) error {
	if err := m.Flush(); err != nil {
		// chain may not exist; try create
		_ = m.ensureChain()
		_ = m.Flush()
	}
	for i, src := range peers {
		for j, dst := range peers {
			if i == j {
				continue
			}
			ok := true
			if defaultDeny {
				ok = false
				if allowed != nil && allowed[src] != nil && allowed[src][dst] {
					ok = true
				}
			}
			if ok {
				if err := m.Allow(src, dst); err != nil {
					return err
				}
			} else {
				if err := m.Block(src, dst); err != nil {
					return err
				}
			}
		}
	}
	if defaultDeny {
		_ = m.DefaultPolicy(true)
	} else {
		_ = m.DefaultPolicy(false)
	}
	return nil
}

func HasIptables() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

func (m *Manager) EnsureChainNoErr() {
	_ = m.ensureChain()
}
