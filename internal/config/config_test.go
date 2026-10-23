package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConfigLoadSavePermissionsAndSinglePort(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	t.Setenv("CERBERUS_NODE_NAME", "hub-alpha")
	t.Setenv("CERBERUS_LISTEN_ADDR", "0.0.0.0:8443")

	c, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	c.DataDir = filepath.Join(dir, "data")
	c.PrivateKey = "test-priv"
	c.PublicKey = "test-pub"

	if got := c.EffectiveUDPPort(); got != 8443 {
		t.Fatalf("expected EffectiveUDPPort=8443 from single listen port, got %d", got)
	}
	c.UDPPort = 51820
	if got := c.EffectiveUDPPort(); got != 51820 {
		t.Fatalf("expected explicit UDPPort=51820, got %d", got)
	}

	if err := c.Save(cfgPath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected 0600 config permissions, got %04o", perm)
	}

	t.Setenv("CERBERUS_NODE_NAME", "")
	t.Setenv("CERBERUS_LISTEN_ADDR", "")
	reloaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if reloaded.NodeName != "hub-alpha" || reloaded.PrivateKey != "test-priv" {
		t.Fatalf("unexpected reloaded config: %+v", reloaded)
	}
}

func TestConfigConcurrentSaveAndIsolationAccess(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	c := DefaultServerConfig()
	c.DataDir = filepath.Join(dir, "data")

	var wg sync.WaitGroup
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c.SetIsolation(func(iso *IsolationConfig) {
				iso.Enabled = true
				iso.DefaultDeny = id%2 == 0
				iso.BlockedPeers = append(iso.BlockedPeers, fmt.Sprintf("10.77.0.%d", (id%50)+2))
			})
			_ = c.GetIsolation()
			_ = c.Clone()
			if err := c.Save(cfgPath); err != nil {
				t.Errorf("concurrent Save error: %v", err)
			}
		}(g)
	}
	wg.Wait()
}
