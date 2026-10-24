package cmd

import (
	"path/filepath"
	"testing"

	"github.com/Baba01hacker666/cerberus/internal/config"
)

func TestInitAndPeerCLIWorkflow(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	t.Setenv("CERBERUS_DATA_DIR", filepath.Join(dir, "data"))

	rootCmd.SetArgs([]string{"--config", cfgPath, "init", "--gen-token"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("cerberus init failed: %v", err)
	}

	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if c.PrivateKey == "" || c.PublicKey == "" || c.AuthToken == "" {
		t.Fatalf("expected generated keys + token, got %+v", c)
	}

	rootCmd.SetArgs([]string{"--config", cfgPath, "status"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("cerberus status failed: %v", err)
	}
}
