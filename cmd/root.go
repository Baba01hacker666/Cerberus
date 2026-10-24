package cmd

import (
	"fmt"
	"os"

	"github.com/Baba01hacker666/cerberus/internal/config"
	"github.com/spf13/cobra"
)

var cfgFile string
var cfg *config.Config

var rootCmd = &cobra.Command{
	Use:   "cerberus",
	Short: "Cerberus - Smart WireGuard mesh & zero-setup VPN for servers and containers",
	Long: `Cerberus builds an encrypted, zero-setup WireGuard mesh network between
servers, VMs, workstations, and Docker containers over a single server port
(native UDP WireGuard with automatic single-port TCP fallback, auto IP/key
provisioning, and stateful container/peer firewall isolation).`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		c, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		cfg = c
		return nil
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (default /etc/cerberus/config.yaml or ~/.cerberus/config.yaml)")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(clientCmd)
	rootCmd.AddCommand(upCmd)
	rootCmd.AddCommand(pingCmd)
	rootCmd.AddCommand(peerCmd)
	rootCmd.AddCommand(isolateCmd)
	rootCmd.AddCommand(statusCmd)
}

func dataDir() string {
	if cfg != nil && cfg.DataDir != "" {
		return cfg.DataDir
	}
	_, d := config.ResolveDefaultPaths()
	return d
}

func cfgPathOrDefault() string {
	if cfgFile != "" {
		return cfgFile
	}
	p, _ := config.ResolveDefaultPaths()
	return p
}

func mustCfg() *config.Config {
	if cfg == nil {
		c, err := config.Load(cfgFile)
		if err != nil {
			c = config.DefaultServerConfig()
		}
		cfg = c
	}
	return cfg
}

func localServerURL(c *config.Config) string {
	scheme := "http"
	if c.TLS.CertFile != "" && c.TLS.KeyFile != "" {
		scheme = "https"
	}
	addr := c.ListenAddr
	if addr == "" {
		addr = config.DefaultListenAddr
	}
	if len(addr) > 0 && addr[0] == ':' {
		return fmt.Sprintf("%s://127.0.0.1%s", scheme, addr)
	}
	if len(addr) >= 7 && addr[:7] == "0.0.0.0" {
		return fmt.Sprintf("%s://127.0.0.1%s", scheme, addr[7:])
	}
	return fmt.Sprintf("%s://%s", scheme, addr)
}

func printErr(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
}
