package cmd

import (
	"fmt"
	"os"

	"github.com/baba01hacker/cerberus/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var cfg *config.Config

var rootCmd = &cobra.Command{
	Use:   "cerberus",
	Short: "Cerberus - WireGuard-like mesh networking for Docker containers",
	Long: `Cerberus builds an auto-peering, isolated mesh network between Docker
containers using a modern protocol (WireGuard data plane + HTTP/2 control plane).`,
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
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (default /etc/cerberus/config.yaml)")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(peerCmd)
	rootCmd.AddCommand(isolateCmd)
	rootCmd.AddCommand(statusCmd)
	_ = viper.New()
}

func dataDir() string {
	if cfg != nil {
		return cfg.DataDir
	}
	return config.DefaultDataDir
}

func mustCfg() *config.Config {
	if cfg == nil {
		c, _ := config.Load(cfgFile)
		cfg = c
	}
	return cfg
}

func printErr(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
}
