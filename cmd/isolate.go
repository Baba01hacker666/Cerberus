package cmd

import (
	"fmt"

	"github.com/Baba01hacker666/cerberus/internal/config"
	"github.com/Baba01hacker666/cerberus/internal/isolation"
	"github.com/Baba01hacker666/cerberus/internal/store"
	"github.com/spf13/cobra"
)

var isolateCmd = &cobra.Command{
	Use:   "isolate",
	Short: "Manage isolation between peers",
}

var isolateBlockCmd = &cobra.Command{
	Use:   "block [src] [dst]",
	Short: "Block traffic between two mesh IPs",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		m := isolation.New("CERBERUS")
		if err := m.Block(args[0], args[1]); err != nil {
			return err
		}
		fmt.Println("blocked", args[0], "->", args[1])
		return nil
	},
}

var isolateAllowCmd = &cobra.Command{
	Use:   "allow [src] [dst]",
	Short: "Allow traffic between two mesh IPs",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		m := isolation.New("CERBERUS")
		if err := m.Allow(args[0], args[1]); err != nil {
			return err
		}
		fmt.Println("allowed", args[0], "->", args[1])
		return nil
	},
}

var isolateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show isolation status",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		fmt.Println("isolation enabled:", c.Isolation.Enabled)
		fmt.Println("default deny:", c.Isolation.DefaultDeny)
		fmt.Println("blocked peers:", c.Isolation.BlockedPeers)
		fmt.Println("allowed peers:", c.Isolation.AllowedPeers)
		fmt.Println("iptables available:", isolation.HasIptables())
		st := store.New(dataDir())
		fmt.Println("peers:", len(st.List()))
		return nil
	},
}

var isolateApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply isolation policy from config",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		st := store.New(dataDir())
		m := isolation.New("CERBERUS")
		ips := []string{}
		for _, p := range st.List() {
			if p.MeshIP != "" {
				ips = append(ips, p.MeshIP)
			}
		}
		blocked := map[string]bool{}
		for _, b := range c.Isolation.BlockedPeers {
			blocked[b] = true
		}
		allowed := map[string]map[string]bool{}
		for i, src := range ips {
			allowed[src] = map[string]bool{}
			for j, dst := range ips {
				if i == j {
					continue
				}
				ok := true
				for name := range blocked {
					if name == src || name == dst {
						ok = false
					}
				}
				if ok {
					allowed[src][dst] = true
				}
			}
		}
		if err := m.ApplyPolicy(ips, allowed, c.Isolation.DefaultDeny); err != nil {
			return err
		}
		fmt.Println("applied isolation policy")
		return nil
	},
}

func init() {
	isolateCmd.AddCommand(isolateBlockCmd, isolateAllowCmd, isolateStatusCmd, isolateApplyCmd)
	_ = config.DefaultConfigPath
}
