package cmd

import (
	"fmt"

	"github.com/Baba01hacker666/cerberus/internal/control"
	"github.com/Baba01hacker666/cerberus/internal/isolation"
	"github.com/Baba01hacker666/cerberus/internal/store"
	"github.com/spf13/cobra"
)

var isolateCmd = &cobra.Command{
	Use:   "isolate",
	Short: "Manage zero-trust firewall isolation between peers & containers",
}

var isolateBlockCmd = &cobra.Command{
	Use:   "block [src] [dst]",
	Short: "Block traffic from src to dst (by mesh IP, peer ID, or peer name; omit dst to quarantine peer)",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		src := args[0]
		dst := ""
		if len(args) > 1 {
			dst = args[1]
		}
		// Apply live via running server control API if running!
		cl := control.NewClient(localServerURL(c))
		cl.AuthToken = c.AuthToken
		cl.CAFile = c.TLS.CAFile
		if _, err := cl.BlockPeers(src, dst); err == nil {
			if dst != "" {
				fmt.Println("blocked", src, "->", dst, "(live)")
			} else {
				fmt.Println("quarantined peer", src, "(live)")
			}
			return nil
		} else if control.IsHTTPError(err) {
			return err
		}
		// Offline fallback: persist to config and apply iptables if available
		rule := src
		if dst != "" {
			rule = src + "->" + dst
		}
		c.Isolation.Enabled = true
		c.Isolation.BlockedPeers = append(c.Isolation.BlockedPeers, rule)
		_ = c.Save(cfgPathOrDefault())
		if dst != "" && isolation.CanUseIptables() {
			m := isolation.New("CERBERUS")
			if err := m.Block(src, dst); err != nil {
				return err
			}
		}
		fmt.Println("blocked", rule)
		return nil
	},
}

var isolateAllowCmd = &cobra.Command{
	Use:   "allow [src] [dst]",
	Short: "Allow traffic from src to dst (by mesh IP, peer ID, or peer name)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		cl := control.NewClient(localServerURL(c))
		cl.AuthToken = c.AuthToken
		cl.CAFile = c.TLS.CAFile
		if _, err := cl.AllowPeers(args[0], args[1]); err == nil {
			fmt.Println("allowed", args[0], "->", args[1], "(live)")
			return nil
		} else if control.IsHTTPError(err) {
			return err
		}
		rule := args[0] + "->" + args[1]
		c.Isolation.AllowedPeers = append(c.Isolation.AllowedPeers, rule)
		_ = c.Save(cfgPathOrDefault())
		if isolation.CanUseIptables() {
			m := isolation.New("CERBERUS")
			if err := m.Allow(args[0], args[1]); err != nil {
				return err
			}
		}
		fmt.Println("allowed", args[0], "->", args[1])
		return nil
	},
}

var isolateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show isolation policy status",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		fmt.Println("isolation enabled:", c.Isolation.Enabled)
		fmt.Println("default deny:     ", c.Isolation.DefaultDeny)
		fmt.Println("blocked rules:    ", c.Isolation.BlockedPeers)
		fmt.Println("allowed rules:    ", c.Isolation.AllowedPeers)
		fmt.Println("iptables available:", isolation.HasIptables())
		st := store.New(dataDir())
		fmt.Println("peers:            ", len(st.List()))
		return nil
	},
}

var isolateApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply isolation policy from config",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		cl := control.NewClient(localServerURL(c))
		cl.AuthToken = c.AuthToken
		cl.CAFile = c.TLS.CAFile
		if _, err := cl.SetIsolationPolicy(c.Isolation.Enabled, c.Isolation.DefaultDeny); err == nil {
			fmt.Println("applied isolation policy (live)")
			return nil
		} else if control.IsHTTPError(err) {
			return err
		}

		st := store.New(dataDir())
		peers := st.List()
		nameToIP := map[string]string{}
		var ips, isolated []string
		for _, p := range peers {
			if p.MeshIP != "" {
				ips = append(ips, p.MeshIP)
				nameToIP[p.Name] = p.MeshIP
				nameToIP[p.ID] = p.MeshIP
				if p.Isolated {
					isolated = append(isolated, p.MeshIP)
				}
			}
		}
		pe := isolation.NewPolicyEngine()
		pe.Configure(
			c.Isolation.Enabled,
			c.Isolation.DefaultDeny,
			c.Isolation.AllowedPeers,
			c.Isolation.BlockedPeers,
			isolated,
			nameToIP,
		)
		m := isolation.New("CERBERUS")
		allowed, _, dd := pe.BuildAllowedMatrix(ips)
		if err := m.ApplyPolicy(ips, allowed, dd); err != nil {
			return err
		}
		fmt.Println("applied isolation policy")
		return nil
	},
}

func init() {
	isolateCmd.AddCommand(isolateBlockCmd, isolateAllowCmd, isolateStatusCmd, isolateApplyCmd)
}
