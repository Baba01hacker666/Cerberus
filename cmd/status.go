package cmd

import (
	"fmt"

	"github.com/Baba01hacker666/cerberus/internal/control"
	"github.com/Baba01hacker666/cerberus/internal/isolation"
	"github.com/Baba01hacker666/cerberus/internal/store"
	"github.com/Baba01hacker666/cerberus/internal/tunnel"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show live Cerberus server/node status and WireGuard telemetry",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		cl := control.NewClient(localServerURL(c))
		cl.AuthToken = c.AuthToken
		cl.CAFile = c.TLS.CAFile
		if live, err := cl.Status(); err == nil {
			fmt.Println("status:            running (live)")
			fmt.Println("node:             ", live.Info.NodeName)
			fmt.Println("mesh gateway:     ", live.Info.MeshIP)
			fmt.Println("mesh cidr:        ", live.Info.MeshCIDR)
			fmt.Println("udp port:         ", live.Info.UDPPort)
			fmt.Println("public key:       ", live.Info.PublicKey)
			fmt.Println("os tun active:    ", live.OSInterfaceUp)
			fmt.Println("relayed packets:  ", live.RelayedPackets)
			fmt.Println("policy drops:     ", live.DroppedPolicy)
			fmt.Println("isolation enabled:", live.Isolation.Enabled, "(default_deny:", live.Isolation.DefaultDeny, ")")
			fmt.Println("peers:            ", len(live.Peers))

			statsByKey := map[string]tunnel.PeerRuntimeStats{}
			for _, ts := range live.TunnelStats {
				statsByKey[ts.PublicKey] = ts
			}
			for _, p := range live.Peers {
				ts := statsByKey[p.PublicKey]
				fmt.Printf("  - %-16s ip=%-15s ep=%-22s rx=%dB tx=%dB\n",
					p.ID, p.MeshIP, ts.Endpoint, ts.RxBytes, ts.TxBytes)
			}
			return nil
		}

		// Offline summary from config & store
		st := store.New(dataDir())
		fmt.Println("status:            offline")
		fmt.Println("node:             ", c.NodeName)
		fmt.Println("mesh cidr:        ", c.MeshCIDR)
		fmt.Println("interface:        ", c.Interface)
		fmt.Println("listen:           ", c.ListenAddr)
		fmt.Println("public key:       ", c.PublicKey)
		fmt.Println("peers (saved):    ", len(st.List()))
		fmt.Println("tunnel available: ", tunnel.Available())
		fmt.Println("iptables available:", isolation.HasIptables())
		return nil
	},
}
