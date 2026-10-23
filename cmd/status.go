package cmd

import (
	"fmt"

	"github.com/baba01hacker/cerberus/internal/isolation"
	"github.com/baba01hacker/cerberus/internal/store"
	"github.com/baba01hacker/cerberus/internal/wireguard"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon/node status",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		st := store.New(dataDir())
		fmt.Println("node:", c.NodeName)
		fmt.Println("mesh cidr:", c.MeshCIDR)
		fmt.Println("interface:", c.Interface)
		fmt.Println("listen:", c.ListenAddr)
		fmt.Println("public key:", c.PublicKey)
		fmt.Println("peers:", len(st.List()))
		fmt.Println("wireguard available:", wireguard.Available())
		fmt.Println("iptables available:", isolation.HasIptables())
		return nil
	},
}
