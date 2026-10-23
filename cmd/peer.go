package cmd

import (
	"fmt"
	"strings"

	"github.com/Baba01hacker666/cerberus/internal/control"
	"github.com/Baba01hacker666/cerberus/internal/store"
	"github.com/spf13/cobra"
)

var peerCmd = &cobra.Command{
	Use:   "peer",
	Short: "Manage mesh peers",
}

var peerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List peers",
	RunE: func(cmd *cobra.Command, args []string) error {
		st := store.New(dataDir())
		for _, p := range st.List() {
			fmt.Printf("%-16s %-20s %-16s %s\n", p.ID, p.Name, p.MeshIP, p.PublicKey)
		}
		return nil
	},
}

var peerAddCmd = &cobra.Command{
	Use:   "add [remote-url]",
	Short: "Register this node with a remote peer or add a peer manually",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		st := store.New(dataDir())
		if len(args) > 0 && strings.HasPrefix(args[0], "http") {
			// register with remote
			client := control.NewClient(args[0])
			info, err := client.Info()
			if err != nil {
				return err
			}
			// send our info
			peer, err := client.Register(control.RegisterReq{
				Name:      c.NodeName,
				PublicKey: c.PublicKey,
				Endpoint:  c.Endpoint,
				Labels:    c.Labels,
			})
			if err != nil {
				return err
			}
			_ = st.Add(*peer)
			_ = st.Save()
			fmt.Println("registered with", info.NodeName, "-> mesh ip", peer.MeshIP)
			return nil
		}
		// manual add via flags
		pub, _ := cmd.Flags().GetString("pubkey")
		ep, _ := cmd.Flags().GetString("endpoint")
		ip, _ := cmd.Flags().GetString("ip")
		name, _ := cmd.Flags().GetString("name")
		if pub == "" {
			return fmt.Errorf("--pubkey required")
		}
		id := name
		if id == "" {
			id = pub[:8]
		}
		p := store.Peer{ID: id, Name: name, PublicKey: pub, Endpoint: ep, MeshIP: ip, AllowedIPs: []string{ip + "/32"}}
		if ip == "" {
			p.AllowedIPs = []string{}
		}
		if err := st.Add(p); err != nil {
			return err
		}
		_ = st.Save()
		fmt.Println("added peer", id)
		return nil
	},
}

var peerRemoveCmd = &cobra.Command{
	Use:   "remove [id]",
	Short: "Remove a peer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		st := store.New(dataDir())
		st.Remove(args[0])
		_ = st.Save()
		fmt.Println("removed", args[0])
		return nil
	},
}

func init() {
	peerCmd.AddCommand(peerListCmd, peerAddCmd, peerRemoveCmd)
	peerAddCmd.Flags().String("pubkey", "", "peer public key")
	peerAddCmd.Flags().String("endpoint", "", "peer endpoint host:port")
	peerAddCmd.Flags().String("ip", "", "peer mesh ip")
	peerAddCmd.Flags().String("name", "", "peer name")
}
