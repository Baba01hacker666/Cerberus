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
		c := mustCfg()
		cl := control.NewClient(localServerURL(c))
		cl.AuthToken = c.AuthToken
		var peers []store.Peer
		if live, err := cl.ListPeers(); err == nil {
			peers = live
		} else {
			peers = store.New(dataDir()).List()
		}
		for _, p := range peers {
			fmt.Printf("%-16s %-20s %-16s %s\n", p.ID, p.Name, p.MeshIP, p.PublicKey)
		}
		return nil
	},
}

var peerAddCmd = &cobra.Command{
	Use:   "add [remote-url]",
	Short: "Register this node with a remote server or add a peer manually",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		if len(args) > 0 {
			remote := args[0]
			if !strings.HasPrefix(remote, "http://") && !strings.HasPrefix(remote, "https://") {
				remote = "http://" + remote
			}
			cl := control.NewClient(remote)
			cl.AuthToken = c.AuthToken
			jr, err := cl.Join(control.RegisterReq{
				Name:      c.NodeName,
				PublicKey: c.PublicKey,
				Endpoint:  c.Endpoint,
				Labels:    c.Labels,
			})
			if err != nil {
				return err
			}
			st := store.New(dataDir())
			_ = st.Add(store.Peer{
				ID:         "srv-" + jr.Server.NodeName,
				Name:       jr.Server.NodeName,
				PublicKey:  jr.Server.PublicKey,
				Endpoint:   jr.Server.Endpoint,
				MeshIP:     jr.Server.MeshIP,
				AllowedIPs: []string{jr.Server.MeshCIDR},
			})
			_ = st.Save()
			fmt.Println("registered with", jr.Server.NodeName, "-> assigned mesh ip", jr.Peer.MeshIP)
			return nil
		}

		pub, _ := cmd.Flags().GetString("pubkey")
		ep, _ := cmd.Flags().GetString("endpoint")
		ip, _ := cmd.Flags().GetString("ip")
		name, _ := cmd.Flags().GetString("name")
		if pub == "" {
			return fmt.Errorf("--pubkey required when no remote URL is provided")
		}

		// Try live daemon first so WireGuard reconciles immediately!
		cl := control.NewClient(localServerURL(c))
		cl.AuthToken = c.AuthToken
		if created, err := cl.Register(control.RegisterReq{
			Name:      name,
			PublicKey: pub,
			Endpoint:  ep,
			MeshIP:    ip,
		}); err == nil {
			fmt.Println("added peer", created.ID, "->", created.MeshIP)
			return nil
		}

		st := store.New(dataDir())
		id := name
		if id == "" && len(pub) >= 8 {
			id = pub[:8]
		} else if id == "" {
			id = "peer"
		}
		var allowed []string
		if ip != "" {
			allowed = []string{ip + "/32"}
		}
		p := store.Peer{ID: id, Name: name, PublicKey: pub, Endpoint: ep, MeshIP: ip, AllowedIPs: allowed}
		if err := st.Add(p); err != nil {
			return err
		}
		if err := st.Save(); err != nil {
			return err
		}
		fmt.Println("added peer", id)
		return nil
	},
}

var peerRemoveCmd = &cobra.Command{
	Use:   "remove [id]",
	Short: "Remove a peer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		cl := control.NewClient(localServerURL(c))
		cl.AuthToken = c.AuthToken
		if err := cl.DeletePeer(args[0]); err == nil {
			fmt.Println("removed", args[0])
			return nil
		}
		st := store.New(dataDir())
		st.Remove(args[0])
		if err := st.Save(); err != nil {
			return err
		}
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
