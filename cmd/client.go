package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Baba01hacker666/cerberus/internal/node"
	"github.com/spf13/cobra"
)

var clientCmd = &cobra.Command{
	Use:   "client [server-host:port]",
	Short: "Connect to a Cerberus Smart Server with zero setup (auto keys, auto IP, auto UDP/TCP tunnel)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runClientCommand,
}

var upCmd = &cobra.Command{
	Use:   "up [server-host:port]",
	Short: "Join a Cerberus network (alias for `cerberus client`)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runClientCommand,
}

func bindClientFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("server", "s", "", "Cerberus server address (host:port or http://host:port)")
	cmd.Flags().String("name", "", "client node name (defaults to hostname)")
	cmd.Flags().String("iface", "cerberus0", "OS TUN interface name")
	cmd.Flags().IntP("port", "p", 0, "local WireGuard UDP listen port (0 = auto free port)")
	cmd.Flags().String("endpoint", "", "optional explicit public endpoint host:port")
	cmd.Flags().String("token", "", "optional server join token")
	cmd.Flags().String("state-dir", "", "directory to persist assigned keys & IP across restarts")
	cmd.Flags().Bool("ephemeral", false, "ephemeral node: do not persist state and deregister cleanly on exit")
	cmd.Flags().Bool("userspace", false, "run WireGuard in userspace without kernel /dev/net/tun")
	cmd.Flags().Bool("tcp-only", false, "force WireGuard-over-TCP single-port transport")
	cmd.Flags().String("write-wg-conf", "", "optional path to also write a standard wg-quick .conf file")
}

func runClientCommand(cmd *cobra.Command, args []string) error {
	c := mustCfg()
	serverAddr, _ := cmd.Flags().GetString("server")
	if serverAddr == "" && len(args) > 0 {
		serverAddr = args[0]
	}
	if serverAddr == "" {
		serverAddr = c.ServerURL
	}
	if serverAddr == "" {
		return fmt.Errorf("server address required: pass `cerberus client <host:port>` or `--server <host:port>`")
	}

	name, _ := cmd.Flags().GetString("name")
	iface, _ := cmd.Flags().GetString("iface")
	listenPort, _ := cmd.Flags().GetInt("port")
	endpoint, _ := cmd.Flags().GetString("endpoint")
	token, _ := cmd.Flags().GetString("token")
	if token == "" {
		token = c.AuthToken
	}
	stateDir, _ := cmd.Flags().GetString("state-dir")
	if stateDir == "" {
		stateDir = filepath.Join(dataDir(), "client")
	}
	ephemeral, _ := cmd.Flags().GetBool("ephemeral")
	userspace, _ := cmd.Flags().GetBool("userspace")
	forceTCP, _ := cmd.Flags().GetBool("tcp-only")
	wgConfOut, _ := cmd.Flags().GetString("write-wg-conf")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cl, err := node.StartClient(ctx, node.ClientOptions{
		ServerAddr:    serverAddr,
		Name:          name,
		Interface:     iface,
		ListenPort:    listenPort,
		Endpoint:      endpoint,
		Token:         token,
		StateDir:      stateDir,
		Ephemeral:     ephemeral,
		UserspaceOnly: userspace,
		ForceTCP:      forceTCP,
		CAFile:        c.TLS.CAFile,
	})
	if err != nil {
		return err
	}
	defer cl.Stop()

	if wgConfOut != "" && cl.JoinInfo.WireGuardConf != "" {
		if err := os.WriteFile(wgConfOut, []byte(cl.JoinInfo.WireGuardConf), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "warning: write wg conf %s: %v\n", wgConfOut, err)
		} else {
			fmt.Println("wrote WireGuard config:", wgConfOut)
		}
	}

	tunMode := "userspace"
	if cl.Tunnel.HasOSInterface() {
		tunMode = fmt.Sprintf("kernel tun (%s)", cl.Tunnel.InterfaceName())
	}

	fmt.Println("Connected to Cerberus mesh!")
	fmt.Printf("  server:      %s (%s, %s)\n", cl.JoinInfo.Server.NodeName, cl.ServerMeshIP(), cl.JoinInfo.Server.MeshCIDR)
	fmt.Printf("  peer id:     %s\n", cl.PeerID())
	fmt.Printf("  mesh ip:     %s\n", cl.MeshIP())
	fmt.Printf("  public key:  %s\n", cl.JoinInfo.Peer.PublicKey)
	fmt.Printf("  transport:   %s\n", cl.Transport)
	fmt.Printf("  interface:   %s\n", tunMode)
	fmt.Printf("  mesh peers:  %d\n", len(cl.Peers()))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigCh:
	case <-ctx.Done():
	}
	fmt.Println("shutting down client")
	return nil
}

func init() {
	bindClientFlags(clientCmd)
	bindClientFlags(upCmd)
}
