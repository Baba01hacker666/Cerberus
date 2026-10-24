package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/Baba01hacker666/cerberus/internal/node"
	"github.com/Baba01hacker666/cerberus/internal/tunnel"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run Cerberus as the main Smart Server (single port for auto keys, IPAM, mesh & tunnel)",
	RunE:  runServerCommand,
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run the Cerberus server daemon (alias for `cerberus server`)",
	RunE:  runServerCommand,
}

func bindServerFlags(cmd *cobra.Command) {
	cmd.Flags().IntP("port", "p", 0, "single port to open for both control HTTP/TCP and WireGuard UDP (default 7443)")
	cmd.Flags().String("listen", "", "control plane TCP listen address (overrides --port, e.g. 0.0.0.0:7443)")
	cmd.Flags().Int("udp-port", 0, "optional distinct WireGuard UDP port (defaults to same port as --port)")
	cmd.Flags().String("cidr", "", "mesh IPv4 subnet CIDR (default 10.77.0.0/16)")
	cmd.Flags().String("name", "", "server node name")
	cmd.Flags().String("iface", "", "OS TUN interface name (default cerberus0)")
	cmd.Flags().String("token", "", "require join secret token from clients")
	cmd.Flags().Bool("gen-token", false, "auto-generate a random join token if none set")
	cmd.Flags().Bool("default-deny", false, "enable zero-trust default-deny isolation between peers")
	cmd.Flags().Bool("userspace", false, "run WireGuard in userspace without creating OS /dev/net/tun device")
	cmd.Flags().Bool("tcp-only", false, "force single-port TCP transport (disable raw UDP)")
}

func runServerCommand(cmd *cobra.Command, _ []string) error {
	c := mustCfg()
	c.Role = "server"

	if port, _ := cmd.Flags().GetInt("port"); port > 0 {
		c.ListenAddr = fmt.Sprintf("0.0.0.0:%d", port)
		if udpPort, _ := cmd.Flags().GetInt("udp-port"); udpPort == 0 {
			c.UDPPort = port
		}
	}
	if listen, _ := cmd.Flags().GetString("listen"); listen != "" {
		c.ListenAddr = listen
	}
	if udpPort, _ := cmd.Flags().GetInt("udp-port"); udpPort > 0 {
		c.UDPPort = udpPort
	}
	if cidr, _ := cmd.Flags().GetString("cidr"); cidr != "" {
		c.MeshCIDR = cidr
	}
	if name, _ := cmd.Flags().GetString("name"); name != "" {
		c.NodeName = name
	}
	if iface, _ := cmd.Flags().GetString("iface"); iface != "" {
		c.Interface = iface
	}
	if tok, _ := cmd.Flags().GetString("token"); tok != "" {
		c.AuthToken = tok
	}
	if genTok, _ := cmd.Flags().GetBool("gen-token"); genTok && c.AuthToken == "" {
		tok, err := tunnel.GenerateRandomToken(16)
		if err != nil {
			return err
		}
		c.AuthToken = tok
	}
	if cmd.Flags().Changed("default-deny") {
		dd, _ := cmd.Flags().GetBool("default-deny")
		c.Isolation.Enabled = true
		c.Isolation.DefaultDeny = dd
	}
	if cmd.Flags().Changed("userspace") {
		us, _ := cmd.Flags().GetBool("userspace")
		c.UserspaceOnly = us
	}
	forceTCP, _ := cmd.Flags().GetBool("tcp-only")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfgPath := cfgPathOrDefault()
	srv, err := node.StartServer(ctx, node.ServerOptions{
		Config:     c,
		ConfigPath: cfgPath,
		ForceTCP:   forceTCP,
	})
	if err != nil {
		return err
	}
	defer srv.Stop()
	_ = c.Save(cfgPath)

	_, portStr, _ := net.SplitHostPort(srv.ListenAddr())
	displayHost := firstNonLoopbackIPv4(srv.Tunnel.InterfaceName())
	if displayHost == "" {
		displayHost = "<SERVER_IP>"
	}
	joinTarget := net.JoinHostPort(displayHost, portStr)
	if portStr == "" {
		joinTarget = displayHost + ":" + strconv.Itoa(srv.UDPPort())
	}

	tunMode := "userspace"
	if srv.Tunnel.HasOSInterface() {
		tunMode = fmt.Sprintf("kernel tun (%s)", srv.Tunnel.InterfaceName())
	}

	fmt.Println("Cerberus Smart Server running")
	fmt.Printf("  node:         %s\n", c.NodeName)
	fmt.Printf("  mesh gateway: %s (%s)\n", srv.MeshIP(), c.MeshCIDR)
	fmt.Printf("  control/tcp:  %s\n", srv.ListenAddr())
	fmt.Printf("  wireguard/udp:0.0.0.0:%d\n", srv.UDPPort())
	fmt.Printf("  tunnel mode:  %s\n", tunMode)
	fmt.Printf("  public key:   %s\n", c.PublicKey)
	if c.AuthToken != "" {
		fmt.Printf("\nJoin from any client (zero setup — auto keys + IP):\n")
		fmt.Printf("  cerberus client %s --token %s\n\n", joinTarget, c.AuthToken)
	} else {
		fmt.Printf("\nJoin from any client (zero setup — auto keys + IP):\n")
		fmt.Printf("  cerberus client %s\n\n", joinTarget)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigCh:
	case <-ctx.Done():
	}
	fmt.Println("shutting down cerberus server")
	return nil
}

func init() {
	bindServerFlags(serverCmd)
	bindServerFlags(daemonCmd)
}
