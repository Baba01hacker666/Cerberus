package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Baba01hacker666/cerberus/internal/control"
	"github.com/Baba01hacker666/cerberus/internal/mesh"
	"github.com/Baba01hacker666/cerberus/internal/tunnel"
	"github.com/spf13/cobra"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Join a cerberus mesh as a client node",
	RunE: func(cmd *cobra.Command, args []string) error {
		server, _ := cmd.Flags().GetString("server")
		if server == "" {
			return fmt.Errorf("--server required")
		}
		if !hasScheme(server) {
			server = "http://" + server
		}
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			hostname, _ := os.Hostname()
			name = hostname
		}
		listenPort, _ := cmd.Flags().GetInt("port")
		if listenPort == 0 {
			listenPort = 51820
		}

		// generate keys
		priv, pub, err := tunnel.GenerateKeyPair()
		if err != nil {
			return err
		}
		fmt.Println("public key:", pub)

		// endpoint
		endpoint, _ := cmd.Flags().GetString("endpoint")
		if endpoint == "" {
			addrs, _ := net.InterfaceAddrs()
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						endpoint = ipnet.IP.String() + fmt.Sprintf(":%d", listenPort)
						break
					}
				}
			}
		}

		client := control.NewClient(server)
		info, err := client.Info()
		if err != nil {
			return fmt.Errorf("contact server: %w", err)
		}
		fmt.Println("server:", info.NodeName, info.MeshCIDR)

		peer, err := client.Register(control.RegisterReq{
			Name:      name,
			PublicKey: pub,
			Endpoint:  endpoint,
		})
		if err != nil {
			return fmt.Errorf("register: %w", err)
		}
		fmt.Println("assigned mesh ip:", peer.MeshIP)

		meshIP := mesh.MeshIPWithPrefix(peer.MeshIP, info.MeshCIDR)

		tun := tunnel.New(tunnel.TunnelConfig{
			Name:       "cerberus0",
			PrivateKey: priv,
			PublicKey:  pub,
			MeshIP:     meshIP,
			ListenPort: listenPort,
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if tunnel.Available() {
			if err := tun.Start(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "tunnel start:", err)
			} else {
				fmt.Println("tunnel up on", meshIP)
			}
		} else {
			fmt.Println("tunnel device unavailable; running in control-only mode")
		}

		// keep alive: periodic re-register
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					_, _ = client.Register(control.RegisterReq{
						Name:      name,
						PublicKey: pub,
						Endpoint:  endpoint,
						MeshIP:    peer.MeshIP,
					})
				}
			}
		}()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-sigCh:
		case <-ctx.Done():
		}
		cancel()
		fmt.Println("shutting down client")
		return nil
	},
}

func hasScheme(s string) bool {
	return len(s) > 7 && (s[:7] == "http://" || s[:8] == "https://")
}

func init() {
	clientCmd.Flags().String("server", "", "cerberus server URL (host:port)")
	clientCmd.Flags().String("name", "", "client name")
	clientCmd.Flags().Int("port", 51820, "UDP listen port")
	clientCmd.Flags().String("endpoint", "", "public endpoint host:port")
	rootCmd.AddCommand(clientCmd)
}
