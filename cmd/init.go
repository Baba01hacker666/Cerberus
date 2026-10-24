package cmd

import (
	"fmt"
	"net"
	"strconv"

	"github.com/Baba01hacker666/cerberus/internal/tunnel"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize node: generate WireGuard keys and write config",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		regen, _ := cmd.Flags().GetBool("force-keys")
		genToken, _ := cmd.Flags().GetBool("gen-token")

		if c.PrivateKey == "" || regen {
			priv, pub, err := tunnel.GenerateKeyPair()
			if err != nil {
				return err
			}
			c.PrivateKey = priv
			c.PublicKey = pub
		} else if c.PublicKey == "" {
			pub, err := tunnel.PublicKeyFromPrivate(c.PrivateKey)
			if err != nil {
				return err
			}
			c.PublicKey = pub
		}

		if genToken {
			tok, err := tunnel.GenerateRandomToken(20)
			if err != nil {
				return err
			}
			c.AuthToken = tok
		}

		if c.Endpoint == "" {
			if ip := firstNonLoopbackIPv4(c.Interface); ip != "" {
				c.Endpoint = net.JoinHostPort(ip, strconv.Itoa(c.EffectiveUDPPort()))
			}
		}

		path := cfgPathOrDefault()
		if err := c.Save(path); err != nil {
			return err
		}
		fmt.Println("initialized config at:", path)
		fmt.Println("public key:           ", c.PublicKey)
		if c.AuthToken != "" {
			fmt.Println("auth token:           ", c.AuthToken)
		}
		return nil
	},
}

func firstNonLoopbackIPv4(excludeIface string) string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Name == excludeIface || (iface.Flags&net.FlagLoopback) != 0 || (iface.Flags&net.FlagUp) == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					return ip4.String()
				}
			}
		}
	}
	return ""
}

func init() {
	initCmd.Flags().Bool("force-keys", false, "regenerate WireGuard X25519 keypair")
	initCmd.Flags().Bool("gen-token", false, "generate and save a join auth token")
}
