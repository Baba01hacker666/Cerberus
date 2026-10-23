package cmd

import (
	"fmt"
	"net"

	"github.com/Baba01hacker666/cerberus/internal/config"
	"github.com/Baba01hacker666/cerberus/internal/wireguard"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize node: generate keys and write config",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		if c.PrivateKey == "" {
			priv, pub, err := wireguard.GenerateKeyPair()
			if err != nil {
				return err
			}
			c.PrivateKey = priv
			c.PublicKey = pub
		}
		if c.Endpoint == "" {
			// best effort: first non-loopback ip
			addrs, _ := net.InterfaceAddrs()
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						c.Endpoint = ipnet.IP.String() + ":51820"
						break
					}
				}
			}
		}
		path := cfgFile
		if path == "" {
			path = config.DefaultConfigPath
		}
		if err := c.Save(path); err != nil {
			return err
		}
		fmt.Println("initialized config at", path)
		fmt.Println("public key:", c.PublicKey)
		return nil
	},
}
