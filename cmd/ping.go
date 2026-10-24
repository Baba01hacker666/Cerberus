package cmd

import (
	"fmt"
	"time"

	"github.com/Baba01hacker666/cerberus/internal/control"
	"github.com/spf13/cobra"
)

var pingCmd = &cobra.Command{
	Use:   "ping <mesh-ip-or-peer-name>",
	Short: "Send encrypted WireGuard ICMP mesh pings via the running Cerberus server/daemon",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		count, _ := cmd.Flags().GetInt("count")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		serverURL, _ := cmd.Flags().GetString("server")
		if serverURL == "" {
			serverURL = localServerURL(c)
		}
		if count <= 0 {
			count = 3
		}
		cl := control.NewClient(serverURL)
		cl.AuthToken = c.AuthToken
		cl.CAFile = c.TLS.CAFile

		target := args[0]
		sent := 0
		received := 0
		for seq := 1; seq <= count; seq++ {
			sent++
			rttMS, resolvedIP, err := cl.PingPeer(target, timeout)
			if err != nil {
				fmt.Printf("seq=%d target=%s error: %v\n", seq, target, err)
			} else {
				received++
				fmt.Printf("from %s: seq=%d time=%.2f ms\n", resolvedIP, seq, rttMS)
			}
			if seq < count {
				time.Sleep(250 * time.Millisecond)
			}
		}
		fmt.Printf("--- %s cerberus mesh ping statistics: %d transmitted, %d received ---\n", target, sent, received)
		if received == 0 {
			return fmt.Errorf("100%% packet loss to %s", target)
		}
		return nil
	},
}

func init() {
	pingCmd.Flags().IntP("count", "c", 3, "number of mesh pings to send")
	pingCmd.Flags().DurationP("timeout", "W", 3*time.Second, "per-packet timeout")
	pingCmd.Flags().StringP("server", "s", "", "Cerberus daemon control URL (defaults to local daemon)")
}
