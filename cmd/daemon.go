package cmd

import (
	"context"
	"fmt"
	"net"
	"strings"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/baba01hacker/cerberus/internal/config"
	"github.com/baba01hacker/cerberus/internal/control"
	"github.com/baba01hacker/cerberus/internal/docker"
	"github.com/baba01hacker/cerberus/internal/isolation"
	"github.com/baba01hacker/cerberus/internal/mesh"
	"github.com/baba01hacker/cerberus/internal/store"
	"github.com/baba01hacker/cerberus/internal/wireguard"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run the cerberus daemon (control plane + mesh)",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := mustCfg()
		// ensure keys
		if c.PrivateKey == "" {
			priv, pub, err := wireguard.GenerateKeyPair()
			if err != nil {
				return err
			}
			c.PrivateKey = priv
			c.PublicKey = pub
			_ = c.Save(cfgFileOr(c))
		}
		st := store.New(c.DataDir)

		// isolation manager
		iso := isolation.New("CERBERUS")
		if c.Isolation.Enabled && isolation.HasIptables() {
			iso.EnsureChainNoErr()
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// docker auto-add loop
		if c.Docker.AutoAdd {
			go autoAddLoop(ctx, c, st)
		}

		// peer sync loop
		go syncLoop(ctx, c, st)

		// rebuild + apply loop
		go reconcileLoop(ctx, c, st, iso)

		// control server
		addr := c.ListenAddr
		fmt.Println("cerberus daemon listening on", addr)
		go func() {
			if err := control.Serve(c, st, addr); err != nil {
				fmt.Fprintln(os.Stderr, "control serve:", err)
				cancel()
			}
		}()

		// wait for signal
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-sigCh:
		case <-ctx.Done():
		}
		cancel()
		fmt.Println("shutting down")
		return nil
	},
}

func cfgFileOr(c *config.Config) string {
	if cfgFile != "" {
		return cfgFile
	}
	return config.DefaultConfigPath
}

// EnsureChainNoErr wrapper
func init() {
	// noop
}

func autoAddLoop(ctx context.Context, c *config.Config, st *store.Store) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			containers, err := docker.ListContainers(c.Docker.Socket, "")
			if err != nil {
				continue
			}
			changed := false
			for _, cont := range containers {
				// filter by label
				if !labelMatches(cont.Labels, c.Docker.LabelFilter) {
					continue
				}
				id := "ctr-" + docker.ShortID(cont.ID)
				if _, ok := st.Get(id); ok {
					continue
				}
				// allocate mesh ip
				alloc, _ := mesh.NewAllocator(c.MeshCIDR)
				// mark existing
				for _, p := range st.List() {
					if p.MeshIP != "" {
						_, _ = alloc.Allocate(p.MeshIP)
					}
				}
				ip, err := alloc.Allocate("")
				if err != nil {
					continue
				}
				peer := store.Peer{
					ID:         id,
					Name:       cont.Names,
					PublicKey:  cont.Labels["cerberus.public-key"],
					Endpoint:   "",
					MeshIP:     ip,
					AllowedIPs: []string{ip + "/32"},
					Container:  cont.ID,
					Labels:     cont.Labels,
					LastSeen:   docker.Now(),
				}
				_ = st.Add(peer)
				changed = true
			}
			if changed {
				_ = st.Save()
			}
		}
	}
}

func labelMatches(labels map[string]string, filter string) bool {
	if filter == "" {
		return true
	}
	// filter like key=value or key
	for _, f := range splitFilters(filter) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.Contains(f, "=") {
			parts := strings.SplitN(f, "=", 2)
			if labels[parts[0]] != parts[1] {
				return false
			}
		} else {
			if _, ok := labels[f]; !ok {
				return false
			}
		}
	}
	return true
}

func splitFilters(s string) []string {
	// support comma or space
	s = strings.ReplaceAll(s, " ", ",")
	return strings.Split(s, ",")
}

func syncLoop(ctx context.Context, c *config.Config, st *store.Store) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, p := range c.Peers {
				base := p
				if !strings.HasPrefix(base, "http") {
					base = "http://" + base
				}
				client := control.NewClient(base)
				peers, err := client.ListPeers()
				if err != nil {
					continue
				}
				changed := false
				for _, rp := range peers {
					if rp.ID == "" {
						continue
					}
					// avoid overwriting local
					if existing, ok := st.Get(rp.ID); ok {
						if existing.Container != "" {
							continue
						}
					}
					if err := st.Add(rp); err != nil {
						continue
					}
					changed = true
				}
				_ = changed
			}
			_ = st.Save()
		}
	}
}

func reconcileLoop(ctx context.Context, c *config.Config, st *store.Store, iso *isolation.Manager) {
	reconcile(c, st, iso)
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcile(c, st, iso)
		}
	}
}

func reconcile(c *config.Config, st *store.Store, iso *isolation.Manager) {
	peers := st.List()
	// build wireguard config
	var wgPeers []wireguard.PeerConfig
	for _, p := range peers {
		if p.PublicKey == "" {
			continue
		}
		wgPeers = append(wgPeers, wireguard.PeerConfig{
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
			AllowedIPs: p.AllowedIPs,
		})
	}
	cfg := wireguard.InterfaceConfig{
		Name:       c.Interface,
		PrivateKey: c.PrivateKey,
		Address:    mesh.MeshIPWithPrefix(firstIP(c), c.MeshCIDR),
		ListenPort: 51820,
		Peers:      wgPeers,
	}
	path := c.DataDir + "/wg.conf"
	_ = wireguard.WriteConfig(path, cfg)
	if wireguard.Available() {
		_ = wireguard.Apply(c.Interface, path)
	}

	// isolation
	if c.Isolation.Enabled && isolation.HasIptables() {
		ips := []string{}
		for _, p := range peers {
			if p.MeshIP != "" {
				ips = append(ips, p.MeshIP)
			}
		}
		allowed := map[string]map[string]bool{}
		if c.Isolation.AllowedPeers != nil {
			// allowed peer names -> mesh ip lookup
			nameToIP := map[string]string{}
			for _, p := range peers {
				nameToIP[p.Name] = p.MeshIP
				nameToIP[p.ID] = p.MeshIP
			}
			for _, src := range c.Isolation.AllowedPeers {
				_ = src
				// format src->dst? We'll support "src,dst"
			}
		}
		// blocked peers
		blocked := map[string]bool{}
		for _, b := range c.Isolation.BlockedPeers {
			blocked[b] = true
		}
		// build allowed matrix from blocked list: all pairs allowed except blocked
		for i, src := range ips {
			allowed[src] = map[string]bool{}
			for j, dst := range ips {
				if i == j {
					continue
				}
				ok := true
				// if src or dst in blocked list (by ip or name), block
				for name := range blocked {
					if name == src || name == dst {
						ok = false
					}
				}
				if ok {
					allowed[src][dst] = true
				}
			}
		}
		_ = iso.ApplyPolicy(ips, allowed, c.Isolation.DefaultDeny)
	}
}

func firstIP(c *config.Config) string {
	_, n, err := net.ParseCIDR(c.MeshCIDR)
	if err != nil {
		return "10.77.0.1"
	}
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	// +1
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
	return ip.String()
}
