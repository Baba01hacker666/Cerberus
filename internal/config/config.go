package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath = "/etc/cerberus/config.yaml"
	DefaultDataDir    = "/var/lib/cerberus"
	DefaultListenAddr = "0.0.0.0:7443"
	DefaultPort       = 7443
	DefaultMeshCIDR   = "10.77.0.0/16"
	DefaultInterface  = "cerberus0"
	DefaultMTU        = 1420
	DefaultKeepalive  = 20
)

type Config struct {
	mu sync.RWMutex `yaml:"-"`

	Role          string            `mapstructure:"role" yaml:"role,omitempty"`
	NodeName      string            `mapstructure:"node_name" yaml:"node_name"`
	ListenAddr    string            `mapstructure:"listen_addr" yaml:"listen_addr"`
	UDPPort       int               `mapstructure:"udp_port" yaml:"udp_port,omitempty"`
	DataDir       string            `mapstructure:"data_dir" yaml:"data_dir"`
	MeshCIDR      string            `mapstructure:"mesh_cidr" yaml:"mesh_cidr"`
	MeshIP        string            `mapstructure:"mesh_ip" yaml:"mesh_ip,omitempty"`
	Interface     string            `mapstructure:"interface" yaml:"interface"`
	MTU           int               `mapstructure:"mtu" yaml:"mtu,omitempty"`
	Keepalive     int               `mapstructure:"keepalive" yaml:"keepalive,omitempty"`
	PrivateKey    string            `mapstructure:"private_key" yaml:"private_key,omitempty"`
	PublicKey     string            `mapstructure:"public_key" yaml:"public_key,omitempty"`
	PresharedKey  string            `mapstructure:"preshared_key" yaml:"preshared_key,omitempty"`
	AuthToken     string            `mapstructure:"auth_token" yaml:"auth_token,omitempty"`
	Endpoint      string            `mapstructure:"endpoint" yaml:"endpoint,omitempty"`
	ServerURL     string            `mapstructure:"server_url" yaml:"server_url,omitempty"`
	PeerID        string            `mapstructure:"peer_id" yaml:"peer_id,omitempty"`
	PeerSecret    string            `mapstructure:"peer_secret" yaml:"peer_secret,omitempty"`
	UserspaceOnly bool              `mapstructure:"userspace_only" yaml:"userspace_only,omitempty"`
	Peers         []string          `mapstructure:"peers" yaml:"peers,omitempty"`
	Labels        map[string]string `mapstructure:"labels" yaml:"labels,omitempty"`
	Isolation     IsolationConfig   `mapstructure:"isolation" yaml:"isolation"`
	Docker        DockerConfig      `mapstructure:"docker" yaml:"docker"`
	TLS           TLSConfig         `mapstructure:"tls" yaml:"tls"`
}

type IsolationConfig struct {
	Enabled      bool     `mapstructure:"enabled" yaml:"enabled"`
	DefaultDeny  bool     `mapstructure:"default_deny" yaml:"default_deny"`
	AllowedPeers []string `mapstructure:"allowed_peers" yaml:"allowed_peers,omitempty"`
	BlockedPeers []string `mapstructure:"blocked_peers" yaml:"blocked_peers,omitempty"`
}

type DockerConfig struct {
	Socket      string `mapstructure:"socket" yaml:"socket"`
	AutoAdd     bool   `mapstructure:"auto_add" yaml:"auto_add"`
	LabelFilter string `mapstructure:"label_filter" yaml:"label_filter"`
	Network     string `mapstructure:"network" yaml:"network,omitempty"`
}

type TLSConfig struct {
	CertFile string `mapstructure:"cert_file" yaml:"cert_file,omitempty"`
	KeyFile  string `mapstructure:"key_file" yaml:"key_file,omitempty"`
	CAFile   string `mapstructure:"ca_file" yaml:"ca_file,omitempty"`
}

// ResolveDefaultPaths picks system paths (/etc/cerberus, /var/lib/cerberus) when writable
// (e.g. running as root) and gracefully falls back to ~/.cerberus when unprivileged.
func ResolveDefaultPaths() (cfgPath, dataDir string) {
	if os.Geteuid() == 0 {
		return DefaultConfigPath, DefaultDataDir
	}
	// Check if /var/lib/cerberus is already writable
	if info, err := os.Stat(DefaultDataDir); err == nil && info.IsDir() {
		testFile := filepath.Join(DefaultDataDir, ".write-check")
		if f, err := os.OpenFile(testFile, os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			_ = f.Close()
			_ = os.Remove(testFile)
			return DefaultConfigPath, DefaultDataDir
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		base := filepath.Join(os.TempDir(), "cerberus")
		return filepath.Join(base, "config.yaml"), filepath.Join(base, "data")
	}
	base := filepath.Join(home, ".cerberus")
	return filepath.Join(base, "config.yaml"), filepath.Join(base, "data")
}

func DefaultServerConfig() *Config {
	_, defaultData := ResolveDefaultPaths()
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "cerberus-server"
	}
	return &Config{
		Role:       "server",
		NodeName:   hostname,
		ListenAddr: DefaultListenAddr,
		DataDir:    defaultData,
		MeshCIDR:   DefaultMeshCIDR,
		Interface:  DefaultInterface,
		MTU:        DefaultMTU,
		Keepalive:  DefaultKeepalive,
		Isolation: IsolationConfig{
			Enabled:     true,
			DefaultDeny: false,
		},
		Docker: DockerConfig{
			Socket:      "/var/run/docker.sock",
			AutoAdd:     true,
			LabelFilter: "cerberus.enable=true",
		},
	}
}

func Load(path string) (*Config, error) {
	defaultCfgPath, defaultDataDir := ResolveDefaultPaths()
	if path == "" {
		path = defaultCfgPath
	}

	c := DefaultServerConfig()
	c.DataDir = defaultDataDir

	if b, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	applyEnvOverrides(c)
	c.applyDefaults(defaultDataDir)

	_ = os.MkdirAll(c.DataDir, 0o700)
	return c, nil
}

func applyEnvOverrides(c *Config) {
	if v := os.Getenv("CERBERUS_NODE_NAME"); v != "" {
		c.NodeName = v
	}
	if v := os.Getenv("CERBERUS_LISTEN_ADDR"); v != "" {
		c.ListenAddr = v
	}
	if v := os.Getenv("CERBERUS_UDP_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			c.UDPPort = p
		}
	}
	if v := os.Getenv("CERBERUS_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("CERBERUS_MESH_CIDR"); v != "" {
		c.MeshCIDR = v
	}
	if v := os.Getenv("CERBERUS_INTERFACE"); v != "" {
		c.Interface = v
	}
	if v := os.Getenv("CERBERUS_AUTH_TOKEN"); v != "" {
		c.AuthToken = v
	}
	if v := os.Getenv("CERBERUS_ENDPOINT"); v != "" {
		c.Endpoint = v
	}
	if v := os.Getenv("CERBERUS_SERVER_URL"); v != "" {
		c.ServerURL = v
	}
	if v := os.Getenv("CERBERUS_USERSPACE_ONLY"); v != "" {
		c.UserspaceOnly = v == "1" || strings.EqualFold(v, "true")
	}
}

func (c *Config) applyDefaults(defaultDataDir string) {
	if c.DataDir == "" {
		c.DataDir = defaultDataDir
	}
	if c.ListenAddr == "" {
		c.ListenAddr = DefaultListenAddr
	}
	if c.MeshCIDR == "" {
		c.MeshCIDR = DefaultMeshCIDR
	}
	if c.Interface == "" {
		c.Interface = DefaultInterface
	}
	if c.MTU <= 0 {
		c.MTU = DefaultMTU
	}
	if c.Keepalive <= 0 {
		c.Keepalive = DefaultKeepalive
	}
	if c.Docker.Socket == "" {
		c.Docker.Socket = "/var/run/docker.sock"
	}
	if c.Docker.LabelFilter == "" {
		c.Docker.LabelFilter = "cerberus.enable=true"
	}
	if c.NodeName == "" {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "cerberus-node"
		}
		c.NodeName = hostname
	}
}

// EffectiveUDPPort returns UDPPort if explicitly configured (>0), otherwise
// extracts the port number from ListenAddr so a single open port serves both
// HTTP/TCP control+relay and WireGuard UDP traffic out of the box.
func (c *Config) EffectiveUDPPort() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.UDPPort > 0 {
		return c.UDPPort
	}
	_, portStr, err := net.SplitHostPort(c.ListenAddr)
	if err == nil {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			return p
		}
	}
	return DefaultPort
}

// Save writes the configuration atomically with 0600 permissions so private keys
// and tokens are never world-readable or torn by concurrent writes.
func (c *Config) Save(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if path == "" {
		defaultCfgPath, _ := ResolveDefaultPaths()
		path = defaultCfgPath
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir config dir %s: %w", dir, err)
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// Clone returns a deep copy of Config safe for reading without holding locks.
func (c *Config) Clone() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cp := &Config{
		Role:          c.Role,
		NodeName:      c.NodeName,
		ListenAddr:    c.ListenAddr,
		UDPPort:       c.UDPPort,
		DataDir:       c.DataDir,
		MeshCIDR:      c.MeshCIDR,
		MeshIP:        c.MeshIP,
		Interface:     c.Interface,
		MTU:           c.MTU,
		Keepalive:     c.Keepalive,
		PrivateKey:    c.PrivateKey,
		PublicKey:     c.PublicKey,
		PresharedKey:  c.PresharedKey,
		AuthToken:     c.AuthToken,
		Endpoint:      c.Endpoint,
		ServerURL:     c.ServerURL,
		PeerID:        c.PeerID,
		PeerSecret:    c.PeerSecret,
		UserspaceOnly: c.UserspaceOnly,
		Docker:        c.Docker,
		TLS:           c.TLS,
		Isolation: IsolationConfig{
			Enabled:     c.Isolation.Enabled,
			DefaultDeny: c.Isolation.DefaultDeny,
		},
	}
	if c.Peers != nil {
		cp.Peers = append([]string(nil), c.Peers...)
	}
	if c.Isolation.AllowedPeers != nil {
		cp.Isolation.AllowedPeers = append([]string(nil), c.Isolation.AllowedPeers...)
	}
	if c.Isolation.BlockedPeers != nil {
		cp.Isolation.BlockedPeers = append([]string(nil), c.Isolation.BlockedPeers...)
	}
	if c.Labels != nil {
		cp.Labels = make(map[string]string, len(c.Labels))
		for k, v := range c.Labels {
			cp.Labels[k] = v
		}
	}
	return cp
}

// SetIsolation updates isolation config atomically.
func (c *Config) SetIsolation(fn func(*IsolationConfig)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(&c.Isolation)
}

// GetIsolation returns a deep copy of IsolationConfig safely.
func (c *Config) GetIsolation() IsolationConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	iso := IsolationConfig{
		Enabled:     c.Isolation.Enabled,
		DefaultDeny: c.Isolation.DefaultDeny,
	}
	if c.Isolation.AllowedPeers != nil {
		iso.AllowedPeers = append([]string(nil), c.Isolation.AllowedPeers...)
	}
	if c.Isolation.BlockedPeers != nil {
		iso.BlockedPeers = append([]string(nil), c.Isolation.BlockedPeers...)
	}
	return iso
}
