package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const (
	DefaultConfigPath = "/etc/cerberus/config.yaml"
	DefaultDataDir    = "/var/lib/cerberus"
	DefaultListenAddr = "0.0.0.0:7443"
	DefaultMeshCIDR   = "10.77.0.0/16"
)

type Config struct {
	NodeName     string            `mapstructure:"node_name" yaml:"node_name"`
	ListenAddr   string            `mapstructure:"listen_addr" yaml:"listen_addr"`
	DataDir      string            `mapstructure:"data_dir" yaml:"data_dir"`
	MeshCIDR     string            `mapstructure:"mesh_cidr" yaml:"mesh_cidr"`
	Interface    string            `mapstructure:"interface" yaml:"interface"`
	PrivateKey   string            `mapstructure:"private_key" yaml:"private_key"`
	PublicKey    string            `mapstructure:"public_key" yaml:"public_key"`
	Endpoint     string            `mapstructure:"endpoint" yaml:"endpoint"`
	Peers        []string          `mapstructure:"peers" yaml:"peers"`
	Labels       map[string]string `mapstructure:"labels" yaml:"labels"`
	Isolation    IsolationConfig   `mapstructure:"isolation" yaml:"isolation"`
	Docker       DockerConfig      `mapstructure:"docker" yaml:"docker"`
	TLS          TLSConfig         `mapstructure:"tls" yaml:"tls"`
}

type IsolationConfig struct {
	Enabled      bool     `mapstructure:"enabled" yaml:"enabled"`
	DefaultDeny  bool     `mapstructure:"default_deny" yaml:"default_deny"`
	AllowedPeers []string `mapstructure:"allowed_peers" yaml:"allowed_peers"`
	BlockedPeers []string `mapstructure:"blocked_peers" yaml:"blocked_peers"`
}

type DockerConfig struct {
	Socket       string `mapstructure:"socket" yaml:"socket"`
	AutoAdd      bool   `mapstructure:"auto_add" yaml:"auto_add"`
	LabelFilter  string `mapstructure:"label_filter" yaml:"label_filter"`
	Network      string `mapstructure:"network" yaml:"network"`
}

type TLSConfig struct {
	CertFile string `mapstructure:"cert_file" yaml:"cert_file"`
	KeyFile  string `mapstructure:"key_file" yaml:"key_file"`
	CAFile   string `mapstructure:"ca_file" yaml:"ca_file"`
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.AutomaticEnv()
	v.SetEnvPrefix("CERBERUS")

	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		// allow missing config; use defaults
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// if file simply doesn't exist, continue
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("read config: %w", err)
			}
		}
	}

	var c Config
	if err := v.Unmarshal(&c); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir
	}
	if c.ListenAddr == "" {
		c.ListenAddr = DefaultListenAddr
	}
	if c.MeshCIDR == "" {
		c.MeshCIDR = DefaultMeshCIDR
	}
	if c.Interface == "" {
		c.Interface = "cerberus0"
	}
	if c.Docker.Socket == "" {
		c.Docker.Socket = "/var/run/docker.sock"
	}
	if c.Docker.LabelFilter == "" {
		c.Docker.LabelFilter = "cerberus.enable=true"
	}
	if c.NodeName == "" {
		hostname, _ := os.Hostname()
		c.NodeName = hostname
	}
	_ = os.MkdirAll(c.DataDir, 0o755)
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	return &c, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("listen_addr", DefaultListenAddr)
	v.SetDefault("data_dir", DefaultDataDir)
	v.SetDefault("mesh_cidr", DefaultMeshCIDR)
	v.SetDefault("interface", "cerberus0")
	v.SetDefault("docker.socket", "/var/run/docker.sock")
	v.SetDefault("docker.auto_add", true)
	v.SetDefault("docker.label_filter", "cerberus.enable=true")
	v.SetDefault("isolation.enabled", true)
	v.SetDefault("isolation.default_deny", false)
}

func (c *Config) Save(path string) error {
	if path == "" {
		path = DefaultConfigPath
	}
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	// marshal via yaml through viper's write requires setting values
	v.Set("node_name", c.NodeName)
	v.Set("listen_addr", c.ListenAddr)
	v.Set("data_dir", c.DataDir)
	v.Set("mesh_cidr", c.MeshCIDR)
	v.Set("interface", c.Interface)
	v.Set("private_key", c.PrivateKey)
	v.Set("public_key", c.PublicKey)
	v.Set("endpoint", c.Endpoint)
	v.Set("peers", c.Peers)
	v.Set("labels", c.Labels)
	v.Set("isolation", c.Isolation)
	v.Set("docker", c.Docker)
	v.Set("tls", c.TLS)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return v.WriteConfigAs(path)
}
