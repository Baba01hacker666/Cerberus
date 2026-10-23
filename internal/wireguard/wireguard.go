package wireguard

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeyPair returns base64-encoded private and public keys (Curve25519).
func GenerateKeyPair() (priv, pub string, err error) {
	var private [32]byte
	// read from crypto/rand
	if err := readRandom(private[:]); err != nil {
		return "", "", err
	}
	// clamp
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	var public [32]byte
	curve25519.ScalarBaseMult(&public, &private)

	priv = base64.StdEncoding.EncodeToString(private[:])
	pub = base64.StdEncoding.EncodeToString(public[:])
	return priv, pub, nil
}

func readRandom(b []byte) error {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Read(b)
	return err
}

type PeerConfig struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
	Preshared  string
}

type InterfaceConfig struct {
	Name       string
	PrivateKey string
	Address    string // CIDR
	ListenPort int
	Peers      []PeerConfig
	PostUp     string
	PostDown   string
}

func RenderConfig(c InterfaceConfig) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + c.PrivateKey + "\n")
	if c.Address != "" {
		b.WriteString("Address = " + c.Address + "\n")
	}
	if c.ListenPort > 0 {
		b.WriteString(fmt.Sprintf("ListenPort = %d\n", c.ListenPort))
	}
	if c.PostUp != "" {
		b.WriteString("PostUp = " + c.PostUp + "\n")
	}
	if c.PostDown != "" {
		b.WriteString("PostDown = " + c.PostDown + "\n")
	}
	b.WriteString("\n")
	for _, p := range c.Peers {
		b.WriteString("[Peer]\n")
		b.WriteString("PublicKey = " + p.PublicKey + "\n")
		if p.Preshared != "" {
			b.WriteString("PresharedKey = " + p.Preshared + "\n")
		}
		if p.Endpoint != "" {
			b.WriteString("Endpoint = " + p.Endpoint + "\n")
		}
		if len(p.AllowedIPs) > 0 {
			b.WriteString("AllowedIPs = " + strings.Join(p.AllowedIPs, ", ") + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func WriteConfig(path string, c InterfaceConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(RenderConfig(c)), 0o600)
}

// Apply uses wg-quick if available to bring interface up.
func Apply(name, configPath string) error {
	bin, err := exec.LookPath("wg-quick")
	if err != nil {
		return fmt.Errorf("wg-quick not found: %w", err)
	}
	cmd := exec.Command(bin, "up", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func Down(name string) error {
	bin, err := exec.LookPath("wg-quick")
	if err != nil {
		return fmt.Errorf("wg-quick not found: %w", err)
	}
	cmd := exec.Command(bin, "down", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func Available() bool {
	_, err := exec.LookPath("wg-quick")
	return err == nil
}
