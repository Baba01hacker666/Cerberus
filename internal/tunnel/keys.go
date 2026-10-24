package tunnel

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeyPair generates a cryptographically secure X25519 WireGuard keypair
// encoded as standard 44-char base64 strings.
func GenerateKeyPair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", fmt.Errorf("crypto/rand read: %w", err)
	}
	// RFC 7748 X25519 scalar clamping
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("x25519 derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub), nil
}

// PublicKeyFromPrivate derives the base64 X25519 public key corresponding to privB64.
func PublicKeyFromPrivate(privB64 string) (string, error) {
	raw, err := decodeKey32(privB64)
	if err != nil {
		return "", err
	}
	pub, err := curve25519.X25519(raw[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// GeneratePresharedKey returns a cryptographically random 32-byte base64 WireGuard PSK.
func GeneratePresharedKey() (string, error) {
	var psk [32]byte
	if _, err := rand.Read(psk[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(psk[:]), nil
}

// GenerateRandomToken returns a URL-safe random hex token with byteLen bytes of entropy.
func GenerateRandomToken(byteLen int) (string, error) {
	if byteLen <= 0 {
		byteLen = 24
	}
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func decodeKey32(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		b, err := hex.DecodeString(s)
		if err == nil && len(b) == 32 {
			copy(out[:], b)
			return out, nil
		}
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("invalid key encoding: %w", err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("invalid key length %d (expected 32 bytes)", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// ValidatePublicKey verifies that k is a valid 32-byte key and normalizes it to standard base64.
func ValidatePublicKey(k string) (string, error) {
	raw, err := decodeKey32(k)
	if err != nil {
		return "", err
	}
	var zero [32]byte
	if raw == zero {
		return "", fmt.Errorf("all-zero public key is invalid")
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

// KeyToHex converts a base64 (or hex) 32-byte WireGuard key into 64-char lowercase hex for UAPI.
func KeyToHex(k string) (string, error) {
	raw, err := decodeKey32(k)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// HexToKey converts a 64-char hex WireGuard key back into standard base64 format.
func HexToKey(h string) (string, error) {
	raw, err := decodeKey32(h)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

// WireGuardConfParams holds fields to render a standard wg-quick / WireGuard app config file.
type WireGuardConfParams struct {
	PrivateKey      string
	Address         string
	MTU             int
	ServerPublicKey string
	PresharedKey    string
	ServerEndpoint  string
	AllowedIPs      string
	Keepalive       int
}

func RenderWireGuardConf(p WireGuardConfParams) string {
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", p.PrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", p.Address))
	if p.MTU > 0 {
		sb.WriteString(fmt.Sprintf("MTU = %d\n", p.MTU))
	}
	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", p.ServerPublicKey))
	if p.PresharedKey != "" {
		sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", p.PresharedKey))
	}
	if p.ServerEndpoint != "" {
		sb.WriteString(fmt.Sprintf("Endpoint = %s\n", p.ServerEndpoint))
	}
	allowed := p.AllowedIPs
	if allowed == "" {
		allowed = "10.77.0.0/16"
	}
	sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", allowed))
	ka := p.Keepalive
	if ka <= 0 {
		ka = 20
	}
	sb.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", ka))
	return sb.String()
}
