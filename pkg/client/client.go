package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Client represents a creddy client identity
type Client struct {
	ID         string
	Name       string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	ServerURL  string
}

// GenerateKeypair creates a new Ed25519 keypair
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Fingerprint returns the SHA256 fingerprint of a public key
func Fingerprint(pub ed25519.PublicKey) string {
	hash := sha256.Sum256(pub)
	return fmt.Sprintf("SHA256:%s", base64.RawStdEncoding.EncodeToString(hash[:12]))
}

// EncodePublicKey encodes a public key to base64
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodePublicKey decodes a base64 public key
func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: got %d, want %d", len(data), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(data), nil
}

// SavePrivateKey saves a private key to a file in PEM format
func SavePrivateKey(key ed25519.PrivateKey, path string) error {
	// Ensure directory exists with secure permissions
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	block := &pem.Block{
		Type:  "CREDDY PRIVATE KEY",
		Bytes: key,
	}

	data := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// LoadPrivateKey loads a private key from a PEM file
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CREDDY PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}

	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}

	return ed25519.PrivateKey(block.Bytes), nil
}

// ClientConfig represents the client configuration stored on disk
type ClientConfig struct {
	ServerURL string `yaml:"server_url"`
	ClientID  string `yaml:"client_id"`
	Name      string `yaml:"name"`
}

// CredentialsDir returns the path to the credentials directory
func CredentialsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".creddy"), nil
}

// Load loads the client from disk
func Load() (*Client, error) {
	dir, err := CredentialsDir()
	if err != nil {
		return nil, err
	}

	keyPath := filepath.Join(dir, "client.key")
	privateKey, err := LoadPrivateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	configPath := filepath.Join(dir, "config.yaml")
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// Simple YAML parsing (avoid adding yaml dependency just for this)
	var serverURL, clientID, name string
	for _, line := range splitLines(string(configData)) {
		if k, v := parseYAMLLine(line); k != "" {
			switch k {
			case "server_url":
				serverURL = v
			case "client_id":
				clientID = v
			case "name":
				name = v
			}
		}
	}

	return &Client{
		ID:         clientID,
		Name:       name,
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public().(ed25519.PublicKey),
		ServerURL:  serverURL,
	}, nil
}

// Save saves the client to disk
func (c *Client) Save() error {
	dir, err := CredentialsDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Save private key
	keyPath := filepath.Join(dir, "client.key")
	if err := SavePrivateKey(c.PrivateKey, keyPath); err != nil {
		return err
	}

	// Save config
	configPath := filepath.Join(dir, "config.yaml")
	config := fmt.Sprintf("server_url: %s\nclient_id: %s\nname: %s\n", c.ServerURL, c.ID, c.Name)
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func parseYAMLLine(line string) (key, value string) {
	for i := 0; i < len(line); i++ {
		if line[i] == ':' {
			key = trim(line[:i])
			if i+1 < len(line) {
				value = trim(line[i+1:])
			}
			return
		}
	}
	return "", ""
}

func trim(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '"') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '"') {
		end--
	}
	return s[start:end]
}
