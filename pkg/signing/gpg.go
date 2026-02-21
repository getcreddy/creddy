package signing

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// sanitizeForEmail removes or replaces characters that aren't valid in email local parts
func sanitizeForEmail(s string) string {
	// Replace spaces and special chars with hyphens
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")
	// Remove anything that's not alphanumeric or hyphen
	reg := regexp.MustCompile(`[^a-zA-Z0-9\-]`)
	s = reg.ReplaceAllString(s, "")
	// Convert to lowercase
	return strings.ToLower(s)
}

// KeyPair holds a GPG key pair for an agent
type KeyPair struct {
	PublicKey  string // ASCII armored
	PrivateKey string // ASCII armored
	KeyID      string // Short key ID
	Email      string
	Name       string
}

// GenerateKeyPair creates a new GPG key pair for an agent
func GenerateKeyPair(agentName, domain string) (*KeyPair, error) {
	// Sanitize agent name for email (replace invalid chars)
	sanitized := sanitizeForEmail(agentName)
	email := fmt.Sprintf("%s@%s", sanitized, domain)
	name := agentName // Keep original name for display

	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Create OpenPGP entity
	config := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		RSABits:                4096,
	}

	// Create entity without comment field to avoid character issues
	entity, err := openpgp.NewEntity(name, "", email, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create entity: %w", err)
	}

	// Export public key
	var pubBuf bytes.Buffer
	pubWriter, err := armor.Encode(&pubBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create armor encoder: %w", err)
	}
	if err := entity.Serialize(pubWriter); err != nil {
		return nil, fmt.Errorf("failed to serialize public key: %w", err)
	}
	pubWriter.Close()

	// Export private key (PKCS#8 PEM format for simplicity)
	privBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	keyID := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint[len(entity.PrimaryKey.Fingerprint)-8:])

	return &KeyPair{
		PublicKey:  pubBuf.String(),
		PrivateKey: string(privPEM),
		KeyID:      keyID,
		Email:      email,
		Name:       name,
	}, nil
}

// SignData signs data with the private key and returns an ASCII-armored signature
func SignData(privateKeyPEM string, data []byte) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode private key PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not RSA")
	}

	// Hash the data
	h := crypto.SHA256.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// Sign
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	// Armor the signature
	var sigBuf bytes.Buffer
	sigWriter, err := armor.Encode(&sigBuf, "SIGNATURE", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create armor encoder: %w", err)
	}
	sigWriter.Write(signature)
	sigWriter.Close()

	return sigBuf.String(), nil
}
