package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// ClientCredentials holds OIDC client credentials
type ClientCredentials struct {
	ClientID     string // e.g., "agent_abc123"
	ClientSecret string // Raw secret (only shown once)
	SecretHash   string // SHA256 hash for storage
}

// GenerateClientCredentials creates a new set of OIDC client credentials
func GenerateClientCredentials() (*ClientCredentials, error) {
	// Generate client_id: agent_ + 12 random hex chars
	idBytes := make([]byte, 6)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("failed to generate client_id: %w", err)
	}
	clientID := "agent_" + hex.EncodeToString(idBytes)

	// Generate client_secret: cks_ + 32 random hex chars
	secretBytes := make([]byte, 16)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("failed to generate client_secret: %w", err)
	}
	clientSecret := "cks_" + hex.EncodeToString(secretBytes)

	// Hash the secret for storage
	hash := sha256.Sum256([]byte(clientSecret))
	secretHash := hex.EncodeToString(hash[:])

	return &ClientCredentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		SecretHash:   secretHash,
	}, nil
}

// HashClientSecret hashes a client secret for comparison
func HashClientSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])
}

// ValidateClientSecret compares a secret against its hash using constant-time comparison
func ValidateClientSecret(secret, hash string) bool {
	computed := HashClientSecret(secret)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}
