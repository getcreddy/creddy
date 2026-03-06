package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// SigningKey represents an RSA signing key for OIDC tokens
type SigningKey struct {
	ID         string    // Key ID (kid)
	PrivateKey *rsa.PrivateKey
	CreatedAt  time.Time
	ExpiresAt  *time.Time // nil = no expiry
}

// KeyManager handles OIDC signing key lifecycle
type KeyManager struct {
	mu         sync.RWMutex
	keys       map[string]*SigningKey
	currentKey string // ID of the active signing key
}

// NewKeyManager creates a new key manager
func NewKeyManager() *KeyManager {
	return &KeyManager{
		keys: make(map[string]*SigningKey),
	}
}

// GenerateKey creates a new RSA-2048 signing key
func (km *KeyManager) GenerateKey() (*SigningKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	key := &SigningKey{
		ID:         uuid.New().String()[:8], // Short key ID
		PrivateKey: privateKey,
		CreatedAt:  time.Now(),
	}

	km.mu.Lock()
	km.keys[key.ID] = key
	km.currentKey = key.ID
	km.mu.Unlock()

	return key, nil
}

// CurrentKey returns the active signing key
func (km *KeyManager) CurrentKey() (*SigningKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.currentKey == "" {
		return nil, fmt.Errorf("no signing key available")
	}
	key, ok := km.keys[km.currentKey]
	if !ok {
		return nil, fmt.Errorf("current key not found")
	}
	return key, nil
}

// GetKey returns a key by ID (for verification)
func (km *KeyManager) GetKey(kid string) (*SigningKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	key, ok := km.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", kid)
	}
	return key, nil
}

// AllKeys returns all active keys (for JWKS)
func (km *KeyManager) AllKeys() []*SigningKey {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keys := make([]*SigningKey, 0, len(km.keys))
	for _, k := range km.keys {
		keys = append(keys, k)
	}
	return keys
}

// JWKS returns a JSON Web Key Set for all public keys
func (km *KeyManager) JWKS() jose.JSONWebKeySet {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var keys []jose.JSONWebKey
	for _, k := range km.keys {
		jwk := jose.JSONWebKey{
			Key:       &k.PrivateKey.PublicKey,
			KeyID:     k.ID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}
		keys = append(keys, jwk)
	}
	return jose.JSONWebKeySet{Keys: keys}
}

// ExportPrivateKeyPEM exports the current key as PEM (for persistence)
func (km *KeyManager) ExportPrivateKeyPEM() (string, string, error) {
	key, err := km.CurrentKey()
	if err != nil {
		return "", "", err
	}

	privBytes := x509.MarshalPKCS1PrivateKey(key.PrivateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	return key.ID, string(privPEM), nil
}

// ImportPrivateKeyPEM imports a key from PEM (for loading from storage)
func (km *KeyManager) ImportPrivateKeyPEM(kid string, pemData string, createdAt time.Time) error {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return fmt.Errorf("failed to decode PEM")
	}

	var privateKey *rsa.PrivateKey
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return fmt.Errorf("failed to parse PKCS8 key: %w", parseErr)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("key is not RSA")
		}
	default:
		return fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	key := &SigningKey{
		ID:         kid,
		PrivateKey: privateKey,
		CreatedAt:  createdAt,
	}

	km.mu.Lock()
	km.keys[kid] = key
	if km.currentKey == "" {
		km.currentKey = kid
	}
	km.mu.Unlock()

	return nil
}

// SetCurrentKey sets the active signing key
func (km *KeyManager) SetCurrentKey(kid string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if _, ok := km.keys[kid]; !ok {
		return fmt.Errorf("key not found: %s", kid)
	}
	km.currentKey = kid
	return nil
}

// RemoveKey removes a key (for rotation cleanup)
func (km *KeyManager) RemoveKey(kid string) error {
	if kid == km.currentKey {
		return fmt.Errorf("cannot remove current signing key")
	}
	delete(km.keys, kid)
	return nil
}

// HasKeys returns true if any keys are loaded
func (km *KeyManager) HasKeys() bool {
	return len(km.keys) > 0
}

// CurrentKeyID returns the current key ID
func (km *KeyManager) CurrentKeyID() string {
	return km.currentKey
}
