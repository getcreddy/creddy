package oidc

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Provider is the main OIDC provider that coordinates all OIDC functionality
type Provider struct {
	issuer        string
	keyManager    *KeyManager
	keyStore      KeyStore
	discovery     *DiscoveryDocument
	tokenEndpoint *TokenEndpoint
	tokenProvider TokenProvider
}

// KeyStore defines the interface for persisting OIDC keys
type KeyStore interface {
	// CreateOIDCKey stores a new key
	CreateOIDCKey(keyID, privateKeyPEM string, isCurrent bool) error
	// ListOIDCKeys returns all stored keys
	ListOIDCKeys() ([]StoredKey, error)
	// GetCurrentOIDCKey returns the current signing key
	GetCurrentOIDCKey() (*StoredKey, error)
	// SetCurrentOIDCKey sets the current key
	SetCurrentOIDCKey(keyID string) error
	// DeleteOIDCKey removes a key
	DeleteOIDCKey(keyID string) error
}

// StoredKey represents a key from storage
type StoredKey struct {
	KeyID      string
	PrivateKey string // PEM
	IsCurrent  bool
	CreatedAt  time.Time
}

// Config holds the OIDC provider configuration
type Config struct {
	Issuer        string        // e.g., "https://creddy.example.com"
	DefaultTTL    time.Duration // Default token lifetime
	MaxTTL        time.Duration // Maximum token lifetime
	TokenProvider TokenProvider // Interface to validate clients and get agent info
	KeyStore      KeyStore      // Optional: persistent key storage
}

// NewProvider creates a new OIDC provider
func NewProvider(cfg Config) (*Provider, error) {
	km := NewKeyManager()

	// Try to load keys from storage
	if cfg.KeyStore != nil {
		keys, err := cfg.KeyStore.ListOIDCKeys()
		if err == nil && len(keys) > 0 {
			for _, k := range keys {
				if err := km.ImportPrivateKeyPEM(k.KeyID, k.PrivateKey, k.CreatedAt); err != nil {
					continue // Skip invalid keys
				}
				if k.IsCurrent {
					km.SetCurrentKey(k.KeyID)
				}
			}
		}
	}

	// Generate initial signing key if none loaded
	if !km.HasKeys() {
		key, err := km.GenerateKey()
		if err != nil {
			return nil, err
		}
		// Persist the new key
		if cfg.KeyStore != nil {
			_, pem, _ := km.ExportPrivateKeyPEM()
			cfg.KeyStore.CreateOIDCKey(key.ID, pem, true)
		}
	}

	discovery := NewDiscoveryDocument(cfg.Issuer)

	tokenEndpoint := NewTokenEndpoint(cfg.Issuer, km, cfg.TokenProvider)
	if cfg.DefaultTTL > 0 {
		tokenEndpoint = tokenEndpoint.WithTTL(cfg.DefaultTTL, cfg.MaxTTL)
	}

	return &Provider{
		issuer:        cfg.Issuer,
		keyManager:    km,
		keyStore:      cfg.KeyStore,
		discovery:     discovery,
		tokenEndpoint: tokenEndpoint,
		tokenProvider: cfg.TokenProvider,
	}, nil
}

// KeyManager returns the key manager for persistence/restoration
func (p *Provider) KeyManager() *KeyManager {
	return p.keyManager
}

// RegisterRoutes adds the OIDC routes to an HTTP mux
func (p *Provider) RegisterRoutes(mux *http.ServeMux) {
	// Discovery
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery.Handler())

	// JWKS
	mux.HandleFunc("GET /.well-known/jwks.json", p.keyManager.JWKSHandler())

	// Token endpoint
	mux.HandleFunc("POST /oauth/token", p.tokenEndpoint.Handler())

	// Userinfo endpoint (returns agent info)
	mux.HandleFunc("GET /oauth/userinfo", p.userinfoHandler())
}

// userinfoHandler returns agent information for a valid access token
func (p *Provider) userinfoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract bearer token
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="creddy"`)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")

		// Parse and validate the token
		token, err := jwt.ParseWithClaims(tokenStr, &AgentClaims{}, func(token *jwt.Token) (interface{}, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, jwt.ErrTokenMalformed
			}
			key, err := p.keyManager.GetKey(kid)
			if err != nil {
				return nil, err
			}
			return &key.PrivateKey.PublicKey, nil
		})

		if err != nil || !token.Valid {
			w.Header().Set("WWW-Authenticate", `Bearer realm="creddy", error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
			return
		}

		claims, ok := token.Claims.(*AgentClaims)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_claims"})
			return
		}

		// Return userinfo response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":        claims.Subject,
			"agent_id":   claims.AgentID,
			"agent_name": claims.AgentName,
			"scopes":     claims.Scopes,
			"client_id":  claims.ClientID,
		})
	}
}

// RotateKey generates a new signing key and sets it as current
func (p *Provider) RotateKey() error {
	key, err := p.keyManager.GenerateKey()
	if err != nil {
		return err
	}

	// Persist the new key
	if p.keyStore != nil {
		_, pem, _ := p.keyManager.ExportPrivateKeyPEM()
		if err := p.keyStore.CreateOIDCKey(key.ID, pem, true); err != nil {
			return err
		}
	}

	return nil
}

// Issuer returns the OIDC issuer URL
func (p *Provider) Issuer() string {
	return p.issuer
}
