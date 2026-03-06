package oidc

import (
	"net/http"
	"time"
)

// Provider is the main OIDC provider that coordinates all OIDC functionality
type Provider struct {
	issuer        string
	keyManager    *KeyManager
	discovery     *DiscoveryDocument
	tokenEndpoint *TokenEndpoint
}

// Config holds the OIDC provider configuration
type Config struct {
	Issuer        string        // e.g., "https://creddy.example.com"
	DefaultTTL    time.Duration // Default token lifetime
	MaxTTL        time.Duration // Maximum token lifetime
	TokenProvider TokenProvider // Interface to validate clients and get agent info
}

// NewProvider creates a new OIDC provider
func NewProvider(cfg Config) (*Provider, error) {
	km := NewKeyManager()

	// Generate initial signing key
	if _, err := km.GenerateKey(); err != nil {
		return nil, err
	}

	discovery := NewDiscoveryDocument(cfg.Issuer)

	tokenEndpoint := NewTokenEndpoint(cfg.Issuer, km, cfg.TokenProvider)
	if cfg.DefaultTTL > 0 {
		tokenEndpoint = tokenEndpoint.WithTTL(cfg.DefaultTTL, cfg.MaxTTL)
	}

	return &Provider{
		issuer:        cfg.Issuer,
		keyManager:    km,
		discovery:     discovery,
		tokenEndpoint: tokenEndpoint,
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
		// TODO: Validate bearer token and return agent info
		// For now, return a placeholder
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"error": "not_implemented"}`))
	}
}

// RotateKey generates a new signing key and sets it as current
func (p *Provider) RotateKey() error {
	_, err := p.keyManager.GenerateKey()
	return err
}

// Issuer returns the OIDC issuer URL
func (p *Provider) Issuer() string {
	return p.issuer
}
