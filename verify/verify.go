// Package verify provides utilities for verifying Creddy agent identity tokens.
//
// Example usage:
//
//	verifier := verify.New("https://creddy.example.com")
//	claims, err := verifier.Verify(ctx, token)
//	if err != nil {
//	    log.Fatal("invalid token:", err)
//	}
//	fmt.Println("Agent:", claims.AgentName)
package verify

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// AgentClaims contains the verified claims from an agent token
type AgentClaims struct {
	// Standard OIDC claims
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	AuthTime  int64    `json:"auth_time,omitempty"`

	// Agent-specific claims
	AgentID         string   `json:"agent_id"`
	AgentName       string   `json:"agent_name"`
	Scopes          []string `json:"scopes,omitempty"`
	ClientID        string   `json:"client_id,omitempty"`
	TaskID          string   `json:"task_id,omitempty"`
	TaskDescription string   `json:"task_description,omitempty"`
	ParentAgentID   string   `json:"parent_agent_id,omitempty"`
}

// GetAudience implements jwt.ClaimsValidator
func (c AgentClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}

// GetExpirationTime implements jwt.ClaimsValidator
func (c AgentClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetIssuedAt implements jwt.ClaimsValidator
func (c AgentClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

// GetNotBefore implements jwt.ClaimsValidator
func (c AgentClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetIssuer implements jwt.ClaimsValidator
func (c AgentClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements jwt.ClaimsValidator
func (c AgentClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// HasScope checks if the token has a specific scope
func (c AgentClaims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// Verifier validates agent identity tokens
type Verifier struct {
	issuer     string
	httpClient *http.Client
	jwksURL    string

	// JWKS cache
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	lastFetch time.Time
	cacheTTL  time.Duration
}

// Option configures the Verifier
type Option func(*Verifier)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) Option {
	return func(v *Verifier) {
		v.httpClient = client
	}
}

// WithCacheTTL sets the JWKS cache TTL
func WithCacheTTL(ttl time.Duration) Option {
	return func(v *Verifier) {
		v.cacheTTL = ttl
	}
}

// New creates a new Verifier for the given issuer
func New(issuer string, opts ...Option) *Verifier {
	v := &Verifier{
		issuer:     issuer,
		jwksURL:    issuer + "/.well-known/jwks.json",
		httpClient: http.DefaultClient,
		keys:       make(map[string]*rsa.PublicKey),
		cacheTTL:   5 * time.Minute,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Verify validates a token and returns the claims
func (v *Verifier) Verify(ctx context.Context, tokenStr string) (*AgentClaims, error) {
	// Parse without verification first to get the kid
	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, &AgentClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid header")
	}

	// Get the public key
	key, err := v.getKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Parse and verify
	token, err = jwt.ParseWithClaims(tokenStr, &AgentClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(*AgentClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Verify issuer
	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", v.issuer, claims.Issuer)
	}

	return claims, nil
}

// getKey retrieves a public key by kid, fetching JWKS if needed
func (v *Verifier) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// Check cache
	v.mu.RLock()
	key, ok := v.keys[kid]
	needsFetch := !ok || time.Since(v.lastFetch) > v.cacheTTL
	v.mu.RUnlock()

	if ok && !needsFetch {
		return key, nil
	}

	// Fetch JWKS
	if err := v.fetchJWKS(ctx); err != nil {
		// If we have a cached key and fetch failed, use cached
		if ok {
			return key, nil
		}
		return nil, err
	}

	// Check again after fetch
	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("key not found: %s", kid)
	}

	return key, nil
}

// fetchJWKS retrieves the JWKS from the server
func (v *Verifier) fetchJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", v.jwksURL, nil)
	if err != nil {
		return err
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS request failed: %s", resp.Status)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	for _, key := range jwks.Keys {
		if rsaKey, ok := key.Key.(*rsa.PublicKey); ok {
			v.keys[key.KeyID] = rsaKey
		}
	}
	v.lastFetch = time.Now()

	return nil
}

// VerifyWithAudience verifies a token and checks the audience
func (v *Verifier) VerifyWithAudience(ctx context.Context, tokenStr string, audience string) (*AgentClaims, error) {
	claims, err := v.Verify(ctx, tokenStr)
	if err != nil {
		return nil, err
	}

	// Check audience
	found := false
	for _, aud := range claims.Audience {
		if aud == audience {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("invalid audience: %s not in %v", audience, claims.Audience)
	}

	return claims, nil
}
