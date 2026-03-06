package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ensure strings is used (already imported for HasPrefix)
var _ = strings.HasPrefix

// mockTokenProvider implements TokenProvider for testing
type mockTokenProvider struct {
	agents map[string]*AgentInfo // clientID -> agent
}

func newMockTokenProvider() *mockTokenProvider {
	return &mockTokenProvider{
		agents: make(map[string]*AgentInfo),
	}
}

func (m *mockTokenProvider) AddAgent(clientID, clientSecret string, agent *AgentInfo) {
	// Use clientSecret as the key since that's what we validate
	m.agents[clientSecret] = agent
	// Also store by clientID for lookup
	m.agents["id:"+clientID] = agent
}

func (m *mockTokenProvider) ValidateClient(clientID, clientSecret string) (*AgentInfo, error) {
	agent, ok := m.agents[clientSecret]
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}
	// Verify clientID matches
	if agent.ID != clientID && agent.Name != clientID {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return agent, nil
}

func TestKeyManager(t *testing.T) {
	km := NewKeyManager()

	t.Run("generate key", func(t *testing.T) {
		key, err := km.GenerateKey()
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		if key.ID == "" {
			t.Error("key ID should not be empty")
		}
		if key.PrivateKey == nil {
			t.Error("private key should not be nil")
		}
	})

	t.Run("current key", func(t *testing.T) {
		key, err := km.CurrentKey()
		if err != nil {
			t.Fatalf("failed to get current key: %v", err)
		}
		if key == nil {
			t.Error("current key should not be nil")
		}
	})

	t.Run("JWKS", func(t *testing.T) {
		jwks := km.JWKS()
		if len(jwks.Keys) == 0 {
			t.Error("JWKS should have at least one key")
		}
		if jwks.Keys[0].Algorithm != "RS256" {
			t.Errorf("expected RS256, got %s", jwks.Keys[0].Algorithm)
		}
	})

	t.Run("export and import", func(t *testing.T) {
		kid, pem, err := km.ExportPrivateKeyPEM()
		if err != nil {
			t.Fatalf("failed to export key: %v", err)
		}

		km2 := NewKeyManager()
		err = km2.ImportPrivateKeyPEM(kid, pem, time.Now())
		if err != nil {
			t.Fatalf("failed to import key: %v", err)
		}

		key, err := km2.GetKey(kid)
		if err != nil {
			t.Fatalf("failed to get imported key: %v", err)
		}
		if key == nil {
			t.Error("imported key should not be nil")
		}
	})
}

func TestDiscoveryDocument(t *testing.T) {
	issuer := "https://creddy.example.com"
	doc := NewDiscoveryDocument(issuer)

	t.Run("required fields", func(t *testing.T) {
		if doc.Issuer != issuer {
			t.Errorf("expected issuer %s, got %s", issuer, doc.Issuer)
		}
		if doc.TokenEndpoint != issuer+"/oauth/token" {
			t.Errorf("unexpected token endpoint: %s", doc.TokenEndpoint)
		}
		if doc.JWKSURI != issuer+"/.well-known/jwks.json" {
			t.Errorf("unexpected JWKS URI: %s", doc.JWKSURI)
		}
	})

	t.Run("handler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
		w := httptest.NewRecorder()

		doc.Handler()(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		var resp DiscoveryDocument
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}
		if resp.Issuer != issuer {
			t.Errorf("expected issuer %s, got %s", issuer, resp.Issuer)
		}
	})
}

func TestTokenEndpoint(t *testing.T) {
	issuer := "https://creddy.example.com"
	km := NewKeyManager()
	km.GenerateKey()

	provider := newMockTokenProvider()
	provider.AddAgent("agent-1", "secret-123", &AgentInfo{
		ID:     "agent-1",
		Name:   "test-agent",
		Scopes: []string{"github:read", "aws:sts"},
	})

	te := NewTokenEndpoint(issuer, km, provider)

	t.Run("client_credentials grant", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", "agent-1")
		form.Set("client_secret", "secret-123")
		form.Set("scope", "openid github:read")

		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		te.Handler()(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp TokenResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("access token should not be empty")
		}
		if resp.IDToken == "" {
			t.Error("ID token should not be empty")
		}
		if resp.TokenType != "Bearer" {
			t.Errorf("expected Bearer, got %s", resp.TokenType)
		}
	})

	t.Run("invalid client", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", "agent-1")
		form.Set("client_secret", "wrong-secret")

		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		te.Handler()(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("unsupported grant type", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("client_id", "agent-1")
		form.Set("client_secret", "secret-123")

		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		te.Handler()(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})
}

func TestAgentClaims(t *testing.T) {
	issuer := "https://creddy.example.com"
	claims := NewAgentClaims(issuer, "agent-123", "my-agent", []string{"github"}, []string{issuer}, time.Hour)

	t.Run("standard claims", func(t *testing.T) {
		if claims.Issuer != issuer {
			t.Errorf("expected issuer %s, got %s", issuer, claims.Issuer)
		}
		if claims.Subject != "agent-123" {
			t.Errorf("expected subject agent-123, got %s", claims.Subject)
		}
	})

	t.Run("agent claims", func(t *testing.T) {
		if claims.AgentID != "agent-123" {
			t.Errorf("expected agent_id agent-123, got %s", claims.AgentID)
		}
		if claims.AgentName != "my-agent" {
			t.Errorf("expected agent_name my-agent, got %s", claims.AgentName)
		}
	})

	t.Run("with task context", func(t *testing.T) {
		claims.WithTask("task-456", "Running tests")
		if claims.TaskID != "task-456" {
			t.Errorf("expected task_id task-456, got %s", claims.TaskID)
		}
	})
}

func TestClientCredentials(t *testing.T) {
	t.Run("generate credentials", func(t *testing.T) {
		creds, err := GenerateClientCredentials()
		if err != nil {
			t.Fatalf("failed to generate credentials: %v", err)
		}

		if !strings.HasPrefix(creds.ClientID, "agent_") {
			t.Errorf("client_id should start with 'agent_', got %s", creds.ClientID)
		}
		if !strings.HasPrefix(creds.ClientSecret, "cks_") {
			t.Errorf("client_secret should start with 'cks_', got %s", creds.ClientSecret)
		}
		if creds.SecretHash == "" {
			t.Error("secret hash should not be empty")
		}
	})

	t.Run("validate secret", func(t *testing.T) {
		creds, _ := GenerateClientCredentials()

		if !ValidateClientSecret(creds.ClientSecret, creds.SecretHash) {
			t.Error("should validate correct secret")
		}
		if ValidateClientSecret("wrong_secret", creds.SecretHash) {
			t.Error("should reject incorrect secret")
		}
	})

	t.Run("hash consistency", func(t *testing.T) {
		secret := "cks_test123"
		hash1 := HashClientSecret(secret)
		hash2 := HashClientSecret(secret)

		if hash1 != hash2 {
			t.Error("hash should be consistent")
		}
	})
}

func TestProvider(t *testing.T) {
	provider := newMockTokenProvider()
	provider.AddAgent("agent-1", "secret-123", &AgentInfo{
		ID:     "agent-1",
		Name:   "test-agent",
		Scopes: []string{"github:read"},
	})

	p, err := NewProvider(Config{
		Issuer:        "https://creddy.example.com",
		DefaultTTL:    time.Hour,
		MaxTTL:        24 * time.Hour,
		TokenProvider: provider,
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	t.Run("routes registered", func(t *testing.T) {
		mux := http.NewServeMux()
		p.RegisterRoutes(mux)

		// Test discovery endpoint
		req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("discovery: expected 200, got %d", w.Code)
		}

		// Test JWKS endpoint
		req = httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("jwks: expected 200, got %d", w.Code)
		}
	})

	t.Run("key rotation", func(t *testing.T) {
		originalKID := p.KeyManager().CurrentKeyID()

		if err := p.RotateKey(); err != nil {
			t.Fatalf("failed to rotate key: %v", err)
		}

		newKID := p.KeyManager().CurrentKeyID()
		if newKID == originalKID {
			t.Error("key ID should change after rotation")
		}

		// Both keys should be in JWKS
		jwks := p.KeyManager().JWKS()
		if len(jwks.Keys) < 2 {
			t.Errorf("expected at least 2 keys in JWKS, got %d", len(jwks.Keys))
		}
	})
}
