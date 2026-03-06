package verify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

func TestVerifier(t *testing.T) {
	// Generate test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	keyID := "test-key-1"

	// Create JWKS server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			jwks := jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:       &privateKey.PublicKey,
						KeyID:     keyID,
						Algorithm: "RS256",
						Use:       "sig",
					},
				},
			}
			json.NewEncoder(w).Encode(jwks)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	issuer := server.URL
	verifier := New(issuer)

	t.Run("valid token", func(t *testing.T) {
		claims := &AgentClaims{
			Issuer:    issuer,
			Subject:   "agent-123",
			Audience:  []string{issuer},
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			AgentID:   "agent-123",
			AgentName: "test-agent",
			Scopes:    []string{"github:read"},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = keyID

		tokenStr, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		verified, err := verifier.Verify(context.Background(), tokenStr)
		if err != nil {
			t.Fatalf("failed to verify token: %v", err)
		}

		if verified.AgentID != "agent-123" {
			t.Errorf("expected agent_id agent-123, got %s", verified.AgentID)
		}
		if verified.AgentName != "test-agent" {
			t.Errorf("expected agent_name test-agent, got %s", verified.AgentName)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		claims := &AgentClaims{
			Issuer:    issuer,
			Subject:   "agent-123",
			ExpiresAt: time.Now().Add(-time.Hour).Unix(), // Expired
			IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
			AgentID:   "agent-123",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = keyID

		tokenStr, _ := token.SignedString(privateKey)

		_, err := verifier.Verify(context.Background(), tokenStr)
		if err == nil {
			t.Error("should reject expired token")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		claims := &AgentClaims{
			Issuer:    "https://wrong-issuer.com",
			Subject:   "agent-123",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			AgentID:   "agent-123",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = keyID

		tokenStr, _ := token.SignedString(privateKey)

		_, err := verifier.Verify(context.Background(), tokenStr)
		if err == nil {
			t.Error("should reject wrong issuer")
		}
	})

	t.Run("unknown key", func(t *testing.T) {
		// Generate a different key
		otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)

		claims := &AgentClaims{
			Issuer:    issuer,
			Subject:   "agent-123",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			AgentID:   "agent-123",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "unknown-key"

		tokenStr, _ := token.SignedString(otherKey)

		_, err := verifier.Verify(context.Background(), tokenStr)
		if err == nil {
			t.Error("should reject unknown key")
		}
	})

	t.Run("verify with audience", func(t *testing.T) {
		claims := &AgentClaims{
			Issuer:    issuer,
			Subject:   "agent-123",
			Audience:  []string{issuer, "https://api.example.com"},
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			AgentID:   "agent-123",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = keyID

		tokenStr, _ := token.SignedString(privateKey)

		// Valid audience
		_, err := verifier.VerifyWithAudience(context.Background(), tokenStr, "https://api.example.com")
		if err != nil {
			t.Errorf("should accept valid audience: %v", err)
		}

		// Invalid audience
		_, err = verifier.VerifyWithAudience(context.Background(), tokenStr, "https://wrong.com")
		if err == nil {
			t.Error("should reject invalid audience")
		}
	})
}

func TestAgentClaimsHasScope(t *testing.T) {
	claims := &AgentClaims{
		Scopes: []string{"github:read", "aws:s3:read"},
	}

	tests := []struct {
		scope    string
		expected bool
	}{
		{"github:read", true},
		{"aws:s3:read", true},
		{"github:write", false},
		{"doppler", false},
	}

	for _, tc := range tests {
		t.Run(tc.scope, func(t *testing.T) {
			if claims.HasScope(tc.scope) != tc.expected {
				t.Errorf("HasScope(%s) = %v, want %v", tc.scope, !tc.expected, tc.expected)
			}
		})
	}
}

func TestAgentClaimsWildcardScope(t *testing.T) {
	claims := &AgentClaims{
		Scopes: []string{"*"},
	}

	// Wildcard should match anything
	if !claims.HasScope("github:read") {
		t.Error("wildcard should match github:read")
	}
	if !claims.HasScope("aws:anything") {
		t.Error("wildcard should match aws:anything")
	}
}
