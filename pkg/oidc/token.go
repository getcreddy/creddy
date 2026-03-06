package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenRequest represents an OAuth2 token request
type TokenRequest struct {
	GrantType    string   `json:"grant_type"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scope        string   `json:"scope"`
	Audience     []string `json:"audience,omitempty"`
}

// TokenResponse represents an OAuth2 token response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

// TokenError represents an OAuth2 error response
type TokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// TokenProvider defines the interface for validating clients and getting agent info
type TokenProvider interface {
	// ValidateClient validates client_id and client_secret, returns agent info
	ValidateClient(clientID, clientSecret string) (*AgentInfo, error)
}

// AgentInfo contains agent details for token generation
type AgentInfo struct {
	ID     string
	Name   string
	Scopes []string
}

// TokenEndpoint handles OAuth2 token requests
type TokenEndpoint struct {
	issuer     string
	keyManager *KeyManager
	provider   TokenProvider
	defaultTTL time.Duration
	maxTTL     time.Duration
}

// NewTokenEndpoint creates a new token endpoint handler
func NewTokenEndpoint(issuer string, km *KeyManager, provider TokenProvider) *TokenEndpoint {
	return &TokenEndpoint{
		issuer:     issuer,
		keyManager: km,
		provider:   provider,
		defaultTTL: 1 * time.Hour,
		maxTTL:     24 * time.Hour,
	}
}

// WithTTL sets the default and max TTL for tokens
func (te *TokenEndpoint) WithTTL(defaultTTL, maxTTL time.Duration) *TokenEndpoint {
	te.defaultTTL = defaultTTL
	te.maxTTL = maxTTL
	return te
}

// Handler returns the HTTP handler for the token endpoint
func (te *TokenEndpoint) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			te.writeError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
			return
		}

		// Parse request (form or JSON)
		req, err := te.parseRequest(r)
		if err != nil {
			te.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}

		// Validate grant type
		if req.GrantType != "client_credentials" {
			te.writeError(w, http.StatusBadRequest, "unsupported_grant_type",
				"only client_credentials grant is supported")
			return
		}

		// Validate client
		agent, err := te.provider.ValidateClient(req.ClientID, req.ClientSecret)
		if err != nil {
			te.writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
			return
		}

		// Parse requested scopes
		requestedScopes := parseScopes(req.Scope)
		grantedScopes := intersectScopes(requestedScopes, agent.Scopes)

		// Generate tokens
		accessToken, idToken, err := te.generateTokens(agent, grantedScopes, req.Audience)
		if err != nil {
			te.writeError(w, http.StatusInternalServerError, "server_error", "failed to generate tokens")
			return
		}

		// Build response
		resp := TokenResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   int(te.defaultTTL.Seconds()),
			IDToken:     idToken,
			Scope:       strings.Join(grantedScopes, " "),
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		json.NewEncoder(w).Encode(resp)
	}
}

func (te *TokenEndpoint) parseRequest(r *http.Request) (*TokenRequest, error) {
	req := &TokenRequest{}

	// Check for Basic auth header first
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				req.ClientID = parts[0]
				req.ClientSecret = parts[1]
			}
		}
	}

	// Parse body (form-encoded or JSON)
	// Save Basic auth values - they take precedence per OAuth2 spec
	basicClientID := req.ClientID
	basicClientSecret := req.ClientSecret

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		// Decode into a separate struct to avoid overwriting Basic auth values
		var jsonReq TokenRequest
		if err := json.NewDecoder(r.Body).Decode(&jsonReq); err != nil {
			return nil, fmt.Errorf("invalid JSON body: %w", err)
		}
		// Merge: Basic auth takes precedence for client credentials
		req.GrantType = jsonReq.GrantType
		req.Scope = jsonReq.Scope
		req.Audience = jsonReq.Audience
		if basicClientID != "" {
			req.ClientID = basicClientID
		} else {
			req.ClientID = jsonReq.ClientID
		}
		if basicClientSecret != "" {
			req.ClientSecret = basicClientSecret
		} else {
			req.ClientSecret = jsonReq.ClientSecret
		}
	} else {
		// Form-encoded (default per OAuth2 spec)
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("invalid form body: %w", err)
		}
		if req.GrantType == "" {
			req.GrantType = r.FormValue("grant_type")
		}
		if req.ClientID == "" {
			req.ClientID = r.FormValue("client_id")
		}
		if req.ClientSecret == "" {
			req.ClientSecret = r.FormValue("client_secret")
		}
		if req.Scope == "" {
			req.Scope = r.FormValue("scope")
		}
	}

	if req.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if req.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is required")
	}
	if req.GrantType == "" {
		return nil, fmt.Errorf("grant_type is required")
	}

	return req, nil
}

func (te *TokenEndpoint) generateTokens(agent *AgentInfo, scopes []string, audience []string) (string, string, error) {
	key, err := te.keyManager.CurrentKey()
	if err != nil {
		return "", "", err
	}

	// Default audience to issuer if not specified
	if len(audience) == 0 {
		audience = []string{te.issuer}
	}

	// Generate ID token
	idClaims := NewAgentClaims(te.issuer, agent.ID, agent.Name, scopes, audience, te.defaultTTL)
	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
	idToken.Header["kid"] = key.ID

	signedIDToken, err := idToken.SignedString(key.PrivateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	// Generate access token (similar but simpler claims)
	accessClaims := NewAccessTokenClaims(te.issuer, agent.ID, scopes, te.defaultTTL)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = key.ID

	signedAccessToken, err := accessToken.SignedString(key.PrivateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedAccessToken, signedIDToken, nil
}

func (te *TokenEndpoint) writeError(w http.ResponseWriter, status int, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(TokenError{
		Error:            errCode,
		ErrorDescription: errDesc,
	})
}

// parseScopes splits a space-separated scope string
func parseScopes(scopeStr string) []string {
	if scopeStr == "" {
		return []string{}
	}
	return strings.Fields(scopeStr)
}

// intersectScopes returns scopes that are both requested and allowed
func intersectScopes(requested, allowed []string) []string {
	if len(requested) == 0 {
		return allowed
	}

	allowedSet := make(map[string]bool)
	for _, s := range allowed {
		allowedSet[s] = true
	}

	var result []string
	for _, s := range requested {
		// Always allow "openid" scope
		if s == "openid" || allowedSet[s] {
			result = append(result, s)
		}
	}
	return result
}
