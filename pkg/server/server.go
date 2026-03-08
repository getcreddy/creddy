package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getcreddy/creddy/pkg/backend"
	"github.com/getcreddy/creddy/pkg/logger"
	"github.com/getcreddy/creddy/pkg/oidc"
	pluginpkg "github.com/getcreddy/creddy/pkg/plugin"
	"github.com/getcreddy/creddy/pkg/policy"
	"github.com/getcreddy/creddy/pkg/signing"
	"github.com/getcreddy/creddy/pkg/store"
	"github.com/golang-jwt/jwt/v5"
)

type Server struct {
	store                *store.Store
	backends             *backend.Manager
	pluginLoader         *pluginpkg.Loader
	domain               string
	publicURL            string // Public URL for agents (OIDC issuer or configured URL)
	agentInactivityLimit time.Duration
	localAdminToken      string
	policyEngine         *policy.Engine
	oidcProvider         *oidc.Provider
	ctx                  context.Context
	cancel               context.CancelFunc
}

type Config struct {
	DBPath               string
	DataDir              string         // Data directory (for admin token file)
	Domain               string         // Domain for agent email addresses (e.g., creddy.dev)
	AgentInactivityLimit time.Duration  // Auto-unenroll agents inactive for this long (0 = disabled)
	PluginLoader         *pluginpkg.Loader // Plugin loader for hot-reload support
	PolicyEngine         *policy.Engine
	OIDCIssuer           string         // OIDC issuer URL (e.g., https://creddy.example.com)
}

func New(cfg Config) (*Server, error) {
	st, err := store.New(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	domain := cfg.Domain
	if domain == "" {
		domain = "creddy.local"
	}

	// Generate local admin token
	localAdminToken := generateToken()

	s := &Server{
		store:                st,
		backends:             backend.NewManager(),
		pluginLoader:         cfg.PluginLoader,
		domain:               domain,
		publicURL:            cfg.OIDCIssuer, // Use OIDC issuer as public URL
		agentInactivityLimit: cfg.AgentInactivityLimit,
		localAdminToken:      localAdminToken,
		policyEngine:         cfg.PolicyEngine,
		ctx:                  ctx,
		cancel:               cancel,
	}

	// Write local admin token to file for CLI auto-approval
	if cfg.DataDir != "" {
		if err := s.writeLocalAdminToken(cfg.DataDir, localAdminToken); err != nil {
			logger.Warn("failed to write local admin token", "error", err)
		}
	}

	// Load backends from database
	if err := s.loadBackends(); err != nil {
		logger.Warn("failed to load backends", "error", err)
	}

	// Start the reapers
	go s.reapExpiredCredentials()
	go s.reapExpiredPolicyAgents() // Always run - handles expires_in TTL
	go s.reapStaleEnrollments()    // Clean up approved enrollments with plaintext secrets
	if s.agentInactivityLimit > 0 {
		go s.reapInactiveAgents()
	}

	// Initialize OIDC provider if issuer is configured
	if cfg.OIDCIssuer != "" {
		oidcProvider, err := oidc.NewProvider(oidc.Config{
			Issuer:        cfg.OIDCIssuer,
			DefaultTTL:    1 * time.Hour,
			MaxTTL:        24 * time.Hour,
			TokenProvider: s.newOIDCTokenProvider(),
			KeyStore:      s.newOIDCKeyStore(),
		})
		if err != nil {
			logger.Warn("failed to initialize OIDC provider", "error", err)
		} else {
			s.oidcProvider = oidcProvider
			logger.Info("OIDC provider initialized", "issuer", cfg.OIDCIssuer)
		}
	}

	return s, nil
}

// writeLocalAdminToken writes the admin token to a file for CLI auto-approval.
// The file is only readable by the owner (mode 0600).
func (s *Server) writeLocalAdminToken(dataDir, token string) error {
	tokenPath := filepath.Join(dataDir, ".admin-token")
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		return err
	}
	logger.Debug("local admin token written", "path", tokenPath)
	return nil
}

// LocalAdminTokenPath returns the expected path of the admin token file
func LocalAdminTokenPath(dataDir string) string {
	return filepath.Join(dataDir, ".admin-token")
}

func (s *Server) loadBackends() error {
	backends, err := s.store.ListBackends()
	if err != nil {
		return err
	}

	for _, b := range backends {
		backend, err := backend.LoadFromConfig(b.Type, b.Config)
		if err != nil {
			logger.Warn("failed to load backend", "name", b.Name, "error", err)
			continue
		}
		s.backends.Register(b.Name, backend)
		logger.Info("loaded backend", "name", b.Name, "type", b.Type)
	}

	return nil
}

func (s *Server) reapExpiredCredentials() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			// Get expired credentials to revoke them first
			expired, err := s.store.GetExpiredCredentials()
			if err != nil {
				logger.Error("error getting expired credentials", "error", err)
				continue
			}

			// Revoke from external backends
			for _, cred := range expired {
				if cred.ExternalID != "" {
					s.revokeCredentialFromBackend(cred.Backend, cred.ExternalID)
				}
			}

			// Delete from database
			deleted, err := s.store.DeleteExpiredCredentials()
			if err != nil {
				logger.Error("error reaping expired credentials", "error", err)
			} else if deleted > 0 {
				logger.Debug("reaped expired credentials", "count", deleted)
			}
		}
	}
}

// revokeCredentialFromBackend revokes a credential from the external service
func (s *Server) revokeCredentialFromBackend(backendName, externalID string) {
	b, err := s.backends.Get(backendName)
	if err != nil {
		logger.Warn("backend not found for revocation", "name", backendName)
		return
	}

	if rb, ok := b.(backend.RevocableBackend); ok {
		if err := rb.RevokeToken(externalID); err != nil {
			logger.Warn("failed to revoke credential", "backend", backendName, "error", err)
		} else {
			logger.Debug("revoked credential", "backend", backendName)
		}
	}
}

func (s *Server) reapInactiveAgents() {
	// Check every hour
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			deleted, err := s.store.DeleteInactiveAgents(s.agentInactivityLimit)
			if err != nil {
				logger.Error("error reaping inactive agents", "error", err)
			} else if deleted > 0 {
				logger.Info("reaped inactive agents", "count", deleted, "limit", s.agentInactivityLimit)
			}
		}
	}
}

func (s *Server) Close() error {
	s.cancel()
	return s.store.Close()
}

func (s *Server) Store() *store.Store {
	return s.store
}

func (s *Server) Backends() *backend.Manager {
	return s.backends
}

// newOIDCTokenProvider creates a TokenProvider that validates agents using the store
func (s *Server) newOIDCTokenProvider() oidc.TokenProvider {
	return oidc.NewStoreAdapter(func(clientID, clientSecret string) (*oidc.AgentInfo, error) {
		var agent *store.Agent
		var err error

		// Try OIDC client_id first (agent_xxx format)
		if strings.HasPrefix(clientID, "agent_") {
			agent, err = s.store.GetAgentByClientID(clientID)
			if err == nil && agent.ClientSecretHash != nil {
				// Validate client_secret
				if !oidc.ValidateClientSecret(clientSecret, *agent.ClientSecretHash) {
					return nil, fmt.Errorf("invalid credentials")
				}
			} else {
				return nil, fmt.Errorf("invalid credentials")
			}
		} else {
			// Legacy mode: use agent name as client_id and ckr_ token as client_secret
			agent, err = s.store.GetAgentByTokenHash(hashToken(clientSecret))
			if err != nil {
				return nil, fmt.Errorf("invalid credentials")
			}

			// Verify the client_id matches the agent name or ID
			if agent.Name != clientID && agent.ID != clientID {
				return nil, fmt.Errorf("invalid credentials")
			}
		}

		// Update last used
		s.store.UpdateAgentLastUsed(agent.ID)

		return &oidc.AgentInfo{
			ID:     agent.ID,
			Name:   agent.Name,
			Scopes: oidc.ParseScopes(agent.Scopes),
		}, nil
	})
}

// OIDCProvider returns the OIDC provider (for key management, etc.)
func (s *Server) OIDCProvider() *oidc.Provider {
	return s.oidcProvider
}

// authenticateAdmin validates a request has admin privileges
// Returns the agent if authorized, or writes an error and returns nil
func (s *Server) authenticateAdmin(w http.ResponseWriter, r *http.Request, requiredScope string) *store.Agent {
	token := extractBearerToken(r)
	
	if token == "" {
		writeError(w, http.StatusUnauthorized, "admin authentication required")
		return nil
	}

	// Check for local admin token (written to .admin-token file)
	if token == s.localAdminToken {
		return &store.Agent{Name: "local-admin", ID: "local", Scopes: `["admin:*"]`}
	}

	logger.Debug("admin auth failed local token check",
		"token_prefix", token[:min(len(token), 12)],
		"expected_prefix", s.localAdminToken[:min(len(s.localAdminToken), 12)],
		"token_len", len(token),
		"expected_len", len(s.localAdminToken))

	agent, err := s.authenticateAgent(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid authorization")
		return nil
	}

	// Check for admin scope
	if !agentHasScope(agent, requiredScope) {
		writeError(w, http.StatusForbidden, "insufficient permissions: requires "+requiredScope)
		return nil
	}

	return agent
}

// agentHasScope checks if an agent has a specific scope
func agentHasScope(agent *store.Agent, required string) bool {
	var scopes []string
	json.Unmarshal([]byte(agent.Scopes), &scopes)

	for _, scope := range scopes {
		// Exact match
		if scope == required {
			return true
		}
		// Wildcard match: admin:* matches admin:agents:read
		if strings.HasSuffix(scope, ":*") {
			prefix := strings.TrimSuffix(scope, "*")
			if strings.HasPrefix(required, prefix) {
				return true
			}
		}
		// Full wildcard
		if scope == "*" {
			return true
		}
	}
	return false
}



// authenticateAgent validates a bearer token and returns the agent
// Supports both OIDC JWTs (eyJ...) and legacy ckr_ tokens
func (s *Server) authenticateAgent(token string) (*store.Agent, error) {
	// Check if it looks like a JWT (starts with eyJ)
	if strings.HasPrefix(token, "eyJ") && s.oidcProvider != nil {
		// Parse and validate JWT
		claims, err := s.validateOIDCToken(token)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT: %w", err)
		}

		// Look up agent by ID from claims
		agent, err := s.store.GetAgentByID(claims.AgentID)
		if err != nil {
			return nil, fmt.Errorf("agent not found")
		}

		// Update last used
		s.store.UpdateAgentLastUsed(agent.ID)
		return agent, nil
	}

	// Legacy token authentication
	agent, err := s.store.GetAgentByTokenHash(hashToken(token))
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}

	s.store.UpdateAgentLastUsed(agent.ID)
	return agent, nil
}

// validateOIDCToken validates an OIDC access token and returns its claims
func (s *Server) validateOIDCToken(tokenStr string) (*oidc.AgentClaims, error) {
	if s.oidcProvider == nil {
		return nil, fmt.Errorf("OIDC not configured")
	}

	km := s.oidcProvider.KeyManager()

	token, err := jwt.ParseWithClaims(tokenStr, &oidc.AgentClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid header")
		}

		key, err := km.GetKey(kid)
		if err != nil {
			return nil, err
		}
		return &key.PrivateKey.PublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token not valid")
	}

	claims, ok := token.Claims.(*oidc.AgentClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return claims, nil
}

// newOIDCKeyStore creates a KeyStore adapter backed by the database
func (s *Server) newOIDCKeyStore() oidc.KeyStore {
	return oidc.NewKeyStoreAdapter(
		// CreateOIDCKey
		func(keyID, privateKeyPEM string, isCurrent bool) error {
			_, err := s.store.CreateOIDCKey(keyID, privateKeyPEM, isCurrent)
			return err
		},
		// ListOIDCKeys
		func() ([]oidc.StoredKey, error) {
			keys, err := s.store.ListOIDCKeys()
			if err != nil {
				return nil, err
			}
			result := make([]oidc.StoredKey, len(keys))
			for i, k := range keys {
				result[i] = oidc.ConvertStoredKey(k.KeyID, k.PrivateKey, k.IsCurrent, k.CreatedAt)
			}
			return result, nil
		},
		// GetCurrentOIDCKey
		func() (*oidc.StoredKey, error) {
			k, err := s.store.GetCurrentOIDCKey()
			if err != nil {
				return nil, err
			}
			sk := oidc.ConvertStoredKey(k.KeyID, k.PrivateKey, k.IsCurrent, k.CreatedAt)
			return &sk, nil
		},
		// SetCurrentOIDCKey
		func(keyID string) error {
			return s.store.SetCurrentOIDCKey(keyID)
		},
		// DeleteOIDCKey
		func(keyID string) error {
			return s.store.DeleteOIDCKey(keyID)
		},
	)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /health", s.handleHealth)

	// Enrollment (no auth - client initiates pairing)
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /v1/enroll/status", s.handleEnrollStatus)

	// Agent status (agent auth required)
	mux.HandleFunc("GET /v1/status", s.handleAgentStatus)

	// Scope requests (agent auth required)
	mux.HandleFunc("POST /v1/request", s.handleScopeRequest)

	// Credential endpoints (agent auth required)
	mux.HandleFunc("POST /v1/credentials/{backend}", s.handleGetCredential)

	// Agent self-service
	mux.HandleFunc("GET /v1/active", s.handleListActive)
	mux.HandleFunc("DELETE /v1/active/{id}", s.handleRevokeCredential)
	mux.HandleFunc("GET /v1/signing-key", s.handleGetSigningKey)
	mux.HandleFunc("DELETE /v1/self", s.handleSelfDelete)

	// Admin endpoints (no auth for now - bind to localhost/tailnet only)
	mux.HandleFunc("GET /v1/admin/agents", s.handleListAgents)
	mux.HandleFunc("POST /v1/admin/agents", s.handleCreateAgent)
	mux.HandleFunc("DELETE /v1/admin/agents/{name}", s.handleDeleteAgent)
	mux.HandleFunc("GET /v1/admin/backends", s.handleListBackends)
	mux.HandleFunc("GET /v1/admin/backends/{name}", s.handleGetBackend)
	mux.HandleFunc("POST /v1/admin/backends", s.handleCreateBackend)
	mux.HandleFunc("DELETE /v1/admin/backends/{name}", s.handleDeleteBackend)
	mux.HandleFunc("GET /v1/admin/audit", s.handleGetAuditLog)
	mux.HandleFunc("GET /v1/admin/tokens", s.handleListAllTokens)
	mux.HandleFunc("DELETE /v1/admin/tokens/{id}", s.handleAdminRevokeToken)
	mux.HandleFunc("GET /v1/admin/keys", s.handleListPublicKeys)
	mux.HandleFunc("GET /v1/admin/pending", s.handleListPending)
	mux.HandleFunc("POST /v1/admin/pending/{id}/approve", s.handleApprovePending)
	mux.HandleFunc("POST /v1/admin/pending/{id}/reject", s.handleRejectPending)
	mux.HandleFunc("POST /v1/admin/plugins/reload", s.handlePluginReload)
	mux.HandleFunc("POST /v1/admin/plugins/{name}/reload", s.handlePluginReloadOne)

	// Enrollment endpoints (new PKI-based auth)
	s.RegisterEnrollmentRoutes(mux)

	// Proxy endpoints (for backends that support proxy mode)
	s.RegisterProxyRoutes(mux)

	// OIDC endpoints (if enabled)
	if s.oidcProvider != nil {
		s.oidcProvider.RegisterRoutes(mux)
	}

	// Auth relay endpoints (for @creddy/auth CLI)

	return s.withMiddleware(mux)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		logger.Debug("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// ServerVersion is set by main to expose version info to health endpoint
var ServerVersion = "dev"
var ServerCommit = "unknown"
var ServerStartTime = time.Now()

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Get counts
	agents, _ := s.store.ListAgents()
	backends := s.backends.List()
	pending, _ := s.store.ListPendingEnrollments()
	
	// Get plugin info
	var plugins []string
	if s.pluginLoader != nil {
		for _, p := range s.pluginLoader.ListPlugins() {
			plugins = append(plugins, p.Info.Name)
		}
	}

	response := map[string]interface{}{
		"status":   "ok",
		"version":  ServerVersion,
		"commit":   ServerCommit,
		"uptime":   time.Since(ServerStartTime).Round(time.Second).String(),
		"agents":   len(agents),
		"backends": len(backends),
		"pending":  len(pending),
		"plugins":  plugins,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
func (s *Server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	backendName := r.PathValue("backend")
	token := extractBearerToken(r)

	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return
	}

	// Validate agent - supports both OIDC JWTs and legacy ckr_ tokens
	agent, err := s.authenticateAgent(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid authorization: "+err.Error())
		return
	}

	// Parse agent scopes
	var agentScopes []string
	json.Unmarshal([]byte(agent.Scopes), &agentScopes)

	// Parse repos from query params (can be specified multiple times)
	// If no repos specified, use all repos from agent's scopes
	repos := r.URL.Query()["repo"]
	readOnly := r.URL.Query().Get("read_only") == "true"

	// Extract scopes based on backend type
	var dopplerScopes []string
	if len(repos) == 0 && backendName == "github" {
		// Extract repos from agent's scopes
		repos, _ = backend.ExtractReposFromScopes(agentScopes)
	}
	if backendName == "doppler" {
		// Extract Doppler scopes from agent's scopes
		dopplerScopes = backend.ExtractDopplerScopesFromAgentScopes(agentScopes)
	}

	// Check agent has permission for this backend
	if !agentCanAccessBackend(agent, backendName, repos, dopplerScopes, readOnly) {
		writeError(w, http.StatusForbidden, "agent not authorized for this backend")
		return
	}

	// Get backend
	b, err := s.backends.Get(backendName)
	if err != nil {
		writeError(w, http.StatusNotFound, "backend not found: "+backendName)
		return
	}

	// Parse TTL
	ttlStr := r.URL.Query().Get("ttl")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil || ttl <= 0 {
		ttl = 10 * time.Minute
	}
	// Note: Plugin constraints (max/min TTL) are validated by PluginBackend.ValidateTTL()
	// Native backends should implement their own validation

	// Generate credential
	var cred *backend.Token
	var externalID string

	// Build token request with TTL
	tokenReq := backend.TokenRequest{
		Repos:         repos,
		ReadOnly:      readOnly,
		DopplerScopes: dopplerScopes,
		TTL:           ttl,
	}

	// Check if backend supports revocation (like Anthropic, Doppler)
	if rb, ok := b.(backend.RevocableBackend); ok {
		cred, externalID, err = rb.GetTokenWithID(tokenReq)
	} else {
		cred, err = b.GetToken(tokenReq)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate credential: "+err.Error())
		return
	}

	// Adjust expiry to requested TTL if shorter than backend's default
	expiresAt := cred.ExpiresAt
	requestedExpiry := time.Now().Add(ttl)
	if requestedExpiry.Before(expiresAt) {
		expiresAt = requestedExpiry
	}

	// Record the active credential
	scopes := r.URL.Query().Get("scope")
	activeCred, err := s.store.CreateActiveCredential(agent.ID, backendName, hashToken(cred.Value), externalID, scopes, expiresAt)
	if err != nil {
		logger.Warn("failed to record credential", "error", err)
	}

	// Update agent last used
	s.store.UpdateAgentLastUsed(agent.ID)

	// Audit log
	tokenID := ""
	if activeCred != nil {
		tokenID = activeCred.ID
	}
	details, _ := json.Marshal(map[string]interface{}{
		"ttl":        ttl.String(),
		"expires_at": expiresAt,
		"scopes":     scopes,
		"repos":      repos,
	})
	s.store.LogAuditEvent(agent.ID, agent.Name, "token_issued", backendName, string(details), tokenID, r.RemoteAddr)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      cred.Value,
		"expires_at": expiresAt,
		"ttl":        time.Until(expiresAt).String(),
	})
}

func (s *Server) handleListActive(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return
	}

	agent, err := s.authenticateAgent(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid authorization")
		return
	}

	creds, err := s.store.ListActiveCredentialsByAgent(agent.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list credentials")
		return
	}

	results := make([]map[string]interface{}, len(creds))
	for i, c := range creds {
		results[i] = map[string]interface{}{
			"id":         c.ID,
			"backend":    c.Backend,
			"expires_at": c.ExpiresAt,
			"created_at": c.CreatedAt,
		}
	}

	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token := extractBearerToken(r)

	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return
	}

	agent, err := s.authenticateAgent(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid authorization")
		return
	}

	// Verify the credential belongs to this agent
	cred, err := s.store.GetActiveCredential(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}

	if cred.AgentID != agent.ID {
		writeError(w, http.StatusForbidden, "not authorized to revoke this credential")
		return
	}

	if err := s.store.DeleteActiveCredential(id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke credential")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Admin endpoints

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:agents:read"); admin == nil {
		return
	}

	agents, err := s.store.ListAgents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list agents")
		return
	}

	results := make([]map[string]interface{}, len(agents))
	for i, a := range agents {
		results[i] = map[string]interface{}{
			"id":         a.ID,
			"name":       a.Name,
			"scopes":     a.Scopes,
			"created_at": a.CreatedAt,
			"last_used":  a.LastUsed,
		}
	}

	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:agents:write"); admin == nil {
		return
	}

	var req struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresIn string   `json:"expires_in,omitempty"` // e.g., "4h", "24h"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Parse TTL if provided
	var expiresAt *time.Time
	if req.ExpiresIn != "" {
		ttl, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expires_in: "+err.Error())
			return
		}
		t := time.Now().Add(ttl)
		expiresAt = &t
	}

	// Generate token
	token := generateToken()
	scopesJSON, _ := json.Marshal(req.Scopes)

	var agent *store.Agent
	var err error
	if expiresAt != nil {
		agent, err = s.store.CreateAgentWithPolicy(req.Name, hashToken(token), string(scopesJSON), "", expiresAt)
	} else {
		agent, err = s.store.CreateAgent(req.Name, hashToken(token), string(scopesJSON))
	}
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeError(w, http.StatusConflict, "agent already exists: "+req.Name)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create agent: "+err.Error())
		return
	}

	// Generate GPG signing key for the agent
	keyPair, err := signing.GenerateKeyPair(req.Name, s.domain)
	if err != nil {
		logger.Warn("failed to generate signing key", "agent", req.Name, "error", err)
	} else {
		_, err = s.store.CreateSigningKey(agent.ID, keyPair.KeyID, keyPair.PublicKey, keyPair.PrivateKey, keyPair.Email, keyPair.Name)
		if err != nil {
			logger.Warn("failed to store signing key", "agent", req.Name, "error", err)
		}
	}

	// Generate OIDC client credentials (only if OIDC is enabled)
	var oidcCreds *oidc.ClientCredentials
	if s.oidcProvider != nil {
		oidcCreds, err = oidc.GenerateClientCredentials()
		if err != nil {
			logger.Warn("failed to generate OIDC credentials", "agent", req.Name, "error", err)
		} else {
			if err := s.store.SetAgentOIDCCredentials(agent.ID, oidcCreds.ClientID, oidcCreds.SecretHash); err != nil {
				logger.Warn("failed to store OIDC credentials", "agent", req.Name, "error", err)
				oidcCreds = nil
			}
		}
	}

	// Audit log
	details, _ := json.Marshal(map[string]interface{}{"scopes": req.Scopes})
	s.store.LogAuditEvent(agent.ID, agent.Name, "agent_created", "", string(details), "", r.RemoteAddr)

	response := map[string]interface{}{
		"id":         agent.ID,
		"name":       agent.Name,
		"token":      token, // Only shown once!
		"scopes":     req.Scopes,
		"created_at": agent.CreatedAt,
	}

	if s.publicURL != "" {
		response["server_url"] = s.publicURL
	}

	if expiresAt != nil {
		response["expires_at"] = expiresAt
	}

	if keyPair != nil {
		response["signing_key_id"] = keyPair.KeyID
		response["signing_email"] = keyPair.Email
	}

	// Include OIDC credentials (only shown once!)
	if oidcCreds != nil {
		response["oidc"] = map[string]string{
			"client_id":     oidcCreds.ClientID,
			"client_secret": oidcCreds.ClientSecret,
		}
	}

	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:agents:write"); admin == nil {
		return
	}

	name := r.PathValue("name")

	// Get agent to find their credentials
	agent, err := s.store.GetAgentByName(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	// Revoke all active credentials from backends
	creds, err := s.store.GetAllCredentialsByAgent(agent.ID)
	if err != nil {
		logger.Warn("failed to get credentials for agent", "name", name, "error", err)
	} else {
		for _, cred := range creds {
			if cred.ExternalID != "" {
				s.revokeCredentialFromBackend(cred.Backend, cred.ExternalID)
			}
		}
	}

	// Delete credentials from database
	if err := s.store.DeleteAllCredentialsByAgent(agent.ID); err != nil {
		logger.Warn("failed to delete credentials for agent", "name", name, "error", err)
	}

	// Delete the agent
	if err := s.store.DeleteAgent(name); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete agent")
		return
	}

	logger.Info("unenrolled agent", "name", name, "credentials_revoked", len(creds))

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListBackends(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:backends:read"); admin == nil {
		return
	}

	backends, err := s.store.ListBackends()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list backends")
		return
	}

	results := make([]map[string]interface{}, len(backends))
	for i, b := range backends {
		results[i] = map[string]interface{}{
			"id":         b.ID,
			"type":       b.Type,
			"name":       b.Name,
			"created_at": b.CreatedAt,
		}
	}

	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleGetBackend(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:backends:read"); admin == nil {
		return
	}

	name := r.PathValue("name")

	backend, err := s.store.GetBackendByName(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "backend not found")
		return
	}

	// Parse config to return as object (masking secrets)
	var config map[string]interface{}
	if backend.Config != "" {
		json.Unmarshal([]byte(backend.Config), &config)
		// Mask sensitive fields
		for key := range config {
			keyLower := strings.ToLower(key)
			if strings.Contains(keyLower, "key") || strings.Contains(keyLower, "secret") ||
				strings.Contains(keyLower, "token") || strings.Contains(keyLower, "password") {
				if str, ok := config[key].(string); ok && len(str) > 8 {
					config[key] = str[:4] + "..." + str[len(str)-4:]
				}
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         backend.ID,
		"type":       backend.Type,
		"name":       backend.Name,
		"config":     config,
		"created_at": backend.CreatedAt,
	})
}

func (s *Server) handleCreateBackend(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:backends:write"); admin == nil {
		return
	}

	var req struct {
		Type   string          `json:"type"`
		Name   string          `json:"name"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Type == "" {
		writeError(w, http.StatusBadRequest, "type is required")
		return
	}
	if req.Name == "" {
		req.Name = req.Type
	}

	// Validate config by trying to load the backend
	b, err := backend.LoadFromConfig(req.Type, string(req.Config))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid backend config: "+err.Error())
		return
	}

	// Store in database
	stored, err := s.store.CreateBackend(req.Type, req.Name, string(req.Config))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create backend: "+err.Error())
		return
	}

	// Register in memory
	s.backends.Register(req.Name, b)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         stored.ID,
		"type":       stored.Type,
		"name":       stored.Name,
		"created_at": stored.CreatedAt,
	})
}

func (s *Server) handleDeleteBackend(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:backends:write"); admin == nil {
		return
	}

	name := r.PathValue("name")

	if err := s.store.DeleteBackend(name); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete backend")
		return
	}

	// TODO: remove from s.backends manager

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePluginReload(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:plugins:write"); admin == nil {
		return
	}

	if s.pluginLoader == nil {
		writeError(w, http.StatusServiceUnavailable, "plugin loader not configured")
		return
	}

	loaded, err := s.pluginLoader.Reload()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reload plugins: "+err.Error())
		return
	}

	// Get full list of loaded plugins
	allPlugins := s.pluginLoader.ListPlugins()
	pluginNames := make([]string, 0, len(allPlugins))
	for _, p := range allPlugins {
		pluginNames = append(pluginNames, p.Info.Name)
	}

	logger.Info("plugin reload", "new_plugins", len(loaded), "total", len(pluginNames))

	json.NewEncoder(w).Encode(map[string]interface{}{
		"loaded":  loaded,
		"plugins": pluginNames,
	})
}

func (s *Server) handlePluginReloadOne(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:plugins:write"); admin == nil {
		return
	}

	if s.pluginLoader == nil {
		writeError(w, http.StatusServiceUnavailable, "plugin loader not configured")
		return
	}

	pluginName := r.PathValue("name")
	if pluginName == "" {
		writeError(w, http.StatusBadRequest, "plugin name required")
		return
	}

	// Reload the specific plugin (kills old process, starts new one)
	loaded, err := s.pluginLoader.ReloadPlugin(pluginName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reload plugin: "+err.Error())
		return
	}

	// Re-register the backend bridge
	if s.backends != nil {
		bridge := pluginpkg.NewPluginBackend(pluginName, loaded.Plugin)
		s.backends.Register(pluginName, bridge)
	}

	logger.Info("reloaded plugin", "name", loaded.Info.Name, "version", loaded.Info.Version)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"reloaded": pluginName,
		"version":  loaded.Info.Version,
	})
}

func (s *Server) handleGetSigningKey(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return
	}

	agent, err := s.authenticateAgent(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid authorization")
		return
	}

	key, err := s.store.GetSigningKeyByAgent(agent.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "no signing key found for this agent")
		return
	}

	// Update last accessed
	s.store.UpdateKeyLastAccessed(agent.ID)

	// Audit log
	s.store.LogAuditEvent(agent.ID, agent.Name, "key_accessed", "", "", "", r.RemoteAddr)

	// Return based on format requested
	format := r.URL.Query().Get("format")
	if format == "git" {
		// Return in a format suitable for git config
		json.NewEncoder(w).Encode(map[string]interface{}{
			"signing_key":  key.PrivateKey,
			"key_id":       key.KeyID,
			"email":        key.Email,
			"name":         key.Name,
			"git_config": map[string]string{
				"user.name":       key.Name,
				"user.email":      key.Email,
				"user.signingkey": key.KeyID,
				"commit.gpgsign":  "true",
			},
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"key_id":      key.KeyID,
			"public_key":  key.PublicKey,
			"private_key": key.PrivateKey,
			"email":       key.Email,
			"name":        key.Name,
		})
	}
}

// handleSelfDelete allows an agent to delete itself
func (s *Server) handleSelfDelete(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return
	}

	agent, err := s.authenticateAgent(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid authorization")
		return
	}

	// Revoke all active credentials from backends
	creds, err := s.store.GetAllCredentialsByAgent(agent.ID)
	if err != nil {
		logger.Warn("failed to get credentials for agent", "name", agent.Name, "error", err)
	} else {
		for _, cred := range creds {
			if cred.ExternalID != "" {
				if b, err := s.backends.Get(cred.Backend); err == nil {
					if rb, ok := b.(backend.RevocableBackend); ok {
						if err := rb.RevokeToken(cred.ExternalID); err != nil {
							logger.Warn("failed to revoke token", "backend", cred.Backend, "error", err)
						}
					}
				}
			}
		}
	}

	// Delete all active credentials
	s.store.DeleteActiveCredentialsByAgent(agent.ID)

	// Delete signing key
	s.store.DeleteSigningKey(agent.ID)

	// Delete the agent
	if err := s.store.DeleteAgent(agent.Name); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete agent")
		return
	}

	// Audit log (before deletion completes)
	s.store.LogAuditEvent(agent.ID, agent.Name, "agent_self_deleted", "", "", "", r.RemoteAddr)

	logger.Info("agent self-deleted", "name", agent.Name, "id", agent.ID)

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:audit:read"); admin == nil {
		return
	}

	// Parse query params
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}

	agentID := r.URL.Query().Get("agent_id")
	action := r.URL.Query().Get("action")

	events, err := s.store.GetAuditLog(limit, agentID, action)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get audit log")
		return
	}

	results := make([]map[string]interface{}, len(events))
	for i, e := range events {
		results[i] = map[string]interface{}{
			"id":         e.ID,
			"timestamp":  e.Timestamp,
			"agent_id":   e.AgentID,
			"agent_name": e.AgentName,
			"action":     e.Action,
			"backend":    e.Backend,
			"details":    e.Details,
			"token_id":   e.TokenID,
			"ip_address": e.IPAddress,
		}
	}

	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleListPublicKeys(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:keys:read"); admin == nil {
		return
	}

	keys, err := s.store.ListPublicKeys()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list keys")
		return
	}

	results := make([]map[string]interface{}, len(keys))
	for i, k := range keys {
		results[i] = map[string]interface{}{
			"key_id":     k.KeyID,
			"agent_id":   k.AgentID,
			"email":      k.Email,
			"name":       k.Name,
			"public_key": k.PublicKey,
			"created_at": k.CreatedAt,
		}
	}

	json.NewEncoder(w).Encode(results)
}

// Agent self-service endpoints

func (s *Server) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return
	}

	agent, err := s.authenticateAgent(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid authorization")
		return
	}

	// Get active credentials
	creds, err := s.store.ListActiveCredentialsByAgent(agent.ID)
	if err != nil {
		creds = nil // Non-fatal
	}

	activeCreds := make([]map[string]interface{}, len(creds))
	for i, c := range creds {
		activeCreds[i] = map[string]interface{}{
			"id":         c.ID,
			"backend":    c.Backend,
			"expires_at": c.ExpiresAt,
		}
	}

	// Get pending amendments
	pendingAmendments, err := s.store.ListPendingAmendmentsByAgent(agent.ID)
	if err != nil {
		pendingAmendments = nil // Non-fatal
	}

	amendments := make([]map[string]interface{}, len(pendingAmendments))
	for i, a := range pendingAmendments {
		var scopes []string
		json.Unmarshal([]byte(a.Scopes), &scopes)
		amendments[i] = map[string]interface{}{
			"id":         a.ID,
			"scopes":     scopes,
			"created_at": a.CreatedAt,
		}
	}

	// Parse scopes
	var scopes []string
	json.Unmarshal([]byte(agent.Scopes), &scopes)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":               agent.Name,
		"status":             "enrolled",
		"scopes":             scopes,
		"created_at":         agent.CreatedAt,
		"last_used":          agent.LastUsed,
		"active_credentials": activeCreds,
		"pending_amendments": amendments,
	})
}

// Enrollment endpoints

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string   `json:"name"`
		Scopes     []string `json:"scopes"`
		AdminToken string   `json:"admin_token,omitempty"` // For local auto-approval
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Check if agent with this name already exists
	existing, _ := s.store.GetAgentByName(req.Name)
	if existing != nil {
		writeError(w, http.StatusConflict, fmt.Sprintf("agent '%s' already exists. Use 'creddy request' to add scopes, or ask admin to run 'creddy unenroll %s'", req.Name, req.Name))
		return
	}

	// Validate scopes against installed backends
	if err := s.validateScopes(req.Scopes); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}


	// Check auto-approval policies
	if s.policyEngine != nil {
		result := s.policyEngine.Evaluate(req.Name, req.Scopes)
		if result.AutoApprove {
			logger.Info("policy auto-approved enrollment", "name", req.Name, "policy", result.PolicyName)
			
			token := generateToken()
			scopesJSON, _ := json.Marshal(req.Scopes)
			
			// Calculate agent expiry if set
			var expiresAt *time.Time
			if result.MaxAgentLifetime > 0 {
				t := time.Now().Add(result.MaxAgentLifetime)
				expiresAt = &t
			}
			
			agent, err := s.store.CreateAgentWithPolicy(req.Name, hashToken(token), string(scopesJSON), result.PolicyName, expiresAt)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to create agent: "+err.Error())
				return
			}
			
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":         agent.ID,
				"status":     "approved",
				"token":      token,
				"policy":     result.PolicyName,
				"expires_at": expiresAt,
			})
			return
		}
		// If policy matched but didn't auto-approve, log the reason
		if result.PolicyName != "" {
			logger.Debug("policy requires manual approval", "policy", result.PolicyName, "name", req.Name, "reason", result.DenyReason)
		}
	}

	// Check for local admin token - auto-approve if valid
	if req.AdminToken != "" && req.AdminToken == s.localAdminToken {
		logger.Info("local admin enrollment auto-approved", "name", req.Name)
		
		// Create agent directly without pending state
		token := generateToken()
		scopesJSON, _ := json.Marshal(req.Scopes)
		
		agent, err := s.store.CreateAgent(req.Name, hashToken(token), string(scopesJSON))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create agent: "+err.Error())
			return
		}
		
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":     agent.ID,
			"status": "approved",
			"token":  token,
		})
		return
	}

	// Generate a secret for the client to poll with
	secret := generateToken()
	scopesJSON, _ := json.Marshal(req.Scopes)

	enrollment, err := s.store.CreatePendingEnrollment(req.Name, secret, string(scopesJSON))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create enrollment: "+err.Error())
		return
	}

	logger.Info("new enrollment request", "name", req.Name, "id", enrollment.ID, "scopes", req.Scopes)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     enrollment.ID,
		"secret": secret, // Client uses this to poll
		"status": "pending",
	})
}

func (s *Server) handleScopeRequest(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return
	}

	agent, err := s.authenticateAgent(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid authorization")
		return
	}

	var req struct {
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Scopes) == 0 {
		writeError(w, http.StatusBadRequest, "scopes required")
		return
	}

	// Validate scopes against installed backends
	if err := s.validateScopes(req.Scopes); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	scopesJSON, _ := json.Marshal(req.Scopes)
	amendment, err := s.store.CreateScopeAmendment(agent.ID, agent.Name, string(scopesJSON))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create scope request: "+err.Error())
		return
	}

	logger.Info("scope request", "agent", agent.Name, "scopes", req.Scopes)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     amendment.ID,
		"status": "pending",
	})
}

func (s *Server) handleEnrollStatus(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	if secret == "" {
		writeError(w, http.StatusBadRequest, "secret is required")
		return
	}

	enrollment, err := s.store.GetPendingEnrollmentBySecret(secret)
	if err != nil {
		writeError(w, http.StatusNotFound, "enrollment not found")
		return
	}

	response := map[string]interface{}{
		"id":     enrollment.ID,
		"name":   enrollment.Name,
		"status": enrollment.Status,
	}

	// If approved, return the credentials (only works once - client should save them)
	if enrollment.Status == "approved" && enrollment.Token != "" {
		response["token"] = enrollment.Token
		response["scopes"] = enrollment.Scopes

		// Include OIDC credentials if available
		if enrollment.OIDCClientID != nil && enrollment.OIDCClientSecret != nil {
			response["oidc"] = map[string]string{
				"client_id":     *enrollment.OIDCClientID,
				"client_secret": *enrollment.OIDCClientSecret,
			}
		}

		// Include server URL if configured
		if s.publicURL != "" {
			response["server_url"] = s.publicURL
		}

		// Delete the enrollment after credential pickup
		s.store.DeletePendingEnrollment(enrollment.ID)
	}

	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleListPending(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:enrollments:read"); admin == nil {
		return
	}

	enrollments, err := s.store.ListPendingEnrollments()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list pending enrollments")
		return
	}

	results := make([]map[string]interface{}, len(enrollments))
	for i, e := range enrollments {
		reqType := "enroll"
		if e.IsAmendment() {
			reqType = "amendment"
		}
		results[i] = map[string]interface{}{
			"id":         e.ID,
			"name":       e.Name,
			"type":       reqType,
			"scopes":     e.Scopes,
			"created_at": e.CreatedAt,
		}
	}

	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleApprovePending(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:enrollments:write"); admin == nil {
		return
	}

	id := r.PathValue("id")

	// Get the enrollment
	enrollment, err := s.store.GetPendingEnrollment(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "enrollment not found")
		return
	}

	if enrollment.Status != "pending" {
		writeError(w, http.StatusBadRequest, "enrollment already processed")
		return
	}

	// Handle amendment vs new enrollment
	if enrollment.IsAmendment() {
		// Amendment: merge new scopes with existing agent scopes
		agent, err := s.store.GetAgentByID(enrollment.AgentID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to find agent: "+err.Error())
			return
		}

		// Merge scopes
		var existingScopes, newScopes []string
		json.Unmarshal([]byte(agent.Scopes), &existingScopes)
		json.Unmarshal([]byte(enrollment.Scopes), &newScopes)

		// Add new scopes (avoid duplicates)
		scopeSet := make(map[string]bool)
		for _, sc := range existingScopes {
			scopeSet[sc] = true
		}
		for _, sc := range newScopes {
			scopeSet[sc] = true
		}
		mergedScopes := make([]string, 0, len(scopeSet))
		for sc := range scopeSet {
			mergedScopes = append(mergedScopes, sc)
		}

		mergedJSON, _ := json.Marshal(mergedScopes)
		if err := s.store.UpdateAgentScopes(agent.ID, string(mergedJSON)); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update scopes: "+err.Error())
			return
		}

		// Mark enrollment as approved (no token needed for amendments)
		s.store.ApproveAgentEnrollment(id, "", string(mergedJSON))

		// Audit log
		details, _ := json.Marshal(map[string]interface{}{
			"added_scopes": newScopes,
			"final_scopes": mergedScopes,
		})
		s.store.LogAuditEvent(agent.ID, agent.Name, "scopes_amended", "", string(details), "", r.RemoteAddr)

		logger.Info("approved scope amendment", "agent", agent.Name, "added", newScopes)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":       agent.ID,
			"name":     agent.Name,
			"type":     "amendment",
			"scopes":   mergedScopes,
			"approved": true,
		})
		return
	}

	// New enrollment: create agent
	token := generateToken()

	// Use scopes from the enrollment request
	scopesJSON := enrollment.Scopes
	if scopesJSON == "" {
		scopesJSON = "[]"
	}

	// Create the agent
	agent, err := s.store.CreateAgent(enrollment.Name, hashToken(token), scopesJSON)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create agent: "+err.Error())
		return
	}

	// Generate GPG signing key for the agent
	keyPair, err := signing.GenerateKeyPair(enrollment.Name, s.domain)
	if err != nil {
		logger.Warn("failed to generate signing key", "agent", enrollment.Name, "error", err)
	} else {
		_, err = s.store.CreateSigningKey(agent.ID, keyPair.KeyID, keyPair.PublicKey, keyPair.PrivateKey, keyPair.Email, keyPair.Name)
		if err != nil {
			logger.Warn("failed to store signing key", "agent", enrollment.Name, "error", err)
		}
	}

	// Generate OIDC client credentials (only if OIDC is enabled)
	var oidcCreds *oidc.ClientCredentials
	if s.oidcProvider != nil {
		oidcCreds, err = oidc.GenerateClientCredentials()
		if err != nil {
			logger.Warn("failed to generate OIDC credentials", "agent", enrollment.Name, "error", err)
		} else {
			if err := s.store.SetAgentOIDCCredentials(agent.ID, oidcCreds.ClientID, oidcCreds.SecretHash); err != nil {
				logger.Warn("failed to store OIDC credentials", "agent", enrollment.Name, "error", err)
				oidcCreds = nil
			}
		}
	}

	// Update enrollment with the token (not hashed - client needs to pick it up)
	if oidcCreds != nil {
		s.store.ApproveAgentEnrollmentWithOIDC(id, token, scopesJSON, oidcCreds.ClientID, oidcCreds.ClientSecret)
	} else {
		s.store.ApproveAgentEnrollment(id, token, scopesJSON)
	}

	// Audit log
	details, _ := json.Marshal(map[string]interface{}{"scopes": scopesJSON, "enrollment_id": id})
	s.store.LogAuditEvent(agent.ID, agent.Name, "agent_enrolled", "", string(details), "", r.RemoteAddr)

	logger.Info("approved enrollment", "name", enrollment.Name, "agent_id", agent.ID)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       agent.ID,
		"name":     agent.Name,
		"type":     "enroll",
		"approved": true,
	})
}

func (s *Server) handleRejectPending(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:enrollments:write"); admin == nil {
		return
	}

	id := r.PathValue("id")

	enrollment, err := s.store.GetPendingEnrollment(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "enrollment not found")
		return
	}

	if enrollment.Status != "pending" {
		writeError(w, http.StatusBadRequest, "enrollment already processed")
		return
	}

	if err := s.store.RejectEnrollment(id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reject enrollment")
		return
	}

	logger.Info("rejected enrollment", "name", enrollment.Name)

	w.WriteHeader(http.StatusNoContent)
}

// validateScopes checks that all scopes reference installed backends/plugins
func (s *Server) validateScopes(scopes []string) error {
	if len(scopes) == 0 {
		return nil
	}

	// Combine configured backends and available plugins
	installedBackends := s.backends.List()
	availablePlugins := backend.ListAvailablePlugins()
	
	installedSet := make(map[string]bool)
	for _, name := range installedBackends {
		installedSet[name] = true
	}
	for _, name := range availablePlugins {
		installedSet[name] = true
		// Also add to list for error message
		found := false
		for _, b := range installedBackends {
			if b == name {
				found = true
				break
			}
		}
		if !found {
			installedBackends = append(installedBackends, name)
		}
	}

	for _, scope := range scopes {
		// Extract backend name (everything before first ':')
		backendName := scope
		if idx := strings.Index(scope, ":"); idx != -1 {
			backendName = scope[:idx]
		}

		// Wildcard scope allows all backends
		if backendName == "*" {
			continue
		}

		if !installedSet[backendName] {
			if len(installedBackends) == 0 {
				return fmt.Errorf("unknown backend %q in scope %q - no plugins installed", backendName, scope)
			}
			return fmt.Errorf("unknown backend %q in scope %q - available backends: %s", backendName, scope, strings.Join(installedBackends, ", "))
		}
	}

	return nil
}

// Helpers

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func generateToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// Fallback to less secure if crypto/rand fails
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> (i * 8))
		}
	}
	return "ckr_" + hex.EncodeToString(b)
}

func agentCanAccessBackend(agent *store.Agent, backendName string, repos []string, dopplerScopes []string, readOnly bool) bool {
	// Parse agent scopes
	var scopes []string
	json.Unmarshal([]byte(agent.Scopes), &scopes)

	// No scopes means access to all (for backwards compatibility during dev)
	if len(scopes) == 0 {
		return true
	}

	// For GitHub, check each repo against scopes
	if backendName == "github" {
		// Each requested repo must be allowed by at least one scope
		for _, repo := range repos {
			allowed := false
			for _, scope := range scopes {
				if backend.MatchesGitHubScope(scope, []string{repo}, readOnly) {
					allowed = true
					break
				}
			}
			if !allowed {
				return false
			}
		}
		// If no repos specified, check if any github scope exists
		if len(repos) == 0 {
			for _, scope := range scopes {
				if strings.HasPrefix(scope, "github:") {
					return true
				}
			}
			return false
		}
		return true
	}

	// For Doppler, check each project/config against scopes
	if backendName == "doppler" {
		// Each requested scope must be allowed
		for _, reqScope := range dopplerScopes {
			allowed := false
			for _, scope := range scopes {
				if backend.MatchesDopplerScope(scope, reqScope, readOnly) {
					allowed = true
					break
				}
			}
			if !allowed {
				return false
			}
		}
		// If no scopes specified, check if any doppler scope exists
		if len(dopplerScopes) == 0 {
			for _, scope := range scopes {
				if strings.HasPrefix(scope, "doppler:") {
					return true
				}
			}
			return false
		}
		return true
	}

	// For other backends (anthropic, etc), just check backend name
	for _, scope := range scopes {
		parts := strings.SplitN(scope, ":", 2)
		if parts[0] == backendName || parts[0] == "*" {
			return true
		}
	}

	return false
}

// handleListAllTokens lists all active tokens (admin)
func (s *Server) handleListAllTokens(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:tokens:read"); admin == nil {
		return
	}

	backend := r.URL.Query().Get("backend")
	agentName := r.URL.Query().Get("agent")

	creds, err := s.store.ListActiveCredentials()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tokens")
		return
	}

	// Filter and enrich with agent names
	type tokenInfo struct {
		ID        string    `json:"id"`
		AgentID   string    `json:"agent_id"`
		AgentName string    `json:"agent_name"`
		Backend   string    `json:"backend"`
		ExpiresAt time.Time `json:"expires_at"`
		CreatedAt time.Time `json:"created_at"`
	}

	results := []tokenInfo{}
	for _, c := range creds {
		// Filter by backend
		if backend != "" && c.Backend != backend {
			continue
		}

		// Get agent name
		agent, _ := s.store.GetAgentByID(c.AgentID)
		name := ""
		if agent != nil {
			name = agent.Name
			// Filter by agent name
			if agentName != "" && name != agentName {
				continue
			}
		}

		results = append(results, tokenInfo{
			ID:        c.ID,
			AgentID:   c.AgentID,
			AgentName: name,
			Backend:   c.Backend,
			ExpiresAt: c.ExpiresAt,
			CreatedAt: c.CreatedAt,
		})
	}

	json.NewEncoder(w).Encode(results)
}

// handleAdminRevokeToken revokes a token by ID (admin)
func (s *Server) handleAdminRevokeToken(w http.ResponseWriter, r *http.Request) {
	if admin := s.authenticateAdmin(w, r, "admin:tokens:write"); admin == nil {
		return
	}

	id := r.PathValue("id")

	cred, err := s.store.GetActiveCredential(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}

	// Revoke from backend if supported
	if cred.ExternalID != "" {
		s.revokeCredentialFromBackend(cred.Backend, cred.ExternalID)
	}

	if err := s.store.DeleteActiveCredential(id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// reapExpiredPolicyAgents removes agents whose policy-based lifetime has expired
func (s *Server) reapExpiredPolicyAgents() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			agents, err := s.store.GetExpiredPolicyAgents()
			if err != nil {
				logger.Error("error getting expired policy agents", "error", err)
				continue
			}
			for _, agent := range agents {
                logger.Info("unenrolling expired policy agent", "name", agent.Name, "policy", *agent.PolicyName, "expires_at", agent.ExpiresAt)
				if err := s.store.DeleteAgent(agent.ID); err != nil {
					logger.Error("error deleting expired agent", "name", agent.Name, "error", err)
				}
			}
		}
	}
}

// reapStaleEnrollments removes approved enrollments that haven't been picked up
// This prevents plaintext OIDC secrets from persisting indefinitely
func (s *Server) reapStaleEnrollments() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			// Clean up approved enrollments older than 1 hour
			count, err := s.store.CleanupApprovedEnrollments(1 * time.Hour)
			if err != nil {
				logger.Error("error cleaning up stale enrollments", "error", err)
				continue
			}
			if count > 0 {
				logger.Info("cleaned up stale approved enrollments", "count", count)
			}
		}
	}
}
