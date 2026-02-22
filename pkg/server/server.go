package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/marccampbell/creddy/pkg/backend"
	"github.com/marccampbell/creddy/pkg/signing"
	"github.com/marccampbell/creddy/pkg/store"
)

type Server struct {
	store                *store.Store
	backends             *backend.Manager
	domain               string
	agentInactivityLimit time.Duration
	ctx                  context.Context
	cancel               context.CancelFunc
}

type Config struct {
	DBPath               string
	Domain               string        // Domain for agent email addresses (e.g., creddy.dev)
	AgentInactivityLimit time.Duration // Auto-unenroll agents inactive for this long (0 = disabled)
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

	s := &Server{
		store:                st,
		backends:             backend.NewManager(),
		domain:               domain,
		agentInactivityLimit: cfg.AgentInactivityLimit,
		ctx:                  ctx,
		cancel:               cancel,
	}

	// Load backends from database
	if err := s.loadBackends(); err != nil {
		log.Printf("Warning: failed to load backends: %v", err)
	}

	// Start the reapers
	go s.reapExpiredCredentials()
	if s.agentInactivityLimit > 0 {
		go s.reapInactiveAgents()
	}

	return s, nil
}

func (s *Server) loadBackends() error {
	backends, err := s.store.ListBackends()
	if err != nil {
		return err
	}

	for _, b := range backends {
		backend, err := backend.LoadFromConfig(b.Type, b.Config)
		if err != nil {
			log.Printf("Warning: failed to load backend %s: %v", b.Name, err)
			continue
		}
		s.backends.Register(b.Name, backend)
		log.Printf("Loaded backend: %s (%s)", b.Name, b.Type)
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
			deleted, err := s.store.DeleteExpiredCredentials()
			if err != nil {
				log.Printf("Error reaping expired credentials: %v", err)
			} else if deleted > 0 {
				log.Printf("Reaped %d expired credentials", deleted)
			}
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
				log.Printf("Error reaping inactive agents: %v", err)
			} else if deleted > 0 {
				log.Printf("Reaped %d inactive agents (no activity in %v)", deleted, s.agentInactivityLimit)
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

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /health", s.handleHealth)

	// Enrollment (no auth - client initiates pairing)
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /v1/enroll/status", s.handleEnrollStatus)

	// Scope requests (agent auth required)
	mux.HandleFunc("POST /v1/request", s.handleScopeRequest)

	// Credential endpoints (agent auth required)
	mux.HandleFunc("POST /v1/credentials/{backend}", s.handleGetCredential)

	// Agent self-service
	mux.HandleFunc("GET /v1/active", s.handleListActive)
	mux.HandleFunc("DELETE /v1/active/{id}", s.handleRevokeCredential)
	mux.HandleFunc("GET /v1/signing-key", s.handleGetSigningKey)

	// Admin endpoints (no auth for now - bind to localhost/tailnet only)
	mux.HandleFunc("GET /v1/admin/agents", s.handleListAgents)
	mux.HandleFunc("POST /v1/admin/agents", s.handleCreateAgent)
	mux.HandleFunc("DELETE /v1/admin/agents/{name}", s.handleDeleteAgent)
	mux.HandleFunc("GET /v1/admin/backends", s.handleListBackends)
	mux.HandleFunc("POST /v1/admin/backends", s.handleCreateBackend)
	mux.HandleFunc("DELETE /v1/admin/backends/{name}", s.handleDeleteBackend)
	mux.HandleFunc("GET /v1/admin/audit", s.handleGetAuditLog)
	mux.HandleFunc("GET /v1/admin/keys", s.handleListPublicKeys)
	mux.HandleFunc("GET /v1/admin/pending", s.handleListPending)
	mux.HandleFunc("POST /v1/admin/pending/{id}/approve", s.handleApprovePending)
	mux.HandleFunc("POST /v1/admin/pending/{id}/reject", s.handleRejectPending)

	return s.withMiddleware(mux)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	backendName := r.PathValue("backend")
	token := extractBearerToken(r)

	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return
	}

	// Validate agent token
	agent, err := s.store.GetAgentByTokenHash(hashToken(token))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid agent token")
		return
	}

	// Parse agent scopes
	var agentScopes []string
	json.Unmarshal([]byte(agent.Scopes), &agentScopes)

	// Parse repos from query params (can be specified multiple times)
	// If no repos specified, use all repos from agent's scopes
	repos := r.URL.Query()["repo"]
	readOnly := r.URL.Query().Get("read_only") == "true"

	if len(repos) == 0 && backendName == "github" {
		// Extract repos from agent's scopes
		repos, _ = backend.ExtractReposFromScopes(agentScopes)
	}

	// Check agent has permission for this backend and repos
	if !agentCanAccessBackend(agent, backendName, repos, readOnly) {
		writeError(w, http.StatusForbidden, "agent not authorized for this backend/repos")
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
	// Cap at 1 hour for safety
	if ttl > time.Hour {
		ttl = time.Hour
	}

	// Generate credential
	cred, err := b.GetToken(backend.TokenRequest{
		Repos:    repos,
		ReadOnly: readOnly,
	})
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
	activeCred, err := s.store.CreateActiveCredential(agent.ID, backendName, hashToken(cred.Value), scopes, expiresAt)
	if err != nil {
		log.Printf("Warning: failed to record credential: %v", err)
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

	agent, err := s.store.GetAgentByTokenHash(hashToken(token))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid agent token")
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

	agent, err := s.store.GetAgentByTokenHash(hashToken(token))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid agent token")
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
	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Generate token
	token := generateToken()
	scopesJSON, _ := json.Marshal(req.Scopes)

	agent, err := s.store.CreateAgent(req.Name, hashToken(token), string(scopesJSON))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create agent: "+err.Error())
		return
	}

	// Generate GPG signing key for the agent
	keyPair, err := signing.GenerateKeyPair(req.Name, s.domain)
	if err != nil {
		log.Printf("Warning: failed to generate signing key for agent %s: %v", req.Name, err)
	} else {
		_, err = s.store.CreateSigningKey(agent.ID, keyPair.KeyID, keyPair.PublicKey, keyPair.PrivateKey, keyPair.Email, keyPair.Name)
		if err != nil {
			log.Printf("Warning: failed to store signing key for agent %s: %v", req.Name, err)
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

	if keyPair != nil {
		response["signing_key_id"] = keyPair.KeyID
		response["signing_email"] = keyPair.Email
	}

	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := s.store.DeleteAgent(name); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete agent")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListBackends(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleCreateBackend(w http.ResponseWriter, r *http.Request) {
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
	name := r.PathValue("name")

	if err := s.store.DeleteBackend(name); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete backend")
		return
	}

	// TODO: remove from s.backends manager

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetSigningKey(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return
	}

	agent, err := s.store.GetAgentByTokenHash(hashToken(token))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid agent token")
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

func (s *Server) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
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

// Enrollment endpoints

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
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

	// Generate a secret for the client to poll with
	secret := generateToken()
	scopesJSON, _ := json.Marshal(req.Scopes)

	enrollment, err := s.store.CreatePendingEnrollment(req.Name, secret, string(scopesJSON))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create enrollment: "+err.Error())
		return
	}

	log.Printf("New enrollment request: %s (%s) scopes=%v", req.Name, enrollment.ID, req.Scopes)

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

	agent, err := s.store.GetAgentByTokenHash(hashToken(token))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid agent token")
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

	scopesJSON, _ := json.Marshal(req.Scopes)
	amendment, err := s.store.CreateScopeAmendment(agent.ID, agent.Name, string(scopesJSON))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create scope request: "+err.Error())
		return
	}

	log.Printf("Scope request from %s: %v", agent.Name, req.Scopes)

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

	// If approved, return the token (only works once - client should save it)
	if enrollment.Status == "approved" && enrollment.Token != "" {
		// Get the agent that was created
		agent, err := s.store.GetAgentByTokenHash(enrollment.Token)
		if err == nil {
			// Generate the actual token to return (we stored the hash)
			// Actually, we need to store the token temporarily for pickup
			// Let's return it from a separate field we'll add
		}
		_ = agent // TODO: include agent info

		// For now, the token was stored as hash - we need to change approach
		// Store the actual token encrypted or in a pickup field
		response["token"] = enrollment.Token
		response["scopes"] = enrollment.Scopes

		// Delete the enrollment after token pickup
		s.store.DeletePendingEnrollment(enrollment.ID)
	}

	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleListPending(w http.ResponseWriter, r *http.Request) {
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
		s.store.ApproveEnrollment(id, "", string(mergedJSON))

		// Audit log
		details, _ := json.Marshal(map[string]interface{}{
			"added_scopes": newScopes,
			"final_scopes": mergedScopes,
		})
		s.store.LogAuditEvent(agent.ID, agent.Name, "scopes_amended", "", string(details), "", r.RemoteAddr)

		log.Printf("Approved scope amendment for %s: added %v", agent.Name, newScopes)

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
		log.Printf("Warning: failed to generate signing key for agent %s: %v", enrollment.Name, err)
	} else {
		_, err = s.store.CreateSigningKey(agent.ID, keyPair.KeyID, keyPair.PublicKey, keyPair.PrivateKey, keyPair.Email, keyPair.Name)
		if err != nil {
			log.Printf("Warning: failed to store signing key for agent %s: %v", enrollment.Name, err)
		}
	}

	// Update enrollment with the token (not hashed - client needs to pick it up)
	s.store.ApproveEnrollment(id, token, scopesJSON)

	// Audit log
	details, _ := json.Marshal(map[string]interface{}{"scopes": scopesJSON, "enrollment_id": id})
	s.store.LogAuditEvent(agent.ID, agent.Name, "agent_enrolled", "", string(details), "", r.RemoteAddr)

	log.Printf("Approved enrollment: %s -> agent %s", enrollment.Name, agent.ID)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":       agent.ID,
		"name":     agent.Name,
		"type":     "enroll",
		"approved": true,
	})
}

func (s *Server) handleRejectPending(w http.ResponseWriter, r *http.Request) {
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

	log.Printf("Rejected enrollment: %s", enrollment.Name)

	w.WriteHeader(http.StatusNoContent)
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

func agentCanAccessBackend(agent *store.Agent, backendName string, repos []string, readOnly bool) bool {
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

	// For other backends, just check backend name
	for _, scope := range scopes {
		parts := strings.SplitN(scope, ":", 2)
		if parts[0] == backendName || parts[0] == "*" {
			return true
		}
	}

	return false
}
