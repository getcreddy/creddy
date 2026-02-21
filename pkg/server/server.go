package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	// TODO: Add database, backends, etc.
}

func New() *Server {
	return &Server{}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /health", s.handleHealth)

	// Credential endpoints
	mux.HandleFunc("POST /v1/credentials/{backend}", s.handleGetCredential)

	// Agent management (admin)
	mux.HandleFunc("GET /v1/agents", s.handleListAgents)
	mux.HandleFunc("POST /v1/agents", s.handleCreateAgent)
	mux.HandleFunc("DELETE /v1/agents/{name}", s.handleRevokeAgent)

	// Active credentials
	mux.HandleFunc("GET /v1/active", s.handleListActive)
	mux.HandleFunc("DELETE /v1/active/{id}", s.handleRevokeCredential)

	return s.withMiddleware(mux)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log request
		// TODO: Proper logging

		// CORS for local dev
		w.Header().Set("Content-Type", "application/json")

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	backend := r.PathValue("backend")
	token := extractBearerToken(r)

	if token == "" {
		http.Error(w, `{"error": "missing authorization"}`, http.StatusUnauthorized)
		return
	}

	// TODO: Validate agent token
	// TODO: Check agent has permission for this backend
	// TODO: Generate credential from backend

	ttlStr := r.URL.Query().Get("ttl")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		ttl = 10 * time.Minute
	}

	// Placeholder response
	expiresAt := time.Now().Add(ttl)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"backend":    backend,
		"token":      "TODO_IMPLEMENT_" + backend + "_TOKEN",
		"expires_at": expiresAt,
		"ttl":        ttl.String(),
	})
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement
	json.NewEncoder(w).Encode([]interface{}{})
}

func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement
	http.Error(w, `{"error": "not implemented"}`, http.StatusNotImplemented)
}

func (s *Server) handleRevokeAgent(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement
	http.Error(w, `{"error": "not implemented"}`, http.StatusNotImplemented)
}

func (s *Server) handleListActive(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement
	json.NewEncoder(w).Encode([]interface{}{})
}

func (s *Server) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement
	http.Error(w, `{"error": "not implemented"}`, http.StatusNotImplemented)
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}
