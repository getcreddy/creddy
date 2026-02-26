package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// AuthRequest represents a pending auth request
type AuthRequest struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Status    string    `json:"status"` // pending, completed, expired
	Session   string    `json:"-"`      // The captured session (not exposed in JSON)
	OrgID     string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthRelayStore stores pending auth requests
type AuthRelayStore struct {
	mu       sync.RWMutex
	requests map[string]*AuthRequest
}

func NewAuthRelayStore() *AuthRelayStore {
	store := &AuthRelayStore{
		requests: make(map[string]*AuthRequest),
	}
	// Start cleanup goroutine
	go store.cleanupLoop()
	return store
}

func (s *AuthRelayStore) Create(provider string) *AuthRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateAuthID()
	req := &AuthRequest{
		ID:        id,
		Provider:  provider,
		Status:    "pending",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	s.requests[id] = req
	return req
}

func (s *AuthRelayStore) Get(id string) *AuthRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	req, ok := s.requests[id]
	if !ok {
		return nil
	}
	if time.Now().After(req.ExpiresAt) {
		return nil
	}
	return req
}

func (s *AuthRelayStore) Complete(id, session, orgID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok || time.Now().After(req.ExpiresAt) {
		return false
	}

	req.Status = "completed"
	req.Session = session
	req.OrgID = orgID
	return true
}

func (s *AuthRelayStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.requests, id)
}

func (s *AuthRelayStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, req := range s.requests {
			if now.After(req.ExpiresAt) {
				delete(s.requests, id)
			}
		}
		s.mu.Unlock()
	}
}

func generateAuthID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// RegisterAuthRelayRoutes adds auth relay endpoints
func (s *Server) RegisterAuthRelayRoutes(mux *http.ServeMux, store *AuthRelayStore) {
	// POST /v1/auth/{provider}/start - Start auth flow, get URL for user
	mux.HandleFunc("POST /v1/auth/{provider}/start", func(w http.ResponseWriter, r *http.Request) {
		provider := r.PathValue("provider")
		if provider == "" {
			writeError(w, http.StatusBadRequest, "missing provider")
			return
		}

		// Validate provider
		if provider != "anthropic" {
			writeError(w, http.StatusBadRequest, "unsupported provider: "+provider)
			return
		}

		req := store.Create(provider)

		// Build the URL for the user to run on their laptop
		// This should be the externally-accessible URL
		baseURL := r.Header.Get("X-Forwarded-Host")
		if baseURL == "" {
			baseURL = r.Host
		}
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}

		authURL := fmt.Sprintf("%s://%s/v1/auth/%s/%s", scheme, baseURL, provider, req.ID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         req.ID,
			"auth_url":   authURL,
			"expires_at": req.ExpiresAt,
			"command":    fmt.Sprintf("npx @creddy/auth %s", authURL),
		})
	})

	// GET /v1/auth/{provider}/{id} - Poll for auth completion
	mux.HandleFunc("GET /v1/auth/{provider}/{id}", func(w http.ResponseWriter, r *http.Request) {
		provider := r.PathValue("provider")
		id := r.PathValue("id")

		req := store.Get(id)
		if req == nil {
			writeError(w, http.StatusNotFound, "auth request not found or expired")
			return
		}

		if req.Provider != provider {
			writeError(w, http.StatusBadRequest, "provider mismatch")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		
		if req.Status == "completed" {
			// Return the session and clean up
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "completed",
				"session_key": req.Session,
				"org_id":      req.OrgID,
			})
			store.Delete(id)
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": req.Status,
			})
		}
	})

	// POST /v1/auth/{provider}/{id} - Receive session from @creddy/auth CLI
	mux.HandleFunc("POST /v1/auth/{provider}/{id}", func(w http.ResponseWriter, r *http.Request) {
		provider := r.PathValue("provider")
		id := r.PathValue("id")

		req := store.Get(id)
		if req == nil {
			writeError(w, http.StatusNotFound, "auth request not found or expired")
			return
		}

		if req.Provider != provider {
			writeError(w, http.StatusBadRequest, "provider mismatch")
			return
		}

		var payload struct {
			Provider   string `json:"provider"`
			SessionKey string `json:"sessionKey"`
			OrgID      string `json:"orgId"`
		}

		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}

		if payload.SessionKey == "" {
			writeError(w, http.StatusBadRequest, "missing sessionKey")
			return
		}

		if !store.Complete(id, payload.SessionKey, payload.OrgID) {
			writeError(w, http.StatusGone, "auth request expired")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})
	})
}
