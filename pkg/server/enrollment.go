package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/getcreddy/creddy/pkg/client"
	"github.com/getcreddy/creddy/pkg/enrollment"
)

// RegisterEnrollmentRoutes adds enrollment endpoints to the server
func (s *Server) RegisterEnrollmentRoutes(mux *http.ServeMux) {
	// Public endpoints (no auth)
	mux.HandleFunc("POST /api/v1/enrollments", s.handleInitiateEnrollment)
	mux.HandleFunc("GET /api/v1/enrollments/{id}/status", s.handleEnrollmentStatus)
	
	// Admin endpoints
	mux.HandleFunc("GET /api/v1/admin/enrollments", s.handleListEnrollments)
	mux.HandleFunc("POST /api/v1/admin/enrollments/{id}/approve", s.handleApproveEnrollment)
	mux.HandleFunc("POST /api/v1/admin/enrollments/{id}/deny", s.handleDenyEnrollment)
	mux.HandleFunc("GET /api/v1/admin/clients", s.handleListClients)
	mux.HandleFunc("DELETE /api/v1/admin/clients/{id}", s.handleRevokeClient)
}

func (s *Server) handleInitiateEnrollment(w http.ResponseWriter, r *http.Request) {
	var req enrollment.InitiateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "public_key is required")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	
	// Decode the public key
	pubKey, err := client.DecodePublicKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid public_key: "+err.Error())
		return
	}
	
	// Get client IP
	ipAddress := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ipAddress = xff
	}
	
	// Create enrollment with 5 minute TTL
	expiresAt := time.Now().Add(5 * time.Minute)
	
	enr, err := s.store.CreateEnrollment(req.Name, pubKey, req.Metadata, ipAddress, expiresAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create enrollment: "+err.Error())
		return
	}
	
	// TODO: Send notification to Slack/webhook
	
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(enrollment.InitiateResponse{
		EnrollmentID:   enr.ID,
		Status:         enr.Status,
		ExpiresAt:      enr.ExpiresAt.Format(time.RFC3339),
		PollIntervalMs: 2000,
	})
}

func (s *Server) handleEnrollmentStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	
	enr, err := s.store.GetEnrollment(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "enrollment not found")
		return
	}
	
	// Check if expired
	if enr.Status == enrollment.StatusPending && time.Now().After(enr.ExpiresAt) {
		json.NewEncoder(w).Encode(enrollment.StatusResponse{
			Status: enrollment.StatusExpired,
		})
		return
	}
	
	resp := enrollment.StatusResponse{
		Status: enr.Status,
	}
	
	switch enr.Status {
	case enrollment.StatusPending:
		resp.ExpiresAt = enr.ExpiresAt.Format(time.RFC3339)
	case enrollment.StatusApproved:
		resp.ClientID = enr.ClientID
		// TODO: return server public key for mutual verification
	case enrollment.StatusDenied:
		resp.Reason = enr.DenyReason
	}
	
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleListEnrollments(w http.ResponseWriter, r *http.Request) {
	status := enrollment.Status(r.URL.Query().Get("status"))
	
	enrollments, err := s.store.ListEnrollments(status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list enrollments")
		return
	}
	
	// Convert to response format
	results := make([]map[string]interface{}, len(enrollments))
	for i, e := range enrollments {
		results[i] = map[string]interface{}{
			"enrollment_id":          e.ID,
			"name":                   e.Name,
			"public_key_fingerprint": e.PublicKeyFingerprint,
			"metadata":               e.Metadata,
			"status":                 e.Status,
			"ip_address":             e.IPAddress,
			"requested_at":           e.RequestedAt,
			"expires_at":             e.ExpiresAt,
		}
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{"enrollments": results})
}

func (s *Server) handleApproveEnrollment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	
	var req enrollment.ApproveRequest
	json.NewDecoder(r.Body).Decode(&req) // Optional body
	
	// Get enrollment
	enr, err := s.store.GetEnrollment(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "enrollment not found")
		return
	}
	
	if enr.Status != enrollment.StatusPending {
		writeError(w, http.StatusBadRequest, "enrollment is not pending")
		return
	}
	
	if time.Now().After(enr.ExpiresAt) {
		writeError(w, http.StatusGone, "enrollment has expired")
		return
	}
	
	// TODO: Get approver identity from authenticated request
	approvedBy := "admin"
	
	role := req.Role
	if role == "" {
		role = string(enrollment.RoleOperator)
	}
	
	client, err := s.store.ApproveEnrollment(id, approvedBy, role, req.Note)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to approve enrollment: "+err.Error())
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"client_id": client.ID,
		"status":    "approved",
	})
}

func (s *Server) handleDenyEnrollment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	
	var req enrollment.DenyRequest
	json.NewDecoder(r.Body).Decode(&req) // Optional body
	
	// Get enrollment
	enr, err := s.store.GetEnrollment(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "enrollment not found")
		return
	}
	
	if enr.Status != enrollment.StatusPending {
		writeError(w, http.StatusBadRequest, "enrollment is not pending")
		return
	}
	
	// TODO: Get denier identity from authenticated request
	deniedBy := "admin"
	
	if err := s.store.DenyEnrollment(id, deniedBy, req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to deny enrollment: "+err.Error())
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "denied",
	})
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	
	clients, err := s.store.ListClients(status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list clients")
		return
	}
	
	results := make([]map[string]interface{}, len(clients))
	for i, c := range clients {
		result := map[string]interface{}{
			"client_id":              c.ID,
			"name":                   c.Name,
			"role":                   c.Role,
			"public_key_fingerprint": c.PublicKeyFingerprint,
			"created_at":             c.CreatedAt,
			"status":                 c.Status,
		}
		if c.LastSeen != nil {
			result["last_seen"] = c.LastSeen
		}
		results[i] = result
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{"clients": results})
}

func (s *Server) handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	
	client, err := s.store.GetClient(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "client not found")
		return
	}
	
	if client.Status == "revoked" {
		writeError(w, http.StatusBadRequest, "client is already revoked")
		return
	}
	
	// TODO: Get revoker identity and reason from request
	revokedBy := "admin"
	reason := ""
	
	if err := s.store.RevokeClient(id, revokedBy, reason); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke client: "+err.Error())
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"client_id":  id,
		"status":     "revoked",
		"revoked_at": time.Now(),
	})
}
