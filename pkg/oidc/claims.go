package oidc

import (
	"crypto/rand"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// StandardClaims contains the standard OIDC claims
type StandardClaims struct {
	jwt.RegisteredClaims

	// Standard OIDC claims
	AuthTime int64  `json:"auth_time,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	ACR      string `json:"acr,omitempty"` // Authentication Context Class Reference
	AMR      string `json:"amr,omitempty"` // Authentication Methods References
}

// AgentClaims contains Creddy-specific agent identity claims
type AgentClaims struct {
	StandardClaims

	// Agent identity (Creddy extensions)
	AgentID   string   `json:"agent_id"`            // Creddy agent identifier
	AgentName string   `json:"agent_name"`          // Human-readable name
	Scopes    []string `json:"scopes,omitempty"`    // Granted scopes
	ClientID  string   `json:"client_id,omitempty"` // OIDC client_id (same as agent_id typically)

	// Task context (optional, for audit/attribution)
	TaskID          string `json:"task_id,omitempty"`          // Current task identifier
	TaskDescription string `json:"task_description,omitempty"` // Brief task description
	ParentAgentID   string `json:"parent_agent_id,omitempty"`  // If spawned by another agent

	// Constraints
	IPRestriction string `json:"ip_restriction,omitempty"` // Optional IP/CIDR restriction
}

// NewAgentClaims creates claims for an agent ID token
func NewAgentClaims(issuer, agentID, agentName string, scopes []string, audience []string, ttl time.Duration) *AgentClaims {
	now := time.Now()
	return &AgentClaims{
		StandardClaims: StandardClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   agentID,
				Audience:  audience,
				ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				ID:        generateJTI(),
			},
			AuthTime: now.Unix(),
		},
		AgentID:   agentID,
		AgentName: agentName,
		Scopes:    scopes,
		ClientID:  agentID,
	}
}

// NewAccessTokenClaims creates claims for an access token
func NewAccessTokenClaims(issuer, agentID string, scopes []string, ttl time.Duration) *AgentClaims {
	now := time.Now()
	return &AgentClaims{
		StandardClaims: StandardClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   agentID,
				ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				ID:        generateJTI(),
			},
		},
		AgentID:  agentID,
		Scopes:   scopes,
		ClientID: agentID,
	}
}

// WithTask adds task context to the claims
func (c *AgentClaims) WithTask(taskID, description string) *AgentClaims {
	c.TaskID = taskID
	c.TaskDescription = description
	return c
}

// WithParent adds parent agent context (for spawned agents)
func (c *AgentClaims) WithParent(parentAgentID string) *AgentClaims {
	c.ParentAgentID = parentAgentID
	return c
}

// WithIPRestriction adds IP restriction to the token
func (c *AgentClaims) WithIPRestriction(cidr string) *AgentClaims {
	c.IPRestriction = cidr
	return c
}

// generateJTI creates a unique JWT ID
func generateJTI() string {
	return "jti_" + randomString(16)
}

func randomString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	// Use crypto/rand for secure random
	randBytes := make([]byte, n)
	if _, err := rand.Read(randBytes); err != nil {
		// Fallback (shouldn't happen)
		for i := range b {
			b[i] = chars[time.Now().UnixNano()%int64(len(chars))]
		}
		return string(b)
	}
	for i := range b {
		b[i] = chars[int(randBytes[i])%len(chars)]
	}
	return string(b)
}
