package enrollment

import (
	"crypto/ed25519"
	"time"
)

// Status represents the status of an enrollment request
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
)

// Role represents a client's role
type Role string

const (
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Enrollment represents a pending or completed enrollment request
type Enrollment struct {
	ID                   string            `json:"enrollment_id"`
	Name                 string            `json:"name"`
	PublicKey            ed25519.PublicKey `json:"-"`
	PublicKeyEncoded     string            `json:"public_key,omitempty"`
	PublicKeyFingerprint string            `json:"public_key_fingerprint"`
	Metadata             map[string]string `json:"metadata,omitempty"`
	Status               Status            `json:"status"`
	RequestedAt          time.Time         `json:"requested_at"`
	ExpiresAt            time.Time         `json:"expires_at"`
	IPAddress            string            `json:"ip_address,omitempty"`

	// Set on approval
	ClientID   string `json:"client_id,omitempty"`
	Role       Role   `json:"role,omitempty"`
	ApprovedBy string `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	Note       string `json:"note,omitempty"`

	// Set on denial
	DeniedBy string `json:"denied_by,omitempty"`
	DeniedAt *time.Time `json:"denied_at,omitempty"`
	DenyReason string `json:"reason,omitempty"`
}

// Client represents a registered client
type Client struct {
	ID                   string            `json:"client_id"`
	Name                 string            `json:"name"`
	PublicKey            ed25519.PublicKey `json:"-"`
	PublicKeyEncoded     string            `json:"public_key,omitempty"`
	PublicKeyFingerprint string            `json:"public_key_fingerprint"`
	Role                 Role              `json:"role"`
	Metadata             map[string]string `json:"metadata,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
	LastSeen             *time.Time        `json:"last_seen,omitempty"`
	Status               string            `json:"status"` // active, revoked
	RevokedAt            *time.Time        `json:"revoked_at,omitempty"`
	RevokedBy            string            `json:"revoked_by,omitempty"`
	RevokeReason         string            `json:"revoke_reason,omitempty"`
}

// InitiateRequest is the request body for initiating enrollment
type InitiateRequest struct {
	PublicKey string            `json:"public_key"`
	Name      string            `json:"name"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// InitiateResponse is the response for initiating enrollment
type InitiateResponse struct {
	EnrollmentID   string `json:"enrollment_id"`
	Status         Status `json:"status"`
	ExpiresAt      string `json:"expires_at"`
	PollIntervalMs int    `json:"poll_interval_ms"`
}

// StatusResponse is the response for polling enrollment status
type StatusResponse struct {
	Status          Status `json:"status"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	ServerPublicKey string `json:"server_public_key,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// ApproveRequest is the request body for approving enrollment
type ApproveRequest struct {
	Role string `json:"role,omitempty"`
	Note string `json:"note,omitempty"`
}

// DenyRequest is the request body for denying enrollment
type DenyRequest struct {
	Reason string `json:"reason,omitempty"`
}

// Config holds enrollment configuration
type Config struct {
	PendingTTL  time.Duration
	AutoApprove []AutoApproveRule
}

// AutoApproveRule defines a rule for auto-approving enrollments
type AutoApproveRule struct {
	CIDR            string `yaml:"cidr,omitempty"`
	HostnamePattern string `yaml:"hostname_pattern,omitempty"`
}

// DefaultConfig returns the default enrollment configuration
func DefaultConfig() Config {
	return Config{
		PendingTTL: 5 * time.Minute,
	}
}
