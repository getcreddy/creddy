package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type PendingEnrollment struct {
	ID        string
	Name      string
	Secret    string // Client uses this to poll for approval
	Status    string // pending, approved, rejected
	Token     string // Set when approved (only returned once)
	Scopes    string
	AgentID   string // Set for amendments (existing agent requesting more scopes)
	CreatedAt time.Time
}

// IsAmendment returns true if this is an amendment request for an existing agent
func (p *PendingEnrollment) IsAmendment() bool {
	return p.AgentID != ""
}

func (s *Store) migrateEnroll() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS pending_enrollments (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			secret TEXT NOT NULL,
			status TEXT DEFAULT 'pending',
			token_hash TEXT,
			scopes TEXT DEFAULT '[]',
			agent_id TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_enrollments_secret ON pending_enrollments(secret)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_enrollments_status ON pending_enrollments(status)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return err
		}
	}
	
	// Add agent_id column if it doesn't exist (migration for existing DBs)
	s.db.Exec(`ALTER TABLE pending_enrollments ADD COLUMN agent_id TEXT`)
	
	return nil
}

// CreatePendingEnrollment creates a new enrollment request
func (s *Store) CreatePendingEnrollment(name, secret, scopes string) (*PendingEnrollment, error) {
	id := uuid.New().String()
	_, err := s.db.Exec(
		`INSERT INTO pending_enrollments (id, name, secret, status, scopes) VALUES (?, ?, ?, 'pending', ?)`,
		id, name, secret, scopes,
	)
	if err != nil {
		return nil, err
	}
	return s.GetPendingEnrollment(id)
}

// CreateScopeAmendment creates a request for additional scopes for an existing agent
func (s *Store) CreateScopeAmendment(agentID, agentName, scopes string) (*PendingEnrollment, error) {
	id := uuid.New().String()
	// No secret needed - agent already has a token
	_, err := s.db.Exec(
		`INSERT INTO pending_enrollments (id, name, secret, status, scopes, agent_id) VALUES (?, ?, '', 'pending', ?, ?)`,
		id, agentName, scopes, agentID,
	)
	if err != nil {
		return nil, err
	}
	return s.GetPendingEnrollment(id)
}

// GetPendingEnrollment gets an enrollment by ID
func (s *Store) GetPendingEnrollment(id string) (*PendingEnrollment, error) {
	var e PendingEnrollment
	var tokenHash, agentID sql.NullString
	err := s.db.QueryRow(
		`SELECT id, name, secret, status, token_hash, scopes, agent_id, created_at FROM pending_enrollments WHERE id = ?`,
		id,
	).Scan(&e.ID, &e.Name, &e.Secret, &e.Status, &tokenHash, &e.Scopes, &agentID, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	if tokenHash.Valid {
		e.Token = tokenHash.String
	}
	if agentID.Valid {
		e.AgentID = agentID.String
	}
	return &e, nil
}

// GetPendingEnrollmentBySecret gets an enrollment by its secret (for client polling)
func (s *Store) GetPendingEnrollmentBySecret(secret string) (*PendingEnrollment, error) {
	var e PendingEnrollment
	var tokenHash sql.NullString
	err := s.db.QueryRow(
		`SELECT id, name, secret, status, token_hash, scopes, created_at FROM pending_enrollments WHERE secret = ?`,
		secret,
	).Scan(&e.ID, &e.Name, &e.Secret, &e.Status, &tokenHash, &e.Scopes, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	if tokenHash.Valid {
		e.Token = tokenHash.String
	}
	return &e, nil
}

// ListPendingEnrollments lists all pending enrollment requests
func (s *Store) ListPendingEnrollments() ([]*PendingEnrollment, error) {
	rows, err := s.db.Query(
		`SELECT id, name, secret, status, scopes, agent_id, created_at FROM pending_enrollments WHERE status = 'pending' ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var enrollments []*PendingEnrollment
	for rows.Next() {
		var e PendingEnrollment
		var agentID sql.NullString
		if err := rows.Scan(&e.ID, &e.Name, &e.Secret, &e.Status, &e.Scopes, &agentID, &e.CreatedAt); err != nil {
			return nil, err
		}
		if agentID.Valid {
			e.AgentID = agentID.String
		}
		enrollments = append(enrollments, &e)
	}
	return enrollments, nil
}

// UpdateAgentScopes updates an agent's scopes (used for amendments)
func (s *Store) UpdateAgentScopes(agentID, scopes string) error {
	_, err := s.db.Exec(`UPDATE agents SET scopes = ? WHERE id = ?`, scopes, agentID)
	return err
}

// ApproveEnrollment approves an enrollment and creates the agent
func (s *Store) ApproveEnrollment(id string, tokenHash string, scopes string) error {
	_, err := s.db.Exec(
		`UPDATE pending_enrollments SET status = 'approved', token_hash = ?, scopes = ? WHERE id = ? AND status = 'pending'`,
		tokenHash, scopes, id,
	)
	return err
}

// RejectEnrollment rejects an enrollment request
func (s *Store) RejectEnrollment(id string) error {
	_, err := s.db.Exec(
		`UPDATE pending_enrollments SET status = 'rejected' WHERE id = ? AND status = 'pending'`,
		id,
	)
	return err
}

// DeletePendingEnrollment deletes an enrollment request
func (s *Store) DeletePendingEnrollment(id string) error {
	_, err := s.db.Exec(`DELETE FROM pending_enrollments WHERE id = ?`, id)
	return err
}

// CleanupOldEnrollments removes enrollments older than the given duration
func (s *Store) CleanupOldEnrollments(maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge)
	result, err := s.db.Exec(`DELETE FROM pending_enrollments WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
