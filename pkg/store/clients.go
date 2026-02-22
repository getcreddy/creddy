package store

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/getcreddy/creddy/pkg/client"
	"github.com/getcreddy/creddy/pkg/enrollment"
	"github.com/google/uuid"
)

func (s *Store) migrateClients() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			public_key BLOB NOT NULL,
			public_key_fingerprint TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'operator',
			metadata TEXT DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME,
			revoked_at DATETIME,
			revoked_by TEXT,
			revoke_reason TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_clients_fingerprint ON clients(public_key_fingerprint)`,
		`CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status)`,
		`CREATE TABLE IF NOT EXISTS enrollments (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			public_key BLOB NOT NULL,
			public_key_fingerprint TEXT NOT NULL,
			metadata TEXT DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'pending',
			ip_address TEXT,
			requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			client_id TEXT,
			role TEXT,
			approved_by TEXT,
			approved_at DATETIME,
			note TEXT,
			denied_by TEXT,
			denied_at DATETIME,
			deny_reason TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_enrollments_status ON enrollments(status)`,
		`CREATE INDEX IF NOT EXISTS idx_enrollments_expires ON enrollments(expires_at)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return err
		}
	}
	return nil
}

// Enrollment operations

func (s *Store) CreateEnrollment(name string, publicKey ed25519.PublicKey, metadata map[string]string, ipAddress string, expiresAt time.Time) (*enrollment.Enrollment, error) {
	id := "enr_" + uuid.New().String()[:8]
	fingerprint := client.Fingerprint(publicKey)
	
	metadataJSON, _ := json.Marshal(metadata)
	
	_, err := s.db.Exec(
		`INSERT INTO enrollments (id, name, public_key, public_key_fingerprint, metadata, ip_address, expires_at) 
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, name, []byte(publicKey), fingerprint, string(metadataJSON), ipAddress, expiresAt,
	)
	if err != nil {
		return nil, err
	}
	
	return s.GetEnrollment(id)
}

func (s *Store) GetEnrollment(id string) (*enrollment.Enrollment, error) {
	var e enrollment.Enrollment
	var publicKeyBytes []byte
	var metadataJSON string
	var approvedAt, deniedAt sql.NullTime
	var clientID, role, approvedBy, note, deniedBy, denyReason sql.NullString
	
	err := s.db.QueryRow(
		`SELECT id, name, public_key, public_key_fingerprint, metadata, status, ip_address,
		        requested_at, expires_at, client_id, role, approved_by, approved_at, note,
		        denied_by, denied_at, deny_reason
		 FROM enrollments WHERE id = ?`,
		id,
	).Scan(&e.ID, &e.Name, &publicKeyBytes, &e.PublicKeyFingerprint, &metadataJSON, &e.Status,
		&e.IPAddress, &e.RequestedAt, &e.ExpiresAt, &clientID, &role, &approvedBy, &approvedAt,
		&note, &deniedBy, &deniedAt, &denyReason)
	if err != nil {
		return nil, err
	}
	
	e.PublicKey = ed25519.PublicKey(publicKeyBytes)
	json.Unmarshal([]byte(metadataJSON), &e.Metadata)
	
	if clientID.Valid {
		e.ClientID = clientID.String
	}
	if role.Valid {
		e.Role = enrollment.Role(role.String)
	}
	if approvedBy.Valid {
		e.ApprovedBy = approvedBy.String
	}
	if approvedAt.Valid {
		e.ApprovedAt = &approvedAt.Time
	}
	if note.Valid {
		e.Note = note.String
	}
	if deniedBy.Valid {
		e.DeniedBy = deniedBy.String
	}
	if deniedAt.Valid {
		e.DeniedAt = &deniedAt.Time
	}
	if denyReason.Valid {
		e.DenyReason = denyReason.String
	}
	
	return &e, nil
}

func (s *Store) ListEnrollments(status enrollment.Status) ([]*enrollment.Enrollment, error) {
	query := `SELECT id, name, public_key, public_key_fingerprint, metadata, status, ip_address,
	                 requested_at, expires_at, client_id, role, approved_by, approved_at, note,
	                 denied_by, denied_at, deny_reason
	          FROM enrollments`
	
	var args []interface{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, string(status))
	}
	query += ` ORDER BY requested_at DESC`
	
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var enrollments []*enrollment.Enrollment
	for rows.Next() {
		var e enrollment.Enrollment
		var publicKeyBytes []byte
		var metadataJSON string
		var approvedAt, deniedAt sql.NullTime
		var clientID, role, approvedBy, note, deniedBy, denyReason sql.NullString
		
		if err := rows.Scan(&e.ID, &e.Name, &publicKeyBytes, &e.PublicKeyFingerprint, &metadataJSON,
			&e.Status, &e.IPAddress, &e.RequestedAt, &e.ExpiresAt, &clientID, &role, &approvedBy,
			&approvedAt, &note, &deniedBy, &deniedAt, &denyReason); err != nil {
			return nil, err
		}
		
		e.PublicKey = ed25519.PublicKey(publicKeyBytes)
		json.Unmarshal([]byte(metadataJSON), &e.Metadata)
		
		if clientID.Valid {
			e.ClientID = clientID.String
		}
		if role.Valid {
			e.Role = enrollment.Role(role.String)
		}
		if approvedBy.Valid {
			e.ApprovedBy = approvedBy.String
		}
		if approvedAt.Valid {
			e.ApprovedAt = &approvedAt.Time
		}
		if note.Valid {
			e.Note = note.String
		}
		if deniedBy.Valid {
			e.DeniedBy = deniedBy.String
		}
		if deniedAt.Valid {
			e.DeniedAt = &deniedAt.Time
		}
		if denyReason.Valid {
			e.DenyReason = denyReason.String
		}
		
		enrollments = append(enrollments, &e)
	}
	
	return enrollments, nil
}

func (s *Store) ApproveEnrollment(id, approvedBy, role, note string) (*enrollment.Client, error) {
	// Get the enrollment
	e, err := s.GetEnrollment(id)
	if err != nil {
		return nil, err
	}
	
	// Create the client
	clientID := "cli_" + uuid.New().String()[:8]
	if role == "" {
		role = string(enrollment.RoleOperator)
	}
	
	metadataJSON, _ := json.Marshal(e.Metadata)
	now := time.Now()
	
	_, err = s.db.Exec(
		`INSERT INTO clients (id, name, public_key, public_key_fingerprint, role, metadata, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		clientID, e.Name, []byte(e.PublicKey), e.PublicKeyFingerprint, role, string(metadataJSON), now,
	)
	if err != nil {
		return nil, err
	}
	
	// Update the enrollment
	_, err = s.db.Exec(
		`UPDATE enrollments SET status = ?, client_id = ?, role = ?, approved_by = ?, approved_at = ?, note = ?
		 WHERE id = ?`,
		string(enrollment.StatusApproved), clientID, role, approvedBy, now, note, id,
	)
	if err != nil {
		return nil, err
	}
	
	return s.GetClient(clientID)
}

func (s *Store) DenyEnrollment(id, deniedBy, reason string) error {
	now := time.Now()
	_, err := s.db.Exec(
		`UPDATE enrollments SET status = ?, denied_by = ?, denied_at = ?, deny_reason = ?
		 WHERE id = ?`,
		string(enrollment.StatusDenied), deniedBy, now, reason, id,
	)
	return err
}

func (s *Store) DeleteExpiredEnrollments() (int64, error) {
	result, err := s.db.Exec(
		`DELETE FROM enrollments WHERE status = 'pending' AND expires_at <= CURRENT_TIMESTAMP`,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Client operations

func (s *Store) GetClient(id string) (*enrollment.Client, error) {
	var c enrollment.Client
	var publicKeyBytes []byte
	var metadataJSON string
	var lastSeen, revokedAt sql.NullTime
	var revokedBy, revokeReason sql.NullString
	
	err := s.db.QueryRow(
		`SELECT id, name, public_key, public_key_fingerprint, role, metadata, status,
		        created_at, last_seen, revoked_at, revoked_by, revoke_reason
		 FROM clients WHERE id = ?`,
		id,
	).Scan(&c.ID, &c.Name, &publicKeyBytes, &c.PublicKeyFingerprint, &c.Role, &metadataJSON,
		&c.Status, &c.CreatedAt, &lastSeen, &revokedAt, &revokedBy, &revokeReason)
	if err != nil {
		return nil, err
	}
	
	c.PublicKey = ed25519.PublicKey(publicKeyBytes)
	json.Unmarshal([]byte(metadataJSON), &c.Metadata)
	
	if lastSeen.Valid {
		c.LastSeen = &lastSeen.Time
	}
	if revokedAt.Valid {
		c.RevokedAt = &revokedAt.Time
	}
	if revokedBy.Valid {
		c.RevokedBy = revokedBy.String
	}
	if revokeReason.Valid {
		c.RevokeReason = revokeReason.String
	}
	
	return &c, nil
}

func (s *Store) GetClientByFingerprint(fingerprint string) (*enrollment.Client, error) {
	var c enrollment.Client
	var publicKeyBytes []byte
	var metadataJSON string
	var lastSeen, revokedAt sql.NullTime
	var revokedBy, revokeReason sql.NullString
	
	err := s.db.QueryRow(
		`SELECT id, name, public_key, public_key_fingerprint, role, metadata, status,
		        created_at, last_seen, revoked_at, revoked_by, revoke_reason
		 FROM clients WHERE public_key_fingerprint = ?`,
		fingerprint,
	).Scan(&c.ID, &c.Name, &publicKeyBytes, &c.PublicKeyFingerprint, &c.Role, &metadataJSON,
		&c.Status, &c.CreatedAt, &lastSeen, &revokedAt, &revokedBy, &revokeReason)
	if err != nil {
		return nil, err
	}
	
	c.PublicKey = ed25519.PublicKey(publicKeyBytes)
	json.Unmarshal([]byte(metadataJSON), &c.Metadata)
	
	if lastSeen.Valid {
		c.LastSeen = &lastSeen.Time
	}
	if revokedAt.Valid {
		c.RevokedAt = &revokedAt.Time
	}
	if revokedBy.Valid {
		c.RevokedBy = revokedBy.String
	}
	if revokeReason.Valid {
		c.RevokeReason = revokeReason.String
	}
	
	return &c, nil
}

func (s *Store) ListClients(status string) ([]*enrollment.Client, error) {
	query := `SELECT id, name, public_key, public_key_fingerprint, role, metadata, status,
	                 created_at, last_seen, revoked_at, revoked_by, revoke_reason
	          FROM clients`
	
	var args []interface{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY name`
	
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var clients []*enrollment.Client
	for rows.Next() {
		var c enrollment.Client
		var publicKeyBytes []byte
		var metadataJSON string
		var lastSeen, revokedAt sql.NullTime
		var revokedBy, revokeReason sql.NullString
		
		if err := rows.Scan(&c.ID, &c.Name, &publicKeyBytes, &c.PublicKeyFingerprint, &c.Role,
			&metadataJSON, &c.Status, &c.CreatedAt, &lastSeen, &revokedAt, &revokedBy,
			&revokeReason); err != nil {
			return nil, err
		}
		
		c.PublicKey = ed25519.PublicKey(publicKeyBytes)
		json.Unmarshal([]byte(metadataJSON), &c.Metadata)
		
		if lastSeen.Valid {
			c.LastSeen = &lastSeen.Time
		}
		if revokedAt.Valid {
			c.RevokedAt = &revokedAt.Time
		}
		if revokedBy.Valid {
			c.RevokedBy = revokedBy.String
		}
		if revokeReason.Valid {
			c.RevokeReason = revokeReason.String
		}
		
		clients = append(clients, &c)
	}
	
	return clients, nil
}

func (s *Store) UpdateClientLastSeen(id string) error {
	_, err := s.db.Exec(`UPDATE clients SET last_seen = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return err
}

func (s *Store) RevokeClient(id, revokedBy, reason string) error {
	now := time.Now()
	_, err := s.db.Exec(
		`UPDATE clients SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoke_reason = ?
		 WHERE id = ?`,
		now, revokedBy, reason, id,
	)
	return err
}
