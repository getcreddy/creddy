package store

import (
	"time"
)

type AuditEvent struct {
	ID        string
	Timestamp time.Time
	AgentID   string
	AgentName string
	Action    string // token_issued, token_revoked, agent_created, agent_revoked, key_accessed
	Backend   string // github, aws, etc. (optional)
	Details   string // JSON blob with extra context
	TokenID   string // Reference to active_credential if applicable
	IPAddress string
}

func (s *Store) migrateAudit() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			agent_id TEXT,
			agent_name TEXT,
			action TEXT NOT NULL,
			backend TEXT,
			details TEXT,
			token_id TEXT,
			ip_address TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) LogAuditEvent(agentID, agentName, action, backend, details, tokenID, ipAddress string) error {
	id := generateID()
	_, err := s.db.Exec(
		`INSERT INTO audit_log (id, agent_id, agent_name, action, backend, details, token_id, ip_address) 
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, agentID, agentName, action, backend, details, tokenID, ipAddress,
	)
	return err
}

func (s *Store) GetAuditLog(limit int, agentID string, action string) ([]*AuditEvent, error) {
	query := `SELECT id, timestamp, agent_id, agent_name, action, backend, details, token_id, ip_address 
	          FROM audit_log WHERE 1=1`
	args := []interface{}{}

	if agentID != "" {
		query += " AND agent_id = ?"
		args = append(args, agentID)
	}
	if action != "" {
		query += " AND action = ?"
		args = append(args, action)
	}

	query += " ORDER BY timestamp DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*AuditEvent
	for rows.Next() {
		var e AuditEvent
		var backend, details, tokenID, ipAddress *string
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.AgentID, &e.AgentName, &e.Action, &backend, &details, &tokenID, &ipAddress); err != nil {
			return nil, err
		}
		if backend != nil {
			e.Backend = *backend
		}
		if details != nil {
			e.Details = *details
		}
		if tokenID != nil {
			e.TokenID = *tokenID
		}
		if ipAddress != nil {
			e.IPAddress = *ipAddress
		}
		events = append(events, &e)
	}
	return events, nil
}

// GetAuditLogByTimeRange returns audit events within a time range
func (s *Store) GetAuditLogByTimeRange(start, end time.Time, limit int) ([]*AuditEvent, error) {
	query := `SELECT id, timestamp, agent_id, agent_name, action, backend, details, token_id, ip_address 
	          FROM audit_log 
	          WHERE timestamp >= ? AND timestamp <= ?
	          ORDER BY timestamp DESC`
	args := []interface{}{start, end}

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*AuditEvent
	for rows.Next() {
		var e AuditEvent
		var backend, details, tokenID, ipAddress *string
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.AgentID, &e.AgentName, &e.Action, &backend, &details, &tokenID, &ipAddress); err != nil {
			return nil, err
		}
		if backend != nil {
			e.Backend = *backend
		}
		if details != nil {
			e.Details = *details
		}
		if tokenID != nil {
			e.TokenID = *tokenID
		}
		if ipAddress != nil {
			e.IPAddress = *ipAddress
		}
		events = append(events, &e)
	}
	return events, nil
}
