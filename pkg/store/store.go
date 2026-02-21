package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Agent struct {
	ID        string
	Name      string
	TokenHash string
	Scopes    string // JSON array
	CreatedAt time.Time
	LastUsed  *time.Time
}

type Backend struct {
	ID         string
	Type       string
	Name       string
	Config     string // JSON blob
	CreatedAt  time.Time
}

type ActiveCredential struct {
	ID        string
	AgentID   string
	AgentName string
	Backend   string
	TokenHash string // We don't store the actual token
	Scopes    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Store) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS agents (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			token_hash TEXT NOT NULL,
			scopes TEXT DEFAULT '[]',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_used DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS backends (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			name TEXT UNIQUE NOT NULL,
			config TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS active_credentials (
			id TEXT PRIMARY KEY,
			agent_id TEXT NOT NULL,
			backend TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			scopes TEXT DEFAULT '[]',
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (agent_id) REFERENCES agents(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_active_credentials_expires ON active_credentials(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_active_credentials_agent ON active_credentials(agent_id)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return err
		}
	}

	// Additional migrations
	if err := s.migrateAudit(); err != nil {
		return err
	}
	if err := s.migrateKeys(); err != nil {
		return err
	}

	return nil
}

func generateID() string {
	return uuid.New().String()
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Agent operations

func (s *Store) CreateAgent(name, tokenHash, scopes string) (*Agent, error) {
	id := uuid.New().String()
	_, err := s.db.Exec(
		`INSERT INTO agents (id, name, token_hash, scopes) VALUES (?, ?, ?, ?)`,
		id, name, tokenHash, scopes,
	)
	if err != nil {
		return nil, err
	}

	return s.GetAgentByID(id)
}

func (s *Store) GetAgentByID(id string) (*Agent, error) {
	var a Agent
	err := s.db.QueryRow(
		`SELECT id, name, token_hash, scopes, created_at, last_used FROM agents WHERE id = ?`,
		id,
	).Scan(&a.ID, &a.Name, &a.TokenHash, &a.Scopes, &a.CreatedAt, &a.LastUsed)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) GetAgentByTokenHash(hash string) (*Agent, error) {
	var a Agent
	err := s.db.QueryRow(
		`SELECT id, name, token_hash, scopes, created_at, last_used FROM agents WHERE token_hash = ?`,
		hash,
	).Scan(&a.ID, &a.Name, &a.TokenHash, &a.Scopes, &a.CreatedAt, &a.LastUsed)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) ListAgents() ([]*Agent, error) {
	rows, err := s.db.Query(`SELECT id, name, token_hash, scopes, created_at, last_used FROM agents ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Name, &a.TokenHash, &a.Scopes, &a.CreatedAt, &a.LastUsed); err != nil {
			return nil, err
		}
		agents = append(agents, &a)
	}
	return agents, nil
}

func (s *Store) UpdateAgentLastUsed(id string) error {
	_, err := s.db.Exec(`UPDATE agents SET last_used = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteAgent(name string) error {
	_, err := s.db.Exec(`DELETE FROM agents WHERE name = ?`, name)
	return err
}

// Backend operations

func (s *Store) CreateBackend(backendType, name, config string) (*Backend, error) {
	id := uuid.New().String()
	_, err := s.db.Exec(
		`INSERT INTO backends (id, type, name, config) VALUES (?, ?, ?, ?)`,
		id, backendType, name, config,
	)
	if err != nil {
		return nil, err
	}
	return s.GetBackendByName(name)
}

func (s *Store) GetBackendByName(name string) (*Backend, error) {
	var b Backend
	err := s.db.QueryRow(
		`SELECT id, type, name, config, created_at FROM backends WHERE name = ?`,
		name,
	).Scan(&b.ID, &b.Type, &b.Name, &b.Config, &b.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func (s *Store) ListBackends() ([]*Backend, error) {
	rows, err := s.db.Query(`SELECT id, type, name, config, created_at FROM backends ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var backends []*Backend
	for rows.Next() {
		var b Backend
		if err := rows.Scan(&b.ID, &b.Type, &b.Name, &b.Config, &b.CreatedAt); err != nil {
			return nil, err
		}
		backends = append(backends, &b)
	}
	return backends, nil
}

func (s *Store) DeleteBackend(name string) error {
	_, err := s.db.Exec(`DELETE FROM backends WHERE name = ?`, name)
	return err
}

// Active credential operations

func (s *Store) CreateActiveCredential(agentID, backend, tokenHash, scopes string, expiresAt time.Time) (*ActiveCredential, error) {
	id := uuid.New().String()
	_, err := s.db.Exec(
		`INSERT INTO active_credentials (id, agent_id, backend, token_hash, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, agentID, backend, tokenHash, scopes, expiresAt,
	)
	if err != nil {
		return nil, err
	}
	return s.GetActiveCredential(id)
}

func (s *Store) GetActiveCredential(id string) (*ActiveCredential, error) {
	var c ActiveCredential
	err := s.db.QueryRow(
		`SELECT c.id, c.agent_id, a.name, c.backend, c.token_hash, c.scopes, c.expires_at, c.created_at 
		 FROM active_credentials c 
		 JOIN agents a ON c.agent_id = a.id 
		 WHERE c.id = ?`,
		id,
	).Scan(&c.ID, &c.AgentID, &c.AgentName, &c.Backend, &c.TokenHash, &c.Scopes, &c.ExpiresAt, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) ListActiveCredentials() ([]*ActiveCredential, error) {
	rows, err := s.db.Query(
		`SELECT c.id, c.agent_id, a.name, c.backend, c.token_hash, c.scopes, c.expires_at, c.created_at 
		 FROM active_credentials c 
		 JOIN agents a ON c.agent_id = a.id 
		 WHERE c.expires_at > CURRENT_TIMESTAMP
		 ORDER BY c.expires_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*ActiveCredential
	for rows.Next() {
		var c ActiveCredential
		if err := rows.Scan(&c.ID, &c.AgentID, &c.AgentName, &c.Backend, &c.TokenHash, &c.Scopes, &c.ExpiresAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		creds = append(creds, &c)
	}
	return creds, nil
}

func (s *Store) ListActiveCredentialsByAgent(agentID string) ([]*ActiveCredential, error) {
	rows, err := s.db.Query(
		`SELECT c.id, c.agent_id, a.name, c.backend, c.token_hash, c.scopes, c.expires_at, c.created_at 
		 FROM active_credentials c 
		 JOIN agents a ON c.agent_id = a.id 
		 WHERE c.agent_id = ? AND c.expires_at > CURRENT_TIMESTAMP
		 ORDER BY c.expires_at`,
		agentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*ActiveCredential
	for rows.Next() {
		var c ActiveCredential
		if err := rows.Scan(&c.ID, &c.AgentID, &c.AgentName, &c.Backend, &c.TokenHash, &c.Scopes, &c.ExpiresAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		creds = append(creds, &c)
	}
	return creds, nil
}

func (s *Store) DeleteActiveCredential(id string) error {
	_, err := s.db.Exec(`DELETE FROM active_credentials WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteExpiredCredentials() (int64, error) {
	result, err := s.db.Exec(`DELETE FROM active_credentials WHERE expires_at <= CURRENT_TIMESTAMP`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
