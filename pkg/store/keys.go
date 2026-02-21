package store

import (
	"time"
)

type SigningKey struct {
	ID           string
	AgentID      string
	KeyID        string // GPG short key ID
	PublicKey    string // ASCII armored
	PrivateKey   string // PEM encoded (encrypted in production)
	Email        string
	Name         string
	CreatedAt    time.Time
	LastAccessed *time.Time
}

func (s *Store) migrateKeys() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS signing_keys (
			id TEXT PRIMARY KEY,
			agent_id TEXT UNIQUE NOT NULL,
			key_id TEXT NOT NULL,
			public_key TEXT NOT NULL,
			private_key TEXT NOT NULL,
			email TEXT NOT NULL,
			name TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_accessed DATETIME,
			FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_signing_keys_agent ON signing_keys(agent_id)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateSigningKey(agentID, keyID, publicKey, privateKey, email, name string) (*SigningKey, error) {
	id := generateID()
	_, err := s.db.Exec(
		`INSERT INTO signing_keys (id, agent_id, key_id, public_key, private_key, email, name) 
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, agentID, keyID, publicKey, privateKey, email, name,
	)
	if err != nil {
		return nil, err
	}
	return s.GetSigningKeyByAgent(agentID)
}

func (s *Store) GetSigningKeyByAgent(agentID string) (*SigningKey, error) {
	var k SigningKey
	err := s.db.QueryRow(
		`SELECT id, agent_id, key_id, public_key, private_key, email, name, created_at, last_accessed 
		 FROM signing_keys WHERE agent_id = ?`,
		agentID,
	).Scan(&k.ID, &k.AgentID, &k.KeyID, &k.PublicKey, &k.PrivateKey, &k.Email, &k.Name, &k.CreatedAt, &k.LastAccessed)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (s *Store) UpdateKeyLastAccessed(agentID string) error {
	_, err := s.db.Exec(`UPDATE signing_keys SET last_accessed = CURRENT_TIMESTAMP WHERE agent_id = ?`, agentID)
	return err
}

func (s *Store) DeleteSigningKey(agentID string) error {
	_, err := s.db.Exec(`DELETE FROM signing_keys WHERE agent_id = ?`, agentID)
	return err
}

func (s *Store) ListPublicKeys() ([]*SigningKey, error) {
	rows, err := s.db.Query(
		`SELECT k.id, k.agent_id, k.key_id, k.public_key, '', k.email, k.name, k.created_at, k.last_accessed 
		 FROM signing_keys k
		 JOIN agents a ON k.agent_id = a.id
		 ORDER BY k.created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*SigningKey
	for rows.Next() {
		var k SigningKey
		if err := rows.Scan(&k.ID, &k.AgentID, &k.KeyID, &k.PublicKey, &k.PrivateKey, &k.Email, &k.Name, &k.CreatedAt, &k.LastAccessed); err != nil {
			return nil, err
		}
		keys = append(keys, &k)
	}
	return keys, nil
}
