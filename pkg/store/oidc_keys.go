package store

import (
	"time"
)

// OIDCKey represents a stored OIDC signing key
type OIDCKey struct {
	ID         string
	KeyID      string // kid in JWT header
	PrivateKey string // PEM encoded
	IsCurrent  bool
	CreatedAt  time.Time
}

func (s *Store) migrateOIDCKeys() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS oidc_keys (
			id TEXT PRIMARY KEY,
			key_id TEXT UNIQUE NOT NULL,
			private_key TEXT NOT NULL,
			is_current BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_oidc_keys_current ON oidc_keys(is_current)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return err
		}
	}
	return nil
}

// CreateOIDCKey stores a new OIDC signing key
func (s *Store) CreateOIDCKey(keyID, privateKeyPEM string, isCurrent bool) (*OIDCKey, error) {
	id := generateID()

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// If this is the current key, unset any existing current key
	if isCurrent {
		_, err := tx.Exec(`UPDATE oidc_keys SET is_current = FALSE WHERE is_current = TRUE`)
		if err != nil {
			return nil, err
		}
	}

	_, err = tx.Exec(
		`INSERT INTO oidc_keys (id, key_id, private_key, is_current) VALUES (?, ?, ?, ?)`,
		id, keyID, privateKeyPEM, isCurrent,
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return s.GetOIDCKey(keyID)
}

// GetOIDCKey retrieves an OIDC key by its key ID
func (s *Store) GetOIDCKey(keyID string) (*OIDCKey, error) {
	var k OIDCKey
	err := s.db.QueryRow(
		`SELECT id, key_id, private_key, is_current, created_at FROM oidc_keys WHERE key_id = ?`,
		keyID,
	).Scan(&k.ID, &k.KeyID, &k.PrivateKey, &k.IsCurrent, &k.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// GetCurrentOIDCKey retrieves the current OIDC signing key
func (s *Store) GetCurrentOIDCKey() (*OIDCKey, error) {
	var k OIDCKey
	err := s.db.QueryRow(
		`SELECT id, key_id, private_key, is_current, created_at FROM oidc_keys WHERE is_current = TRUE`,
	).Scan(&k.ID, &k.KeyID, &k.PrivateKey, &k.IsCurrent, &k.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// ListOIDCKeys returns all OIDC keys (for JWKS)
func (s *Store) ListOIDCKeys() ([]*OIDCKey, error) {
	rows, err := s.db.Query(
		`SELECT id, key_id, private_key, is_current, created_at FROM oidc_keys ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*OIDCKey
	for rows.Next() {
		var k OIDCKey
		if err := rows.Scan(&k.ID, &k.KeyID, &k.PrivateKey, &k.IsCurrent, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, &k)
	}
	return keys, nil
}

// SetCurrentOIDCKey sets a key as the current signing key
func (s *Store) SetCurrentOIDCKey(keyID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Unset all current keys
	if _, err := tx.Exec(`UPDATE oidc_keys SET is_current = FALSE`); err != nil {
		return err
	}

	// Set the new current key
	if _, err := tx.Exec(`UPDATE oidc_keys SET is_current = TRUE WHERE key_id = ?`, keyID); err != nil {
		return err
	}

	return tx.Commit()
}

// DeleteOIDCKey removes an OIDC key (for rotation cleanup)
func (s *Store) DeleteOIDCKey(keyID string) error {
	// Don't allow deleting the current key
	var isCurrent bool
	err := s.db.QueryRow(`SELECT is_current FROM oidc_keys WHERE key_id = ?`, keyID).Scan(&isCurrent)
	if err != nil {
		return err
	}
	if isCurrent {
		return &ErrCurrentKey{}
	}

	_, err = s.db.Exec(`DELETE FROM oidc_keys WHERE key_id = ?`, keyID)
	return err
}

// ErrCurrentKey is returned when trying to delete the current signing key
type ErrCurrentKey struct{}

func (e *ErrCurrentKey) Error() string {
	return "cannot delete current signing key"
}
