package oidc

import (
	"encoding/json"
	"fmt"
	"time"
)

// StoreAdapter adapts a credential store to the TokenProvider interface
type StoreAdapter struct {
	// ValidateClientFunc validates client credentials and returns agent info
	ValidateClientFunc func(clientID, clientSecret string) (*AgentInfo, error)
}

// NewStoreAdapter creates a new store adapter with the given validation function
func NewStoreAdapter(validateFunc func(clientID, clientSecret string) (*AgentInfo, error)) *StoreAdapter {
	return &StoreAdapter{
		ValidateClientFunc: validateFunc,
	}
}

// ValidateClient implements TokenProvider
func (sa *StoreAdapter) ValidateClient(clientID, clientSecret string) (*AgentInfo, error) {
	if sa.ValidateClientFunc == nil {
		return nil, fmt.Errorf("validator not configured")
	}
	return sa.ValidateClientFunc(clientID, clientSecret)
}

// ParseScopes parses a JSON scope array into a string slice
func ParseScopes(scopesJSON string) []string {
	var scopes []string
	if err := json.Unmarshal([]byte(scopesJSON), &scopes); err != nil {
		return []string{}
	}
	return scopes
}

// KeyStoreAdapter adapts a database store to the KeyStore interface
type KeyStoreAdapter struct {
	CreateFunc     func(keyID, privateKeyPEM string, isCurrent bool) error
	ListFunc       func() ([]StoredKey, error)
	GetCurrentFunc func() (*StoredKey, error)
	SetCurrentFunc func(keyID string) error
	DeleteFunc     func(keyID string) error
}

// NewKeyStoreAdapter creates a KeyStore adapter with the given functions
func NewKeyStoreAdapter(
	createFunc func(keyID, privateKeyPEM string, isCurrent bool) error,
	listFunc func() ([]StoredKey, error),
	getCurrentFunc func() (*StoredKey, error),
	setCurrentFunc func(keyID string) error,
	deleteFunc func(keyID string) error,
) *KeyStoreAdapter {
	return &KeyStoreAdapter{
		CreateFunc:     createFunc,
		ListFunc:       listFunc,
		GetCurrentFunc: getCurrentFunc,
		SetCurrentFunc: setCurrentFunc,
		DeleteFunc:     deleteFunc,
	}
}

func (ksa *KeyStoreAdapter) CreateOIDCKey(keyID, privateKeyPEM string, isCurrent bool) error {
	if ksa.CreateFunc == nil {
		return fmt.Errorf("create not implemented")
	}
	return ksa.CreateFunc(keyID, privateKeyPEM, isCurrent)
}

func (ksa *KeyStoreAdapter) ListOIDCKeys() ([]StoredKey, error) {
	if ksa.ListFunc == nil {
		return nil, fmt.Errorf("list not implemented")
	}
	return ksa.ListFunc()
}

func (ksa *KeyStoreAdapter) GetCurrentOIDCKey() (*StoredKey, error) {
	if ksa.GetCurrentFunc == nil {
		return nil, fmt.Errorf("get current not implemented")
	}
	return ksa.GetCurrentFunc()
}

func (ksa *KeyStoreAdapter) SetCurrentOIDCKey(keyID string) error {
	if ksa.SetCurrentFunc == nil {
		return fmt.Errorf("set current not implemented")
	}
	return ksa.SetCurrentFunc(keyID)
}

func (ksa *KeyStoreAdapter) DeleteOIDCKey(keyID string) error {
	if ksa.DeleteFunc == nil {
		return fmt.Errorf("delete not implemented")
	}
	return ksa.DeleteFunc(keyID)
}

// Ensure KeyStoreAdapter implements KeyStore
var _ KeyStore = (*KeyStoreAdapter)(nil)

// Helper to convert store.OIDCKey to oidc.StoredKey
func ConvertStoredKey(keyID, privateKey string, isCurrent bool, createdAt time.Time) StoredKey {
	return StoredKey{
		KeyID:      keyID,
		PrivateKey: privateKey,
		IsCurrent:  isCurrent,
		CreatedAt:  createdAt,
	}
}
