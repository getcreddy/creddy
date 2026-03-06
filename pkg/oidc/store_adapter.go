package oidc

import (
	"encoding/json"
	"fmt"
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
