package backend

import (
	"fmt"
	"time"
)

// Token represents a credential issued by a backend
type Token struct {
	Value     string
	ExpiresAt time.Time
}

// TokenRequest contains parameters for requesting a token
type TokenRequest struct {
	InstallationID int64    // GitHub: installation ID
	Repos          []string // GitHub: list of owner/repo to scope token to
	ReadOnly       bool     // Request read-only permissions
}

// Backend is the interface that all credential backends must implement
type Backend interface {
	// GetToken generates a new ephemeral token
	GetToken(req TokenRequest) (*Token, error)
	// Type returns the backend type (e.g., "github", "aws")
	Type() string
}

// RevocableBackend is for backends that support explicit token revocation
type RevocableBackend interface {
	Backend
	// GetTokenWithID returns token + external ID for later revocation
	GetTokenWithID(req TokenRequest) (*Token, string, error)
	// RevokeToken revokes a token by its external ID
	RevokeToken(externalID string) error
}

// GitHubBackendWrapper wraps GitHubBackend to implement Backend interface
type GitHubBackendWrapper struct {
	*GitHubBackend
}

func (g *GitHubBackendWrapper) GetToken(req TokenRequest) (*Token, error) {
	token, err := g.GitHubBackend.GetToken(req.InstallationID, req.Repos, req.ReadOnly)
	if err != nil {
		return nil, err
	}
	return &Token{
		Value:     token.Token,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

func (g *GitHubBackendWrapper) Type() string {
	return "github"
}

// Manager handles multiple backends
type Manager struct {
	backends map[string]Backend
}

func NewManager() *Manager {
	return &Manager{
		backends: make(map[string]Backend),
	}
}

func (m *Manager) Register(name string, b Backend) {
	m.backends[name] = b
}

func (m *Manager) Get(name string) (Backend, error) {
	b, ok := m.backends[name]
	if !ok {
		return nil, fmt.Errorf("backend not found: %s", name)
	}
	return b, nil
}

func (m *Manager) List() []string {
	names := make([]string, 0, len(m.backends))
	for name := range m.backends {
		names = append(names, name)
	}
	return names
}

// LoadFromConfig creates a backend from stored config
func LoadFromConfig(backendType, configJSON string) (Backend, error) {
	switch backendType {
	case "github":
		gb, err := NewGitHub(configJSON)
		if err != nil {
			return nil, err
		}
		return &GitHubBackendWrapper{gb}, nil
	case "anthropic":
		ab, err := NewAnthropic(configJSON)
		if err != nil {
			return nil, err
		}
		return ab, nil
	default:
		return nil, fmt.Errorf("unknown backend type: %s", backendType)
	}
}
