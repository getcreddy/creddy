package backend

import (
	"fmt"
	"strings"
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
	DopplerScopes  []string // Doppler: list of project/config scopes
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

// PluginLoader is an interface for loading plugins (to avoid circular imports)
type PluginLoader interface {
	LoadPlugin(name string) (Backend, error)
}

// DefaultPluginLoader is set by the server on startup
var DefaultPluginLoader PluginLoader

// LoadFromConfig creates a backend from stored config
func LoadFromConfig(backendType, configJSON string) (Backend, error) {
	// All backends are loaded via plugins
	if DefaultPluginLoader == nil {
		return nil, fmt.Errorf("plugin loader not initialized")
	}

	b, err := DefaultPluginLoader.LoadPlugin(backendType)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugin %s: %w", backendType, err)
	}

	// Configure the plugin backend
	if pb, ok := b.(interface{ Configure(string) error }); ok {
		if err := pb.Configure(configJSON); err != nil {
			return nil, fmt.Errorf("failed to configure plugin: %w", err)
		}
	}

	return b, nil
}

// --- Scope parsing helpers (used by server for backwards compatibility) ---

// ParseGitHubScope parses a scope like "github:owner/repo:read"
// Returns: pattern, permission (read/write), isGitHub
func ParseGitHubScope(scope string) (pattern string, perm string, isGitHub bool) {
	if !strings.HasPrefix(scope, "github:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(scope, "github:")

	// Check for :read or :write suffix
	if strings.HasSuffix(rest, ":read") {
		return strings.TrimSuffix(rest, ":read"), "read", true
	}
	if strings.HasSuffix(rest, ":write") {
		return strings.TrimSuffix(rest, ":write"), "write", true
	}

	// Default to write
	return rest, "write", true
}

// MatchesGitHubScope checks if requested repos/permissions are allowed by the scope
func MatchesGitHubScope(scope string, requestedRepos []string, requestedReadOnly bool) bool {
	pattern, perm, isGitHub := ParseGitHubScope(scope)
	if !isGitHub {
		return false
	}

	// Check permission level: if scope is read-only, can't request write
	if perm == "read" && !requestedReadOnly {
		return false
	}

	// Wildcard - allow all repos
	if pattern == "*" {
		return true
	}

	// If no specific repos requested, scope matches
	if len(requestedRepos) == 0 {
		return true
	}

	for _, repo := range requestedRepos {
		if !matchRepoPattern(pattern, repo) {
			return false
		}
	}
	return true
}

func matchRepoPattern(pattern, repo string) bool {
	// Exact match
	if pattern == repo {
		return true
	}

	// Owner wildcard: "owner/*" matches "owner/anything"
	if strings.HasSuffix(pattern, "/*") {
		owner := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(repo, owner+"/")
	}

	return false
}

// MatchesDopplerScope checks if a requested scope is allowed by an agent scope
func MatchesDopplerScope(agentScope string, requestedScope string, requestedReadOnly bool) bool {
	if len(agentScope) < 8 || agentScope[:8] != "doppler:" {
		return false
	}

	agentPattern := agentScope[8:]
	agentProject, agentConfig, agentAccess := parseDopplerScope(agentPattern)

	reqProject, reqConfig, _ := parseDopplerScope(requestedScope)

	// Check permission level
	if agentAccess == "read" && !requestedReadOnly {
		return false
	}

	// Exact match
	if agentProject == reqProject && agentConfig == reqConfig {
		return true
	}

	// Wildcard: project/* matches any config
	if agentConfig == "*" && agentProject == reqProject {
		return true
	}

	// Full wildcard: */* matches anything
	if agentProject == "*" && agentConfig == "*" {
		return true
	}

	return false
}

func parseDopplerScope(scope string) (project, config, access string) {
	access = "read/write" // default

	// Check for :read suffix
	if len(scope) > 5 && scope[len(scope)-5:] == ":read" {
		scope = scope[:len(scope)-5]
		access = "read"
	}

	// Parse project/config
	for i := 0; i < len(scope); i++ {
		if scope[i] == '/' {
			project = scope[:i]
			config = scope[i+1:]
			return
		}
	}
	return "", "", ""
}

// ExtractReposFromScopes extracts all repo patterns from github scopes
// Returns repos and whether they are read-only
func ExtractReposFromScopes(scopes []string) (repos []string, readOnly bool) {
	readOnly = true // Default to read-only, set to false if any scope has write

	for _, scope := range scopes {
		if !strings.HasPrefix(scope, "github:") {
			continue
		}

		rest := strings.TrimPrefix(scope, "github:")

		// Check permission suffix
		perm := "write" // default
		if strings.HasSuffix(rest, ":read") {
			rest = strings.TrimSuffix(rest, ":read")
			perm = "read"
		} else if strings.HasSuffix(rest, ":write") {
			rest = strings.TrimSuffix(rest, ":write")
			perm = "write"
		}

		if perm == "write" {
			readOnly = false
		}

		// rest is now the repo pattern (*, owner/*, owner/repo)
		if rest != "" && rest != "*" {
			repos = append(repos, rest)
		}
	}

	return repos, readOnly
}

// ExtractDopplerScopesFromAgentScopes extracts doppler scopes from agent scopes
// e.g., "doppler:project/config" -> "project/config"
func ExtractDopplerScopesFromAgentScopes(scopes []string) []string {
	var dopplerScopes []string

	for _, scope := range scopes {
		if !strings.HasPrefix(scope, "doppler:") {
			continue
		}

		rest := strings.TrimPrefix(scope, "doppler:")

		// Remove permission suffix if present
		if strings.HasSuffix(rest, ":read") {
			rest = strings.TrimSuffix(rest, ":read")
		} else if strings.HasSuffix(rest, ":write") {
			rest = strings.TrimSuffix(rest, ":write")
		}

		if rest != "" && rest != "*" {
			dopplerScopes = append(dopplerScopes, rest)
		}
	}

	return dopplerScopes
}
