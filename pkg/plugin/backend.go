package plugin

import (
	"context"
	"fmt"
	"time"

	sdk "github.com/getcreddy/creddy-plugin-sdk"
	"github.com/getcreddy/creddy/pkg/backend"
)

// PluginBackend wraps a plugin to implement the backend.Backend interface
type PluginBackend struct {
	plugin     sdk.Plugin
	pluginName string
	configured bool
}

// NewPluginBackend creates a backend wrapper for a plugin
func NewPluginBackend(name string, p sdk.Plugin) *PluginBackend {
	return &PluginBackend{
		plugin:     p,
		pluginName: name,
	}
}

// Configure sets up the plugin with the given JSON config
func (pb *PluginBackend) Configure(configJSON string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := pb.plugin.Configure(ctx, configJSON); err != nil {
		return err
	}

	pb.configured = true
	return nil
}

// Validate tests the plugin configuration
func (pb *PluginBackend) Validate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return pb.plugin.Validate(ctx)
}

// GetToken implements backend.Backend
func (pb *PluginBackend) GetToken(req backend.TokenRequest) (*backend.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Use TTL from request, default to 10 minutes
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	// Validate TTL against plugin constraints
	if err := pb.ValidateTTL(ttl); err != nil {
		return nil, err
	}

	// Build the scope from the request
	scope := pb.buildScope(req)

	// Create credential request
	credReq := &sdk.CredentialRequest{
		Agent: sdk.Agent{
			ID:     "legacy", // For backwards compatibility
			Name:   "Legacy Backend",
			Scopes: []string{scope},
		},
		Scope: scope,
		TTL:   ttl,
	}

	cred, err := pb.plugin.GetCredential(ctx, credReq)
	if err != nil {
		return nil, err
	}

	return &backend.Token{
		Value:     cred.Value,
		ExpiresAt: cred.ExpiresAt,
	}, nil
}

// GetTokenWithID implements backend.RevocableBackend
func (pb *PluginBackend) GetTokenWithID(req backend.TokenRequest) (*backend.Token, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Use TTL from request, default to 10 minutes
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	// Validate TTL against plugin constraints
	if err := pb.ValidateTTL(ttl); err != nil {
		return nil, "", err
	}

	scope := pb.buildScope(req)

	credReq := &sdk.CredentialRequest{
		Agent: sdk.Agent{
			ID:     "legacy",
			Name:   "Legacy Backend",
			Scopes: []string{scope},
		},
		Scope: scope,
		TTL:   ttl,
	}

	cred, err := pb.plugin.GetCredential(ctx, credReq)
	if err != nil {
		return nil, "", err
	}

	return &backend.Token{
		Value:     cred.Value,
		ExpiresAt: cred.ExpiresAt,
	}, cred.Credential, nil // Credential is the token/key needed for revocation
}

// RevokeToken implements backend.RevocableBackend
func (pb *PluginBackend) RevokeToken(externalID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return pb.plugin.RevokeCredential(ctx, externalID)
}

// Type implements backend.Backend
func (pb *PluginBackend) Type() string {
	return pb.pluginName
}

// MatchScope checks if this plugin handles the given scope
func (pb *PluginBackend) MatchScope(scope string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return pb.plugin.MatchScope(ctx, scope)
}

// GetScopes returns the scopes this plugin supports
func (pb *PluginBackend) GetScopes() ([]sdk.ScopeSpec, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return pb.plugin.Scopes(ctx)
}

// GetConstraints returns the TTL constraints for this plugin
func (pb *PluginBackend) GetConstraints() (*sdk.Constraints, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return pb.plugin.Constraints(ctx)
}

// ValidateTTL checks if the requested TTL is within the plugin's constraints
// Returns an error with a clear message if the TTL violates constraints
func (pb *PluginBackend) ValidateTTL(ttl time.Duration) error {
	constraints, err := pb.GetConstraints()
	if err != nil {
		return fmt.Errorf("failed to get plugin constraints: %w", err)
	}

	// No constraints means any TTL is acceptable
	if constraints == nil {
		return nil
	}

	if constraints.MaxTTL > 0 && ttl > constraints.MaxTTL {
		return fmt.Errorf("requested TTL %s exceeds maximum allowed %s for %s plugin (%s)",
			ttl, constraints.MaxTTL, pb.pluginName, constraints.Description)
	}

	if constraints.MinTTL > 0 && ttl < constraints.MinTTL {
		return fmt.Errorf("requested TTL %s is below minimum allowed %s for %s plugin (%s)",
			ttl, constraints.MinTTL, pb.pluginName, constraints.Description)
	}

	return nil
}

// buildScope constructs a scope string from a TokenRequest
// This is for backwards compatibility with the old backend interface
func (pb *PluginBackend) buildScope(req backend.TokenRequest) string {
	switch pb.pluginName {
	case "github":
		if len(req.Repos) > 0 {
			scope := "github:" + req.Repos[0]
			if req.ReadOnly {
				scope += ":read"
			}
			return scope
		}
		if req.ReadOnly {
			return "github:*:read"
		}
		return "github:*"

	case "doppler":
		if len(req.DopplerScopes) > 0 {
			return "doppler:" + req.DopplerScopes[0]
		}
		return "doppler:*"

	default:
		return pb.pluginName + ":*"
	}
}

// Ensure PluginBackend implements the interfaces
var _ backend.Backend = (*PluginBackend)(nil)
var _ backend.RevocableBackend = (*PluginBackend)(nil)
