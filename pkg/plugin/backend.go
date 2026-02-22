package plugin

import (
	"context"
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
		TTL:   10 * time.Minute, // Default TTL
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

	scope := pb.buildScope(req)

	credReq := &sdk.CredentialRequest{
		Agent: sdk.Agent{
			ID:     "legacy",
			Name:   "Legacy Backend",
			Scopes: []string{scope},
		},
		Scope: scope,
		TTL:   10 * time.Minute,
	}

	cred, err := pb.plugin.GetCredential(ctx, credReq)
	if err != nil {
		return nil, "", err
	}

	return &backend.Token{
		Value:     cred.Value,
		ExpiresAt: cred.ExpiresAt,
	}, cred.ExternalID, nil
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
