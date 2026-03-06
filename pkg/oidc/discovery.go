package oidc

import (
	"encoding/json"
	"net/http"
)

// DiscoveryDocument represents the OIDC discovery metadata
// See: https://openid.net/specs/openid-connect-discovery-1_0.html
type DiscoveryDocument struct {
	// Required
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// Recommended
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`

	// Creddy extensions
	CredentialExchangeEndpoint string `json:"credential_exchange_endpoint,omitempty"`
}

// NewDiscoveryDocument creates the OIDC discovery metadata for a Creddy instance
func NewDiscoveryDocument(issuer string) *DiscoveryDocument {
	return &DiscoveryDocument{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oauth/authorize", // Not used for client_credentials
		TokenEndpoint:         issuer + "/oauth/token",
		JWKSURI:               issuer + "/.well-known/jwks.json",
		UserinfoEndpoint:      issuer + "/oauth/userinfo",

		ResponseTypesSupported: []string{"token"}, // Implicit flow for agents
		SubjectTypesSupported:  []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},

		ScopesSupported: []string{
			"openid",
			"profile",     // agent_name, agent_id
			"credentials", // access to credential exchange
		},

		ClaimsSupported: []string{
			// Standard OIDC
			"iss", "sub", "aud", "exp", "iat", "auth_time",
			// Creddy agent claims
			"agent_id", "agent_name", "scopes", "client_id",
			"task_id", "task_description", "parent_agent_id",
		},

		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic", // Basic auth with client_id:client_secret
			"client_secret_post",  // client_id/client_secret in POST body
		},

		GrantTypesSupported: []string{
			"client_credentials", // Machine-to-machine (primary for agents)
		},

		// Creddy extension
		CredentialExchangeEndpoint: issuer + "/v1/credentials",
	}
}

// Handler returns an HTTP handler for the discovery endpoint
func (d *DiscoveryDocument) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
		json.NewEncoder(w).Encode(d)
	}
}
