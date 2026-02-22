package backend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DopplerConfig holds the API credentials
type DopplerConfig struct {
	// Token is a personal or service account token with permission to create service tokens
	Token string `json:"token"`
}

type DopplerBackend struct {
	config  DopplerConfig
	baseURL string
}

type DopplerServiceToken struct {
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Key       string    `json:"key"` // Only returned on creation
	Project   string    `json:"project"`
	Config    string    `json:"config"`
	Access    string    `json:"access"` // "read" or "read/write"
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func NewDoppler(configJSON string) (*DopplerBackend, error) {
	var config DopplerConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, fmt.Errorf("invalid doppler config: %w", err)
	}

	if config.Token == "" {
		return nil, fmt.Errorf("token is required")
	}

	return &DopplerBackend{
		config:  config,
		baseURL: "https://api.doppler.com",
	}, nil
}

// CreateServiceToken creates a new service token scoped to a project/config
func (d *DopplerBackend) CreateServiceToken(project, config, name string, access string, expiresAt *time.Time) (*DopplerServiceToken, error) {
	body := map[string]interface{}{
		"name":    name,
		"project": project,
		"config":  config,
		"access":  access,
	}
	if expiresAt != nil {
		body["expire_at"] = expiresAt.Format(time.RFC3339)
	}

	reqBody, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", d.baseURL+"/v3/configs/config/tokens", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+d.config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create service token: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("doppler API error (%d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Token DopplerServiceToken `json:"token"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result.Token, nil
}

// DeleteServiceToken deletes a service token by slug
func (d *DopplerBackend) DeleteServiceToken(project, config, slug string) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/v3/configs/config/tokens/token?project=%s&config=%s&slug=%s",
		d.baseURL, project, config, slug), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+d.config.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete service token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("doppler API error (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetSecrets fetches secrets for a project/config using a service token
func (d *DopplerBackend) GetSecrets(project, config string) (map[string]string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v3/configs/config/secrets?project=%s&config=%s",
		d.baseURL, project, config), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+d.config.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secrets: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("doppler API error (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Secrets map[string]struct {
			Raw string `json:"raw"`
		} `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse secrets: %w", err)
	}

	secrets := make(map[string]string)
	for k, v := range result.Secrets {
		secrets[k] = v.Raw
	}
	return secrets, nil
}

// DopplerBackend implements Backend and RevocableBackend
func (d *DopplerBackend) GetToken(req TokenRequest) (*Token, error) {
	token, _, err := d.GetTokenWithID(req)
	return token, err
}

func (d *DopplerBackend) GetTokenWithID(req TokenRequest) (*Token, string, error) {
	// Parse scope: doppler:project/config or doppler:project/config:read
	if len(req.DopplerScopes) == 0 {
		return nil, "", fmt.Errorf("doppler scope required (project/config)")
	}

	// Use first scope for now
	scope := req.DopplerScopes[0]
	project, config, access := parseDopplerScope(scope)
	if project == "" || config == "" {
		return nil, "", fmt.Errorf("invalid doppler scope: %s (expected project/config)", scope)
	}

	// Create service token with expiry
	name := fmt.Sprintf("creddy-%d", time.Now().UnixNano())
	expiresAt := time.Now().Add(1 * time.Hour)

	serviceToken, err := d.CreateServiceToken(project, config, name, access, &expiresAt)
	if err != nil {
		return nil, "", err
	}

	// External ID format: project/config/slug (for deletion)
	externalID := fmt.Sprintf("%s/%s/%s", project, config, serviceToken.Slug)

	return &Token{
		Value:     serviceToken.Key,
		ExpiresAt: expiresAt,
	}, externalID, nil
}

func (d *DopplerBackend) RevokeToken(externalID string) error {
	// Parse external ID: project/config/slug
	project, config, slug := parseDopplerExternalID(externalID)
	if project == "" || config == "" || slug == "" {
		return fmt.Errorf("invalid external ID format: %s", externalID)
	}
	return d.DeleteServiceToken(project, config, slug)
}

func (d *DopplerBackend) Type() string {
	return "doppler"
}

// parseDopplerScope parses "project/config" or "project/config:read"
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

// parseDopplerExternalID parses "project/config/slug"
func parseDopplerExternalID(id string) (project, config, slug string) {
	parts := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(id); i++ {
		if id[i] == '/' {
			parts = append(parts, id[start:i])
			start = i + 1
		}
	}
	parts = append(parts, id[start:])

	if len(parts) >= 3 {
		return parts[0], parts[1], parts[2]
	}
	return "", "", ""
}

// ExtractDopplerScopesFromAgentScopes extracts doppler scopes from agent scopes
// Returns list of project/config scopes
func ExtractDopplerScopesFromAgentScopes(scopes []string) []string {
	var dopplerScopes []string
	for _, scope := range scopes {
		if len(scope) > 8 && scope[:8] == "doppler:" {
			dopplerScopes = append(dopplerScopes, scope[8:])
		}
	}
	return dopplerScopes
}

// MatchesDopplerScope checks if requested scope is allowed by agent scope
// Scope format: "doppler:project/config" or "doppler:project/config:read"
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
