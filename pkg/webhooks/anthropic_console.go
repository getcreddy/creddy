package webhooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AnthropicConsoleClient interacts with the Anthropic Console API using session auth
type AnthropicConsoleClient struct {
	sessionKey string
	orgID      string
	httpClient *http.Client
}

// ConsoleAPIKey represents an API key from the console
type ConsoleAPIKey struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Key            string `json:"key,omitempty"` // Only present on creation
	PartialKeyHint string `json:"partial_key_hint,omitempty"`
	Status         string `json:"status"`
	WorkspaceID    string `json:"workspace_id"`
	CreatedAt      string `json:"created_at"`
}

// NewAnthropicConsoleClient creates a new console client
func NewAnthropicConsoleClient(sessionKey, orgID string) *AnthropicConsoleClient {
	return &AnthropicConsoleClient{
		sessionKey: sessionKey,
		orgID:      orgID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CreateAPIKey creates a new API key via the Console API
func (c *AnthropicConsoleClient) CreateAPIKey(name string, workspaceID string) (*ConsoleAPIKey, error) {
	if workspaceID == "" {
		workspaceID = "default"
	}

	url := fmt.Sprintf("https://platform.claude.com/api/console/organizations/%s/workspaces/%s/api_keys",
		c.orgID, workspaceID)

	body := map[string]string{"name": name}
	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var apiKey ConsoleAPIKey
	if err := json.NewDecoder(resp.Body).Decode(&apiKey); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &apiKey, nil
}

// ListAPIKeys lists all API keys
func (c *AnthropicConsoleClient) ListAPIKeys(workspaceID string) ([]ConsoleAPIKey, error) {
	if workspaceID == "" {
		workspaceID = "default"
	}

	url := fmt.Sprintf("https://platform.claude.com/api/console/organizations/%s/workspaces/%s/api_keys",
		c.orgID, workspaceID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var keys []ConsoleAPIKey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return keys, nil
}

// DeleteAPIKey deletes/archives an API key
func (c *AnthropicConsoleClient) DeleteAPIKey(keyID string, workspaceID string) error {
	if workspaceID == "" {
		workspaceID = "default"
	}

	url := fmt.Sprintf("https://platform.claude.com/api/console/organizations/%s/workspaces/%s/api_keys/%s",
		c.orgID, workspaceID, keyID)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// setHeaders adds required headers for console API
func (c *AnthropicConsoleClient) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cookie", fmt.Sprintf("sessionKey=%s", c.sessionKey))
	req.Header.Set("Origin", "https://platform.claude.com")
	req.Header.Set("Referer", "https://platform.claude.com/settings/keys")
}

// ValidateSession checks if the session is still valid
func (c *AnthropicConsoleClient) ValidateSession() error {
	url := fmt.Sprintf("https://platform.claude.com/api/console/organizations/%s", c.orgID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("session expired or invalid")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}
