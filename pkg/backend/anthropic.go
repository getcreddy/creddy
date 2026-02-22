package backend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AnthropicConfig holds the admin API credentials
type AnthropicConfig struct {
	AdminKey string `json:"admin_key"` // Admin API key for managing keys
}

type AnthropicBackend struct {
	config  AnthropicConfig
	baseURL string
}

type AnthropicAPIKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Key       string    `json:"key"` // Only returned on creation
	CreatedAt time.Time `json:"created_at"`
}

func NewAnthropic(configJSON string) (*AnthropicBackend, error) {
	var config AnthropicConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, fmt.Errorf("invalid anthropic config: %w", err)
	}

	if config.AdminKey == "" {
		return nil, fmt.Errorf("admin_key is required")
	}

	return &AnthropicBackend{
		config:  config,
		baseURL: "https://api.anthropic.com",
	}, nil
}

// CreateAPIKey creates a new API key via the Admin API
func (a *AnthropicBackend) CreateAPIKey(name string) (*AnthropicAPIKey, error) {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"name": name,
	})

	req, err := http.NewRequest("POST", a.baseURL+"/v1/api_keys", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-api-key", a.config.AdminKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("anthropic API error (%d): %s", resp.StatusCode, string(body))
	}

	var key AnthropicAPIKey
	if err := json.Unmarshal(body, &key); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &key, nil
}

// DeleteAPIKey deletes an API key via the Admin API
func (a *AnthropicBackend) DeleteAPIKey(keyID string) error {
	req, err := http.NewRequest("DELETE", a.baseURL+"/v1/api_keys/"+keyID, nil)
	if err != nil {
		return err
	}

	req.Header.Set("x-api-key", a.config.AdminKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("anthropic API error (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// AnthropicBackend implements both Backend and RevocableBackend
func (a *AnthropicBackend) GetToken(req TokenRequest) (*Token, error) {
	token, _, err := a.GetTokenWithID(req)
	return token, err
}

func (a *AnthropicBackend) GetTokenWithID(req TokenRequest) (*Token, string, error) {
	// Create a new API key with a unique name
	name := fmt.Sprintf("creddy-%d", time.Now().UnixNano())
	
	apiKey, err := a.CreateAPIKey(name)
	if err != nil {
		return nil, "", err
	}

	// Anthropic keys don't have inherent expiry, we manage that
	// Return the key ID so we can delete it later
	return &Token{
		Value:     apiKey.Key,
		ExpiresAt: time.Now().Add(1 * time.Hour), // We'll enforce TTL ourselves
	}, apiKey.ID, nil
}

func (a *AnthropicBackend) RevokeToken(externalID string) error {
	return a.DeleteAPIKey(externalID)
}

func (a *AnthropicBackend) Type() string {
	return "anthropic"
}
