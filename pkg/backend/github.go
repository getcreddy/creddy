package backend

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type GitHubConfig struct {
	AppID         int64  `json:"app_id"`
	PrivateKeyPEM string `json:"private_key_pem"`
	InstallationID int64 `json:"installation_id,omitempty"` // Optional, will be discovered if not set
}

type GitHubBackend struct {
	config GitHubConfig
}

type GitHubToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func NewGitHub(configJSON string) (*GitHubBackend, error) {
	var config GitHubConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, fmt.Errorf("invalid github config: %w", err)
	}

	if config.AppID == 0 {
		return nil, fmt.Errorf("app_id is required")
	}
	if config.PrivateKeyPEM == "" {
		return nil, fmt.Errorf("private_key_pem is required")
	}

	return &GitHubBackend{config: config}, nil
}

// GenerateJWT creates a JWT for GitHub App authentication
func (g *GitHubBackend) GenerateJWT() (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(g.config.PrivateKeyPEM))
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Add(-60 * time.Second).Unix(), // Issued 60 seconds ago to account for clock drift
		"exp": now.Add(10 * time.Minute).Unix(),  // JWT expires in 10 minutes (max allowed)
		"iss": g.config.AppID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)
}

// GetInstallationToken generates an installation access token
func (g *GitHubBackend) GetInstallationToken(installationID int64) (*GitHubToken, error) {
	jwtToken, err := g.GenerateJWT()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request installation token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("github API error (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &GitHubToken{
		Token:     result.Token,
		ExpiresAt: result.ExpiresAt,
	}, nil
}

// ListInstallations returns all installations for this GitHub App
func (g *GitHubBackend) ListInstallations() ([]Installation, error) {
	jwtToken, err := g.GenerateJWT()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", "https://api.github.com/app/installations", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list installations: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github API error (%d): %s", resp.StatusCode, string(body))
	}

	var installations []Installation
	if err := json.Unmarshal(body, &installations); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return installations, nil
}

type Installation struct {
	ID      int64  `json:"id"`
	Account struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"account"`
	TargetType string `json:"target_type"`
}

// GetToken generates an ephemeral installation token
// If installationID is 0, it will use the first installation found (or the configured one)
func (g *GitHubBackend) GetToken(installationID int64) (*GitHubToken, error) {
	if installationID == 0 {
		installationID = g.config.InstallationID
	}

	if installationID == 0 {
		// Try to find the first installation
		installations, err := g.ListInstallations()
		if err != nil {
			return nil, fmt.Errorf("no installation_id configured and failed to list: %w", err)
		}
		if len(installations) == 0 {
			return nil, fmt.Errorf("no installations found for this GitHub App")
		}
		installationID = installations[0].ID
	}

	return g.GetInstallationToken(installationID)
}
