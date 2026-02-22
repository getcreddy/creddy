package backend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
// If repos is non-empty, the token is scoped to only those repositories
// If readOnly is true, token gets read-only permissions
func (g *GitHubBackend) GetInstallationToken(installationID int64, repos []string, readOnly bool) (*GitHubToken, error) {
	jwtToken, err := g.GenerateJWT()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)

	// Build request body
	reqData := make(map[string]interface{})

	if len(repos) > 0 {
		// Scope token to specific repositories
		// GitHub API wants just repo names, not owner/repo
		repoNames := make([]string, len(repos))
		for i, repo := range repos {
			// Extract repo name from owner/repo format
			parts := splitRepo(repo)
			if len(parts) == 2 {
				repoNames[i] = parts[1]
			} else {
				repoNames[i] = repo
			}
		}
		reqData["repositories"] = repoNames
	}

	if readOnly {
		// Request read-only permissions
		reqData["permissions"] = map[string]string{
			"contents": "read",
			"metadata": "read",
		}
	}

	var reqBody io.Reader
	if len(reqData) > 0 {
		bodyJSON, _ := json.Marshal(reqData)
		reqBody = bytes.NewReader(bodyJSON)
	}

	req, err := http.NewRequest("POST", url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

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

func splitRepo(repo string) []string {
	for i, c := range repo {
		if c == '/' {
			return []string{repo[:i], repo[i+1:]}
		}
	}
	return []string{repo}
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
// If repos is non-empty, the token is scoped to only those repositories
func (g *GitHubBackend) GetToken(installationID int64, repos []string, readOnly bool) (*GitHubToken, error) {
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

	return g.GetInstallationToken(installationID, repos, readOnly)
}

// ParseGitHubScope parses a scope like "github:owner/repo:read" into parts
// Returns: repo pattern, permission (read/write), isGitHub
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
// Scope format: "github:owner/repo[:read|:write]" or "github:owner/*" or "github:*"
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

// ExtractReposFromScopes extracts all repo patterns from github scopes
// Returns list of repos and the most restrictive permission
func ExtractReposFromScopes(scopes []string) (repos []string, readOnly bool) {
	hasWrite := false
	hasRead := false
	
	for _, scope := range scopes {
		pattern, perm, isGitHub := ParseGitHubScope(scope)
		if !isGitHub {
			continue
		}
		
		if perm == "write" {
			hasWrite = true
		} else {
			hasRead = true
		}
		
		// Skip wildcards - they mean "all repos"
		if pattern == "*" || strings.HasSuffix(pattern, "/*") {
			// Can't enumerate wildcard repos
			continue
		}
		
		repos = append(repos, pattern)
	}
	
	// If only read scopes, force read-only
	readOnly = hasRead && !hasWrite
	return repos, readOnly
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
