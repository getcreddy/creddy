package webhooks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/playwright-community/playwright-go"
)

// AnthropicSession holds the captured session data
type AnthropicSession struct {
	SessionKey    string    `json:"session_key"`
	OrgID         string    `json:"org_id"`
	UserID        string    `json:"user_id"`
	Email         string    `json:"email"`
	Password      string    `json:"password"` // Generated password, stored encrypted
	CapturedAt    time.Time `json:"captured_at"`
	ExpiresAt     time.Time `json:"expires_at"` // Estimated
}

// SessionStore interface for storing captured sessions
type SessionStore interface {
	SaveSession(backendID string, session *AnthropicSession) error
}

// AnthropicInviteProcessor handles accepting Anthropic invites via browser automation
type AnthropicInviteProcessor struct {
	sessionStore SessionStore
	pw           *playwright.Playwright
	browser      playwright.Browser
}

// NewAnthropicInviteProcessor creates a new processor
func NewAnthropicInviteProcessor(sessionStore SessionStore) (*AnthropicInviteProcessor, error) {
	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to start playwright: %w", err)
	}

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		pw.Stop()
		return nil, fmt.Errorf("failed to launch browser: %w", err)
	}

	return &AnthropicInviteProcessor{
		sessionStore: sessionStore,
		pw:           pw,
		browser:      browser,
	}, nil
}

// Close cleans up browser resources
func (p *AnthropicInviteProcessor) Close() {
	if p.browser != nil {
		p.browser.Close()
	}
	if p.pw != nil {
		p.pw.Stop()
	}
}

// ProcessInvite accepts an Anthropic invite and captures the session
func (p *AnthropicInviteProcessor) ProcessInvite(setup *PendingSetup) error {
	_, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Printf("Processing invite for %s: %s", setup.Email, setup.InviteURL)

	// Create a new browser context for this invite
	browserCtx, err := p.browser.NewContext()
	if err != nil {
		return fmt.Errorf("failed to create browser context: %w", err)
	}
	defer browserCtx.Close()

	page, err := browserCtx.NewPage()
	if err != nil {
		return fmt.Errorf("failed to create page: %w", err)
	}

	// Navigate to the invite URL
	log.Printf("Navigating to invite URL...")
	if _, err := page.Goto(setup.InviteURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(30000),
	}); err != nil {
		return fmt.Errorf("failed to navigate to invite URL: %w", err)
	}

	// Generate a secure password for this account
	password := generateSecurePassword()

	// Wait a moment for the page to fully load
	page.WaitForTimeout(2000)

	// Check if we need to create an account or just accept
	// The flow depends on whether the email already has an Anthropic account
	
	// Look for password field (new account creation)
	passwordField := page.Locator("input[type='password']")
	hasPasswordField, _ := passwordField.Count()
	
	if hasPasswordField > 0 {
		log.Printf("Creating new account...")
		if err := p.createAccount(page, setup.Email, password); err != nil {
			return fmt.Errorf("failed to create account: %w", err)
		}
	} else {
		log.Printf("Accepting invite for existing account flow...")
		// Click accept button if present
		acceptBtn := page.Locator("button:has-text('Accept'), button:has-text('Join')")
		if count, _ := acceptBtn.Count(); count > 0 {
			if err := acceptBtn.First().Click(); err != nil {
				return fmt.Errorf("failed to click accept button: %w", err)
			}
			page.WaitForTimeout(3000)
		}
	}

	// Wait for redirect to console/dashboard
	log.Printf("Waiting for console redirect...")
	if err := page.WaitForURL("**/platform.claude.com/**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(30000),
	}); err != nil {
		// Try alternative URL patterns
		currentURL := page.URL()
		log.Printf("Current URL: %s", currentURL)
	}

	// Extract session cookie
	log.Printf("Extracting session...")
	cookies, err := browserCtx.Cookies()
	if err != nil {
		return fmt.Errorf("failed to get cookies: %w", err)
	}

	var sessionKey string
	for _, cookie := range cookies {
		if cookie.Name == "sessionKey" {
			sessionKey = cookie.Value
			break
		}
	}

	if sessionKey == "" {
		return errors.New("failed to capture sessionKey cookie")
	}

	log.Printf("Session captured successfully")

	// Extract org ID from URL or page content
	orgID := extractOrgID(page.URL())

	// Save the session
	session := &AnthropicSession{
		SessionKey: sessionKey,
		OrgID:      orgID,
		Email:      setup.Email,
		Password:   password, // Should be encrypted before storage
		CapturedAt: time.Now(),
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour), // Assume 30 day session
	}

	if err := p.sessionStore.SaveSession(setup.BackendID, session); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	return nil
}

// createAccount fills out the new account creation form
func (p *AnthropicInviteProcessor) createAccount(page playwright.Page, email, password string) error {
	// Fill password fields
	passwordFields := page.Locator("input[type='password']")
	count, _ := passwordFields.Count()
	
	for i := 0; i < count; i++ {
		field := passwordFields.Nth(i)
		if err := field.Fill(password); err != nil {
			log.Printf("Failed to fill password field %d: %v", i, err)
		}
	}

	// Look for name field and fill if present
	nameField := page.Locator("input[name='name'], input[placeholder*='name' i]")
	if count, _ := nameField.Count(); count > 0 {
		if err := nameField.First().Fill("Creddy Bot"); err != nil {
			log.Printf("Failed to fill name field: %v", err)
		}
	}

	// Check any required checkboxes (terms, etc.)
	checkboxes := page.Locator("input[type='checkbox']")
	checkboxCount, _ := checkboxes.Count()
	for i := 0; i < checkboxCount; i++ {
		checkbox := checkboxes.Nth(i)
		checked, _ := checkbox.IsChecked()
		if !checked {
			checkbox.Check()
		}
	}

	// Click submit/create button
	submitBtn := page.Locator("button[type='submit'], button:has-text('Create'), button:has-text('Sign up'), button:has-text('Continue')")
	if count, _ := submitBtn.Count(); count > 0 {
		if err := submitBtn.First().Click(); err != nil {
			return fmt.Errorf("failed to click submit: %w", err)
		}
	}

	// Wait for navigation
	page.WaitForTimeout(5000)
	
	return nil
}

// generateSecurePassword creates a random password
func generateSecurePassword() string {
	bytes := make([]byte, 24)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// extractOrgID tries to extract org ID from URL
func extractOrgID(url string) string {
	// URL might be like: https://platform.claude.com/settings/...?organization=xxx
	// or embedded in path
	// This is a simplified extraction
	return ""
}
