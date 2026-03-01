package webhooks

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// PostmarkInbound represents the webhook payload from Postmark
type PostmarkInbound struct {
	From          string `json:"From"`
	FromName      string `json:"FromName"`
	To            string `json:"To"`
	Subject       string `json:"Subject"`
	TextBody      string `json:"TextBody"`
	HtmlBody      string `json:"HtmlBody"`
	MessageID     string `json:"MessageID"`
	Date          string `json:"Date"`
	OriginalRecipient string `json:"OriginalRecipient"`
}

// PendingSetup tracks a pending Anthropic setup request
type PendingSetup struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`        // creddy-xxx@connect.creddy.dev
	BackendID    string    `json:"backend_id"`   // Creddy backend ID
	Status       string    `json:"status"`       // pending, invite_received, completing, completed, failed
	InviteURL    string    `json:"invite_url"`   // Extracted from email
	ErrorMessage string    `json:"error_message"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// SetupStore interface for storing pending setups
type SetupStore interface {
	GetByEmail(email string) (*PendingSetup, error)
	Update(setup *PendingSetup) error
}

// InviteProcessor handles the actual invite acceptance
type InviteProcessor interface {
	ProcessInvite(setup *PendingSetup) error
}

// PostmarkHandler handles inbound emails from Postmark
type PostmarkHandler struct {
	store     SetupStore
	processor InviteProcessor
}

// NewPostmarkHandler creates a new Postmark webhook handler
func NewPostmarkHandler(store SetupStore, processor InviteProcessor) *PostmarkHandler {
	return &PostmarkHandler{
		store:     store,
		processor: processor,
	}
}

// HandleInbound handles POST /api/webhooks/postmark
func (h *PostmarkHandler) HandleInbound(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload PostmarkInbound
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("Failed to parse Postmark payload: %v", err)
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	log.Printf("Received inbound email from %s to %s: %s", payload.From, payload.To, payload.Subject)

	// Extract the local part of the To address
	toEmail := strings.ToLower(payload.To)
	if payload.OriginalRecipient != "" {
		toEmail = strings.ToLower(payload.OriginalRecipient)
	}

	// Look up the pending setup
	setup, err := h.store.GetByEmail(toEmail)
	if err != nil {
		log.Printf("No pending setup for email %s: %v", toEmail, err)
		// Return 200 anyway so Postmark doesn't retry
		w.WriteHeader(http.StatusOK)
		return
	}

	// Check if this is an Anthropic invite
	if !isAnthropicInvite(payload) {
		log.Printf("Email from %s is not an Anthropic invite", payload.From)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract the invite URL
	inviteURL := extractAnthropicInviteURL(payload.HtmlBody)
	if inviteURL == "" {
		inviteURL = extractAnthropicInviteURL(payload.TextBody)
	}
	if inviteURL == "" {
		log.Printf("Could not extract invite URL from email")
		setup.Status = "failed"
		setup.ErrorMessage = "Could not extract invite URL from email"
		setup.UpdatedAt = time.Now()
		h.store.Update(setup)
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Printf("Extracted invite URL: %s", inviteURL)

	// Update setup with invite URL
	setup.Status = "invite_received"
	setup.InviteURL = inviteURL
	setup.UpdatedAt = time.Now()
	if err := h.store.Update(setup); err != nil {
		log.Printf("Failed to update setup: %v", err)
	}

	// Process the invite asynchronously
	go func() {
		setup.Status = "completing"
		setup.UpdatedAt = time.Now()
		h.store.Update(setup)

		if err := h.processor.ProcessInvite(setup); err != nil {
			log.Printf("Failed to process invite: %v", err)
			setup.Status = "failed"
			setup.ErrorMessage = err.Error()
		} else {
			setup.Status = "completed"
		}
		setup.UpdatedAt = time.Now()
		h.store.Update(setup)
	}()

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

// isAnthropicInvite checks if the email is from Anthropic
func isAnthropicInvite(payload PostmarkInbound) bool {
	from := strings.ToLower(payload.From)
	subject := strings.ToLower(payload.Subject)
	
	// Check sender
	if !strings.Contains(from, "anthropic") && !strings.Contains(from, "claude") {
		return false
	}
	
	// Check subject for invite keywords
	if strings.Contains(subject, "invite") || 
	   strings.Contains(subject, "join") ||
	   strings.Contains(subject, "added") {
		return true
	}
	
	return false
}

// extractAnthropicInviteURL finds the invite/accept URL in email body
func extractAnthropicInviteURL(body string) string {
	// Look for URLs containing invite/accept patterns
	// Anthropic uses both console.anthropic.com and platform.claude.com
	patterns := []string{
		`https://console\.anthropic\.com/[^\s"'<>]*accept[^\s"'<>]*`,
		`https://console\.anthropic\.com/[^\s"'<>]*invite[^\s"'<>]*`,
		`https://platform\.claude\.com/[^\s"'<>]*accept[^\s"'<>]*`,
		`https://platform\.claude\.com/[^\s"'<>]*invite[^\s"'<>]*`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		match := re.FindString(body)
		if match != "" {
			// Clean up any trailing punctuation
			match = strings.TrimRight(match, ".,;:\"')")
			return match
		}
	}
	
	return ""
}
