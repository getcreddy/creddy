package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// parseServerError extracts error message from JSON response or returns raw body
func parseServerError(body []byte) string {
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
		return errResp.Error
	}
	return string(body)
}

// formatEnrollError formats enrollment errors for better user experience
func formatEnrollError(errMsg string) string {
	// Check for unknown backend error and format it nicely
	// Error format: unknown backend "foo" in scope "foo:bar" - available backends: a, b, c
	if strings.Contains(errMsg, "unknown backend") {
		// Extract backend name between first pair of quotes
		start := strings.Index(errMsg, `"`)
		if start != -1 {
			end := strings.Index(errMsg[start+1:], `"`)
			if end != -1 {
				backendName := errMsg[start+1 : start+1+end]

				// Check if there are available backends listed
				if idx := strings.Index(errMsg, "available backends:"); idx != -1 {
					available := strings.TrimSpace(errMsg[idx+len("available backends:"):])
					return fmt.Sprintf("Server doesn't have the %q plugin installed.\nAvailable backends: %s", backendName, available)
				}
				return fmt.Sprintf("Server doesn't have the %q plugin installed (no plugins available)", backendName)
			}
		}
	}
	return errMsg
}


// readLocalAdminToken attempts to read the local admin token for auto-approval
func readLocalAdminToken() string {
	// Check common data directories for the admin token
	paths := []string{
		"/var/lib/creddy/.admin-token",
	}
	
	// Also check user's home directory
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".creddy", ".admin-token"))
	}
	
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

var enrollCmd = &cobra.Command{
	Use:   "enroll [server-url]",
	Short: "Enroll this machine as an agent",
	Long: `Request enrollment with a creddy server. The server admin must approve
the request before this machine can request credentials.

If running on the same machine as the server, the URL is auto-detected.

Example:
  creddy enroll                                    # Auto-detect local server
  creddy enroll http://creddy-server:8400          # Explicit URL
  creddy enroll --name my-agent --can github:read  # With options`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, _ := cmd.Flags().GetString("server")
		
		// Check positional arg first
		if serverURL == "" && len(args) > 0 {
			serverURL = args[0]
		}
		
		// Then env/config
		if serverURL == "" {
			serverURL = viper.GetString("url")
		}
		
		// Try auto-detection
		if serverURL == "" {
			if detected := detectLocalServer(); detected != "" {
				serverURL = detected
				fmt.Printf("Auto-detected local server: %s\n", serverURL)
			}
		}
		
		if serverURL == "" {
			return fmt.Errorf("server URL required (creddy enroll <url> or CREDDY_URL)")
		}
		name, _ := cmd.Flags().GetString("name")
		scopes, _ := cmd.Flags().GetStringSlice("can")
		pollInterval, _ := cmd.Flags().GetDuration("poll-interval")
		timeout, _ := cmd.Flags().GetDuration("timeout")

		if name == "" {
			// Default to hostname
			hostname, _ := os.Hostname()
			name = hostname
		}

		fmt.Printf("Requesting enrollment as '%s' from %s...\n", name, serverURL)
		if len(scopes) > 0 {
			fmt.Printf("Requested permissions: %v\n", scopes)
		}

		// Try to read local admin token for auto-approval
		adminToken := readLocalAdminToken()
		
		// Submit enrollment request
		reqData := map[string]interface{}{"name": name, "scopes": scopes}
		if adminToken != "" {
			reqData["admin_token"] = adminToken
		}
		reqBody, _ := json.Marshal(reqData)
		resp, err := http.Post(serverURL+"/v1/enroll", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			errMsg := parseServerError(body)
			return fmt.Errorf("%s", formatEnrollError(errMsg))
		}

		var enrollResp struct {
			ID     string `json:"id"`
			Secret string `json:"secret"`
			Status string `json:"status"`
			Token  string `json:"token"` // Present if auto-approved
		}
		if err := json.Unmarshal(body, &enrollResp); err != nil {
			return fmt.Errorf("invalid response: %w", err)
		}
		
		// If already approved (local admin token), save and exit
		if enrollResp.Status == "approved" && enrollResp.Token != "" {
			fmt.Println("✓ Enrollment approved (local admin)")
			
			if err := saveCredentials(serverURL, enrollResp.Token); err != nil {
				fmt.Printf("Warning: failed to save credentials: %v\n", err)
				fmt.Printf("Token: %s\n", enrollResp.Token)
				fmt.Println("Set CREDDY_TOKEN environment variable or add to config manually.")
			} else {
				fmt.Println("Credentials saved to ~/.config/creddy/config.yaml")
			}
			
			fmt.Printf("\nYou can now request credentials:\n")
			fmt.Printf("  creddy get github --ttl 10m\n")
			return nil
		}

		fmt.Printf("Enrollment request submitted (ID: %s)\n", enrollResp.ID)
		fmt.Println("Waiting for admin approval...")

		// Poll for approval
		startTime := time.Now()
		for {
			if timeout > 0 && time.Since(startTime) > timeout {
				return fmt.Errorf("timeout waiting for approval")
			}

			time.Sleep(pollInterval)

			statusResp, err := http.Get(fmt.Sprintf("%s/v1/enroll/status?secret=%s", serverURL, enrollResp.Secret))
			if err != nil {
				fmt.Printf("  (connection error, retrying...)\n")
				continue
			}

			statusBody, _ := io.ReadAll(statusResp.Body)
			statusResp.Body.Close()

			var status struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
				Token  string `json:"token"`
				Scopes string `json:"scopes"`
			}
			if err := json.Unmarshal(statusBody, &status); err != nil {
				continue
			}

			switch status.Status {
			case "approved":
				fmt.Println("✓ Enrollment approved!")

				// Save the token to config
				if err := saveCredentials(serverURL, status.Token); err != nil {
					fmt.Printf("Warning: failed to save credentials: %v\n", err)
					fmt.Printf("Token: %s\n", status.Token)
					fmt.Println("Set CREDDY_TOKEN environment variable or add to config manually.")
				} else {
					fmt.Println("Credentials saved to ~/.config/creddy/config.yaml")
				}

				fmt.Printf("\nYou can now request credentials:\n")
				fmt.Printf("  creddy get github --ttl 10m\n")
				return nil

			case "rejected":
				return fmt.Errorf("enrollment request was rejected")

			case "pending":
				// Still waiting
				fmt.Print(".")
			}
		}
	},
}

func saveCredentials(serverURL, token string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(home, ".config", "creddy")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	configFile := filepath.Join(configDir, "config.yaml")

	// Simple YAML write - flat keys match env vars (CREDDY_URL, CREDDY_TOKEN)
	config := fmt.Sprintf(`# Creddy configuration
url: %s
token: %s
`, serverURL, token)

	return os.WriteFile(configFile, []byte(config), 0600)
}

// Admin commands for managing pending enrollments

var pendingCmd = &cobra.Command{
	Use:          "pending",
	Short:        "List pending enrollment requests",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := viper.GetString("admin.url")
		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}

		resp, err := http.Get(serverURL + "/v1/admin/pending")
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s", parseServerError(body))
		}

		var pending []struct {
			ID        string    `json:"id"`
			Name      string    `json:"name"`
			Type      string    `json:"type"`
			Scopes    string    `json:"scopes"`
			CreatedAt time.Time `json:"created_at"`
		}
		if err := json.Unmarshal(body, &pending); err != nil {
			return fmt.Errorf("invalid response: %w", err)
		}

		if len(pending) == 0 {
			fmt.Println("No pending requests")
			return nil
		}

		fmt.Printf("%-36s  %-10s  %-16s  %-30s  %s\n", "ID", "TYPE", "NAME", "REQUESTED SCOPES", "REQUESTED")
		fmt.Println("------------------------------------  ----------  ----------------  ------------------------------  --------------------")
		for _, p := range pending {
			scopes := p.Scopes
			if scopes == "" || scopes == "[]" || scopes == "null" {
				scopes = "(none)"
			}
			reqType := p.Type
			if reqType == "" {
				reqType = "enroll"
			}
			fmt.Printf("%-36s  %-10s  %-16s  %-30s  %s\n", p.ID, reqType, p.Name, scopes, p.CreatedAt.Format(time.RFC3339))
		}

		return nil
	},
}

var approveCmd = &cobra.Command{
	Use:          "approve [id]",
	Short:        "Approve a pending enrollment request",
	SilenceUsage: true,
	Args:         cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		scopes, _ := cmd.Flags().GetStringSlice("can")

		serverURL := viper.GetString("admin.url")
		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}

		reqBody, _ := json.Marshal(map[string]interface{}{"scopes": scopes})
		resp, err := http.Post(serverURL+"/v1/admin/pending/"+id+"/approve", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s", parseServerError(body))
		}

		var result struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Approved bool   `json:"approved"`
		}
		json.Unmarshal(body, &result)

		fmt.Printf("✓ Approved enrollment for '%s'\n", result.Name)
		return nil
	},
}

var rejectCmd = &cobra.Command{
	Use:          "reject [id]",
	Short:        "Reject a pending enrollment request",
	SilenceUsage: true,
	Args:         cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]

		serverURL := viper.GetString("admin.url")
		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}

		resp, err := http.Post(serverURL+"/v1/admin/pending/"+id+"/reject", "application/json", nil)
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("%s", parseServerError(body))
		}

		fmt.Println("✓ Enrollment rejected")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(enrollCmd)
	rootCmd.AddCommand(pendingCmd)
	rootCmd.AddCommand(approveCmd)
	rootCmd.AddCommand(rejectCmd)

	enrollCmd.Flags().StringP("server", "s", "", "Creddy server URL (or set CREDDY_URL)")
	enrollCmd.Flags().StringP("name", "n", "", "Agent name (default: hostname)")
	enrollCmd.Flags().StringSlice("can", []string{}, "Permissions to request (e.g., github:read,write)")
	enrollCmd.Flags().Duration("poll-interval", 2*time.Second, "How often to poll for approval")
	enrollCmd.Flags().Duration("timeout", 5*time.Minute, "Timeout waiting for approval (0 = forever)")
}
