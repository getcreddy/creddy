package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var enrollCmd = &cobra.Command{
	Use:   "enroll [server-url]",
	Short: "Enroll this machine as an agent",
	Long: `Request enrollment with a creddy server. The server admin must approve
the request before this machine can request credentials.

Example:
  creddy enroll http://creddy-server:8400 --name my-agent`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := args[0]
		name, _ := cmd.Flags().GetString("name")
		pollInterval, _ := cmd.Flags().GetDuration("poll-interval")
		timeout, _ := cmd.Flags().GetDuration("timeout")

		if name == "" {
			// Default to hostname
			hostname, _ := os.Hostname()
			name = hostname
		}

		fmt.Printf("Requesting enrollment as '%s' from %s...\n", name, serverURL)

		// Submit enrollment request
		reqBody, _ := json.Marshal(map[string]string{"name": name})
		resp, err := http.Post(serverURL+"/v1/enroll", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
		}

		var enrollResp struct {
			ID     string `json:"id"`
			Secret string `json:"secret"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(body, &enrollResp); err != nil {
			return fmt.Errorf("invalid response: %w", err)
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
					fmt.Println("Credentials saved to ~/.creddy/config.yaml")
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

	configDir := filepath.Join(home, ".creddy")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	configFile := filepath.Join(configDir, "config.yaml")

	// Simple YAML write
	config := fmt.Sprintf(`# Creddy configuration
server:
  url: %s

agent:
  token: %s
`, serverURL, token)

	return os.WriteFile(configFile, []byte(config), 0600)
}

// Admin commands for managing pending enrollments

var pendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List pending enrollment requests",
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
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
		}

		var pending []struct {
			ID        string    `json:"id"`
			Name      string    `json:"name"`
			CreatedAt time.Time `json:"created_at"`
		}
		if err := json.Unmarshal(body, &pending); err != nil {
			return fmt.Errorf("invalid response: %w", err)
		}

		if len(pending) == 0 {
			fmt.Println("No pending enrollment requests")
			return nil
		}

		fmt.Printf("%-36s  %-20s  %s\n", "ID", "NAME", "REQUESTED")
		fmt.Println("------------------------------------  --------------------  --------------------")
		for _, p := range pending {
			fmt.Printf("%-36s  %-20s  %s\n", p.ID, p.Name, p.CreatedAt.Format(time.RFC3339))
		}

		return nil
	},
}

var approveCmd = &cobra.Command{
	Use:   "approve [id]",
	Short: "Approve a pending enrollment request",
	Args:  cobra.ExactArgs(1),
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
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
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
	Use:   "reject [id]",
	Short: "Reject a pending enrollment request",
	Args:  cobra.ExactArgs(1),
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
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
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

	enrollCmd.Flags().StringP("name", "n", "", "Agent name (default: hostname)")
	enrollCmd.Flags().Duration("poll-interval", 2*time.Second, "How often to poll for approval")
	enrollCmd.Flags().Duration("timeout", 5*time.Minute, "Timeout waiting for approval (0 = forever)")

	approveCmd.Flags().StringSlice("can", []string{}, "Scopes to grant (e.g., github:read,write)")
}
