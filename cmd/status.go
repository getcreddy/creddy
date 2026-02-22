package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current agent status",
	Long: `Display this agent's enrollment status, approved scopes, and active credentials.

Example:
  creddy status
  creddy status --server http://creddy:8400`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, _ := cmd.Flags().GetString("server")
		if serverURL == "" {
			serverURL = viper.GetString("url")
		}
		if serverURL == "" {
			return fmt.Errorf("server URL required (--server or CREDDY_URL)")
		}

		token := viper.GetString("token")
		if token == "" {
			return fmt.Errorf("not enrolled (no token found). Run 'creddy enroll' first")
		}

		req, err := http.NewRequest("GET", serverURL+"/v1/status", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("invalid or expired token. You may need to re-enroll")
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s", parseServerError(body))
		}

		var status struct {
			Name              string    `json:"name"`
			Status            string    `json:"status"`
			Scopes            []string  `json:"scopes"`
			CreatedAt         time.Time `json:"created_at"`
			LastUsed          time.Time `json:"last_used"`
			ActiveCredentials []struct {
				ID        string    `json:"id"`
				Backend   string    `json:"backend"`
				ExpiresAt time.Time `json:"expires_at"`
			} `json:"active_credentials"`
			PendingAmendments []struct {
				ID        string   `json:"id"`
				Scopes    []string `json:"scopes"`
				CreatedAt time.Time `json:"created_at"`
			} `json:"pending_amendments"`
		}
		if err := json.Unmarshal(body, &status); err != nil {
			return fmt.Errorf("invalid response: %w", err)
		}

		// Display status
		fmt.Printf("Agent: %s\n", status.Name)
		fmt.Printf("Status: %s\n", status.Status)
		fmt.Printf("Enrolled: %s\n", status.CreatedAt.Format(time.RFC3339))
		if !status.LastUsed.IsZero() {
			fmt.Printf("Last used: %s\n", status.LastUsed.Format(time.RFC3339))
		}

		fmt.Println()
		fmt.Println("Scopes:")
		if len(status.Scopes) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, s := range status.Scopes {
				fmt.Printf("  • %s\n", s)
			}
		}

		if len(status.PendingAmendments) > 0 {
			fmt.Println()
			fmt.Println("Pending scope requests:")
			for _, a := range status.PendingAmendments {
				fmt.Printf("  • %v (requested %s)\n", a.Scopes, a.CreatedAt.Format(time.RFC3339))
			}
		}

		if len(status.ActiveCredentials) > 0 {
			fmt.Println()
			fmt.Println("Active credentials:")
			for _, c := range status.ActiveCredentials {
				ttl := time.Until(c.ExpiresAt).Round(time.Second)
				if ttl < 0 {
					fmt.Printf("  • %s: expired\n", c.Backend)
				} else {
					fmt.Printf("  • %s: expires in %s\n", c.Backend, ttl)
				}
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
	statusCmd.Flags().StringP("server", "s", "", "Creddy server URL (or set CREDDY_URL)")
}
