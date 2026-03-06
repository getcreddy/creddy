package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage agent identities",
}

var agentCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new agent identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		scopes, _ := cmd.Flags().GetStringSlice("can")

		serverURL := viper.GetString("admin.url")
		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}

		reqBody, _ := json.Marshal(map[string]interface{}{
			"name":   name,
			"scopes": scopes,
		})

		resp, err := http.Post(serverURL+"/v1/admin/agents", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
		}

		var result struct {
			ID        string    `json:"id"`
			Name      string    `json:"name"`
			Token     string    `json:"token"`
			Scopes    []string  `json:"scopes"`
			CreatedAt time.Time `json:"created_at"`
			ExpiresAt *time.Time `json:"expires_at,omitempty"`
			ServerURL string    `json:"server_url,omitempty"`
			OIDC      *struct {
				ClientID     string `json:"client_id"`
				ClientSecret string `json:"client_secret"`
			} `json:"oidc,omitempty"`
			SigningKeyID string `json:"signing_key_id,omitempty"`
			SigningEmail string `json:"signing_email,omitempty"`
		}
		json.Unmarshal(body, &result)

		fmt.Printf("Agent created: %s\n", result.Name)
		fmt.Printf("ID: %s\n", result.ID)
		if len(result.Scopes) > 0 {
			fmt.Printf("Scopes: %v\n", result.Scopes)
		}
		if result.ExpiresAt != nil {
			fmt.Printf("Expires: %s\n", result.ExpiresAt.Format(time.RFC3339))
		}

		fmt.Printf("\n⚠️  Credentials (save these, they won't be shown again):\n\n")

		fmt.Printf("Vend Token:\n")
		fmt.Printf("  %s\n", result.Token)

		if result.OIDC != nil {
			fmt.Printf("\nOIDC Credentials:\n")
			fmt.Printf("  Client ID:     %s\n", result.OIDC.ClientID)
			fmt.Printf("  Client Secret: %s\n", result.OIDC.ClientSecret)
		}

		if result.SigningKeyID != "" {
			fmt.Printf("\nGit Signing:\n")
			fmt.Printf("  Key ID: %s\n", result.SigningKeyID)
			fmt.Printf("  Email:  %s\n", result.SigningEmail)
		}

		// Use public URL from server if available, otherwise fall back to local URL
		displayURL := serverURL
		if result.ServerURL != "" {
			displayURL = result.ServerURL
		}

		fmt.Printf("\nSet on agent machines:\n")
		fmt.Printf("  export CREDDY_URL=%s\n", displayURL)
		fmt.Printf("  export CREDDY_TOKEN=%s\n", result.Token)

		if result.OIDC != nil {
			fmt.Printf("\nOr use OIDC:\n")
			fmt.Printf("  export CREDDY_URL=%s\n", displayURL)
			fmt.Printf("  export CREDDY_CLIENT_ID=%s\n", result.OIDC.ClientID)
			fmt.Printf("  export CREDDY_CLIENT_SECRET=%s\n", result.OIDC.ClientSecret)
		}

		return nil
	},
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := viper.GetString("admin.url")
		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}

		resp, err := http.Get(serverURL + "/v1/admin/agents")
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		var results []struct {
			ID        string     `json:"id"`
			Name      string     `json:"name"`
			Scopes    string     `json:"scopes"`
			CreatedAt time.Time  `json:"created_at"`
			LastUsed  *time.Time `json:"last_used"`
		}
		json.Unmarshal(body, &results)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSCOPES\tLAST USED")
		for _, r := range results {
			lastUsed := "never"
			if r.LastUsed != nil {
				lastUsed = r.LastUsed.Format(time.RFC3339)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Name, r.Scopes, lastUsed)
		}
		w.Flush()

		return nil
	},
}

var agentRemoveCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Remove an agent",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		serverURL := viper.GetString("admin.url")
		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}

		req, _ := http.NewRequest("DELETE", serverURL+"/v1/admin/agents/"+name, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("agent not found: %s", name)
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
		}

		fmt.Printf("Agent removed: %s\n", name)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)
	agentCmd.AddCommand(agentCreateCmd)
	agentCmd.AddCommand(agentListCmd)
	agentCmd.AddCommand(agentRemoveCmd)

	agentCreateCmd.Flags().StringSlice("can", []string{}, "Scopes this agent can request (e.g., github:read,write)")
}
