package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

var adminTokensCmd = &cobra.Command{
	Use:   "tokens",
	Short: "List all active tokens",
	Long: `List all active tokens across all agents.

Examples:
  creddy admin tokens
  creddy admin tokens --backend anthropic
  creddy admin tokens --agent my-agent`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		flagServer, _ := cmd.Flags().GetString("server")
		serverURL := getServerURL(flagServer)
		if serverURL == "" {
			return fmt.Errorf("server URL required")
		}

		backend, _ := cmd.Flags().GetString("backend")
		agent, _ := cmd.Flags().GetString("agent")
		jsonOutput, _ := cmd.Flags().GetBool("json")

		url := serverURL + "/v1/admin/tokens"
		sep := "?"
		if backend != "" {
			url += sep + "backend=" + backend
			sep = "&"
		}
		if agent != "" {
			url += sep + "agent=" + agent
		}

		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("server error: %s", string(body))
		}

		var tokens []struct {
			ID         string    `json:"id"`
			AgentID    string    `json:"agent_id"`
			AgentName  string    `json:"agent_name"`
			Backend    string    `json:"backend"`
			ExpiresAt  time.Time `json:"expires_at"`
			CreatedAt  time.Time `json:"created_at"`
		}

		if err := json.Unmarshal(body, &tokens); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		if jsonOutput {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(tokens)
		}

		if len(tokens) == 0 {
			fmt.Println("No active tokens")
			return nil
		}

		fmt.Printf("%-36s  %-15s  %-12s  %s\n", "ID", "AGENT", "BACKEND", "EXPIRES")
		fmt.Printf("%-36s  %-15s  %-12s  %s\n", "------------------------------------", "---------------", "------------", "-------")
		for _, t := range tokens {
			ttl := time.Until(t.ExpiresAt).Round(time.Second)
			expires := fmt.Sprintf("in %s", ttl)
			if ttl < 0 {
				expires = "expired"
			}
			name := t.AgentName
			if len(name) > 15 {
				name = name[:12] + "..."
			}
			fmt.Printf("%-36s  %-15s  %-12s  %s\n", t.ID, name, t.Backend, expires)
		}

		return nil
	},
}

var adminRevokeTokenCmd = &cobra.Command{
	Use:   "revoke-token [id]",
	Short: "Revoke an active token",
	Long: `Revoke an active token by ID. Use 'creddy admin tokens' to list token IDs.

Example:
  creddy admin revoke-token abc123`,
	SilenceUsage: true,
	Args:         cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tokenID := args[0]

		flagServer, _ := cmd.Flags().GetString("server")
		serverURL := getServerURL(flagServer)
		if serverURL == "" {
			return fmt.Errorf("server URL required")
		}

		req, err := http.NewRequest("DELETE", serverURL+"/v1/admin/tokens/"+tokenID, nil)
		if err != nil {
			return err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("token not found: %s", tokenID)
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("server error: %s", string(body))
		}

		fmt.Printf("✓ Token %s revoked\n", tokenID)
		return nil
	},
}

func init() {
	adminCmd.AddCommand(adminTokensCmd)
	adminCmd.AddCommand(adminRevokeTokenCmd)

	adminTokensCmd.Flags().StringP("server", "s", "", "Creddy server URL")
	adminTokensCmd.Flags().String("backend", "", "Filter by backend (e.g., anthropic)")
	adminTokensCmd.Flags().String("agent", "", "Filter by agent name")
	adminTokensCmd.Flags().Bool("json", false, "Output as JSON")

	adminRevokeTokenCmd.Flags().StringP("server", "s", "", "Creddy server URL")
}
