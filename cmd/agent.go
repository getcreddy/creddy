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
		}
		json.Unmarshal(body, &result)

		fmt.Printf("Agent created: %s\n", result.Name)
		fmt.Printf("ID: %s\n", result.ID)
		if len(result.Scopes) > 0 {
			fmt.Printf("Scopes: %v\n", result.Scopes)
		}
		fmt.Printf("\n⚠️  Agent token (save this, it won't be shown again):\n")
		fmt.Printf("  %s\n", result.Token)
		fmt.Printf("\nSet on agent machines:\n")
		fmt.Printf("  export CREDDY_URL=%s\n", serverURL)
		fmt.Printf("  export CREDDY_TOKEN=%s\n", result.Token)

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

var agentRevokeCmd = &cobra.Command{
	Use:   "revoke [name]",
	Short: "Revoke an agent's token",
	Args:  cobra.ExactArgs(1),
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

		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
		}

		fmt.Printf("Agent revoked: %s\n", name)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)
	agentCmd.AddCommand(agentCreateCmd)
	agentCmd.AddCommand(agentListCmd)
	agentCmd.AddCommand(agentRevokeCmd)

	agentCreateCmd.Flags().StringSlice("can", []string{}, "Scopes this agent can request (e.g., github:read,write)")
}
