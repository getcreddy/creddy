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

var backendCmd = &cobra.Command{
	Use:   "backend",
	Short: "Manage credential backends",
}

var backendAddCmd = &cobra.Command{
	Use:   "add [type]",
	Short: "Add a credential backend",
	Long: `Add a credential backend. Supported types:
  - github: GitHub App for repository access`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		backendType := args[0]

		switch backendType {
		case "github":
			return addGitHubBackend(cmd)
		default:
			return fmt.Errorf("unknown backend type: %s", backendType)
		}
	},
}

var backendListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured backends",
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := viper.GetString("admin.url")
		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}

		resp, err := http.Get(serverURL + "/v1/admin/backends")
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		var results []struct {
			ID        string    `json:"id"`
			Type      string    `json:"type"`
			Name      string    `json:"name"`
			CreatedAt time.Time `json:"created_at"`
		}
		json.Unmarshal(body, &results)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tTYPE\tCREATED")
		for _, r := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Name, r.Type, r.CreatedAt.Format(time.RFC3339))
		}
		w.Flush()

		return nil
	},
}

var backendRemoveCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Remove a credential backend",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		serverURL := viper.GetString("admin.url")
		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}

		req, _ := http.NewRequest("DELETE", serverURL+"/v1/admin/backends/"+name, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
		}

		fmt.Printf("Backend removed: %s\n", name)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(backendCmd)
	backendCmd.AddCommand(backendAddCmd)
	backendCmd.AddCommand(backendListCmd)
	backendCmd.AddCommand(backendRemoveCmd)

	// GitHub backend flags
	backendAddCmd.Flags().Int64("app-id", 0, "GitHub App ID")
	backendAddCmd.Flags().String("private-key", "", "Path to GitHub App private key")
	backendAddCmd.Flags().Int64("installation-id", 0, "GitHub App installation ID (optional)")
	backendAddCmd.Flags().String("name", "", "Name for this backend (defaults to type)")
}

func addGitHubBackend(cmd *cobra.Command) error {
	appID, _ := cmd.Flags().GetInt64("app-id")
	privateKeyPath, _ := cmd.Flags().GetString("private-key")
	installationID, _ := cmd.Flags().GetInt64("installation-id")
	name, _ := cmd.Flags().GetString("name")

	if appID == 0 {
		return fmt.Errorf("--app-id is required for GitHub backend")
	}
	if privateKeyPath == "" {
		return fmt.Errorf("--private-key is required for GitHub backend")
	}
	if name == "" {
		name = "github"
	}

	// Read private key
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	serverURL := viper.GetString("admin.url")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8400"
	}

	config := map[string]interface{}{
		"app_id":          appID,
		"private_key_pem": string(keyData),
	}
	if installationID != 0 {
		config["installation_id"] = installationID
	}

	reqBody, _ := json.Marshal(map[string]interface{}{
		"type":   "github",
		"name":   name,
		"config": config,
	})

	resp, err := http.Post(serverURL+"/v1/admin/backends", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	}
	json.Unmarshal(body, &result)

	fmt.Printf("GitHub backend added: %s\n", result.Name)
	fmt.Printf("  App ID: %d\n", appID)
	if installationID != 0 {
		fmt.Printf("  Installation ID: %d\n", installationID)
	}

	return nil
}
