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
	Use:   "add <plugin-type>",
	Short: "Add a credential backend",
	Long: `Add a credential backend using any installed plugin.

Examples:
  creddy backend add github --config '{"app_id": 123, "private_key_pem": "..."}'
  creddy backend add anthropic --config '{"admin_key": "sk-admin-..."}'
  creddy backend add aws --config-file ./aws-config.json
  creddy backend add github --name github-work --config '{"app_id": 456, ...}'

Use 'creddy plugin list' to see available plugins.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pluginType := args[0]
		return addBackend(cmd, pluginType)
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

	// Generic backend flags
	backendAddCmd.Flags().StringP("config", "c", "", "JSON configuration for the backend")
	backendAddCmd.Flags().StringP("config-file", "f", "", "Path to JSON file with backend configuration")
	backendAddCmd.Flags().String("name", "", "Name for this backend instance (defaults to plugin type)")
}

func addBackend(cmd *cobra.Command, pluginType string) error {
	configJSON, _ := cmd.Flags().GetString("config")
	configFile, _ := cmd.Flags().GetString("config-file")
	name, _ := cmd.Flags().GetString("name")

	// Validate that we have config from either flag
	if configJSON == "" && configFile == "" {
		return fmt.Errorf("either --config or --config-file is required")
	}
	if configJSON != "" && configFile != "" {
		return fmt.Errorf("cannot specify both --config and --config-file")
	}

	// Read config from file if specified
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		configJSON = string(data)
	}

	// Validate that config is valid JSON
	var configMap map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &configMap); err != nil {
		return fmt.Errorf("invalid JSON config: %w", err)
	}

	// Default name to plugin type
	if name == "" {
		name = pluginType
	}

	serverURL := viper.GetString("admin.url")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8400"
	}

	reqBody, _ := json.Marshal(map[string]interface{}{
		"type":   pluginType,
		"name":   name,
		"config": json.RawMessage(configJSON),
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
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("Backend added: %s (type: %s)\n", result.Name, result.Type)
	return nil
}
