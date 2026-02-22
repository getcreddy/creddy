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

var getCmd = &cobra.Command{
	Use:   "get [backend]",
	Short: "Request credentials from a backend",
	Long: `Request ephemeral credentials from a configured backend.

Examples:
  creddy get github --ttl 10m
  creddy get github --repo owner/repo --ttl 10m
  creddy get github --repo owner/repo1 --repo owner/repo2`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		backend := args[0]
		ttl, _ := cmd.Flags().GetDuration("ttl")
		scope, _ := cmd.Flags().GetStringSlice("scope")
		repos, _ := cmd.Flags().GetStringSlice("repo")
		outputJSON, _ := cmd.Flags().GetBool("json")

		serverURL := viper.GetString("url")
		token := viper.GetString("token")

		if serverURL == "" {
			return fmt.Errorf("CREDDY_URL not set")
		}
		if token == "" {
			return fmt.Errorf("CREDDY_TOKEN not set")
		}

		// Build request
		url := fmt.Sprintf("%s/v1/credentials/%s?ttl=%s", serverURL, backend, ttl)
		for _, s := range scope {
			url += "&scope=" + s
		}
		for _, r := range repos {
			url += "&repo=" + r
		}

		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect to creddy server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
		}

		if outputJSON {
			fmt.Println(string(body))
		} else {
			var result struct {
				Token     string    `json:"token"`
				ExpiresAt time.Time `json:"expires_at"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return err
			}
			fmt.Println(result.Token)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
	getCmd.Flags().Duration("ttl", 10*time.Minute, "Time-to-live for the credential")
	getCmd.Flags().StringSlice("scope", []string{}, "Requested scopes")
	getCmd.Flags().StringSlice("repo", []string{}, "Repository to scope token to (owner/repo)")
	getCmd.Flags().Bool("json", false, "Output full response as JSON")
}
