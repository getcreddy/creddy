package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func parseError(body []byte) string {
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
		return errResp.Error
	}
	return string(body)
}

// formatRequestError formats scope request errors for better user experience
func formatRequestError(errMsg string) string {
	// Check for unknown backend error and format it nicely
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

var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "Request additional permissions",
	Long: `Request additional scopes for an existing agent. The server admin
must approve the request before the new permissions take effect.

Example:
  creddy request --can github:owner/repo3
  creddy request --can github:owner/repo4:read`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		scopes, _ := cmd.Flags().GetStringSlice("can")

		if len(scopes) == 0 {
			return fmt.Errorf("at least one --can flag is required")
		}

		serverURL := viper.GetString("url")
		token := viper.GetString("token")

		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}
		if token == "" {
			if token == "" {
			return fmt.Errorf("not enrolled. Run 'creddy init <server-url>' first")
		}
		}

		reqBody, _ := json.Marshal(map[string]interface{}{
			"scopes": scopes,
		})

		req, err := http.NewRequest("POST", serverURL+"/v1/request", bytes.NewReader(reqBody))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			errMsg := parseError(body)
			return fmt.Errorf("%s", formatRequestError(errMsg))
		}

		var result struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}
		json.Unmarshal(body, &result)

		fmt.Printf("Scope request submitted (ID: %s)\n", result.ID)
		fmt.Println("Waiting for admin approval...")
		fmt.Printf("\nRequested: %v\n", scopes)
		fmt.Println("\nOnce approved, your next `creddy get` will include the new repos.")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(requestCmd)
	requestCmd.Flags().StringSlice("can", []string{}, "Additional permission to request (e.g., github:owner/repo)")
}
