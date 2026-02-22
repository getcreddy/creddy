package cmd

import (
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var unenrollCmd = &cobra.Command{
	Use:   "unenroll [name]",
	Short: "Remove an enrolled agent (admin)",
	Long: `Remove an enrolled agent from the server. This revokes their token
and allows the agent name to be reused.

Example:
  creddy unenroll my-agent`,
	SilenceUsage: true,
	Args:         cobra.ExactArgs(1),
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
			return fmt.Errorf("agent '%s' not found", name)
		}

		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
		}

		fmt.Printf("✓ Agent '%s' unenrolled\n", name)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(unenrollCmd)
}
