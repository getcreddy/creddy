package cmd

import (
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var revokeCmd = &cobra.Command{
	Use:   "revoke [id]",
	Short: "Revoke an active credential",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]

		serverURL := viper.GetString("url")
		token := viper.GetString("token")

		if serverURL == "" {
			return fmt.Errorf("CREDDY_URL not set")
		}
		if token == "" {
			return fmt.Errorf("CREDDY_TOKEN not set")
		}

		req, err := http.NewRequest("DELETE", serverURL+"/v1/active/"+id, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect to creddy server: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("failed to revoke credential: %s", resp.Status)
		}

		fmt.Printf("Credential revoked: %s\n", id)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(revokeCmd)
}
