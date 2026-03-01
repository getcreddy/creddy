package cmd

import (
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

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List active credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		flagServer, _ := cmd.Flags().GetString("server")
		serverURL := getServerURL(flagServer)
		token := viper.GetString("token")

		if token == "" {
			if token == "" {
			return fmt.Errorf("not enrolled. Run 'creddy init <server-url>' first")
		}
		}

		req, err := http.NewRequest("GET", serverURL+"/v1/active", nil)
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

		var results []struct {
			ID        string    `json:"id"`
			Backend   string    `json:"backend"`
			Agent     string    `json:"agent"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := json.Unmarshal(body, &results); err != nil {
			return err
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tBACKEND\tAGENT\tEXPIRES")
		for _, r := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.ID, r.Backend, r.Agent, r.ExpiresAt.Format(time.RFC3339))
		}
		w.Flush()

		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
