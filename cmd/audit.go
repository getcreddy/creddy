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

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View audit log",
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := viper.GetString("admin.url")
		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}

		limit, _ := cmd.Flags().GetInt("limit")
		agentID, _ := cmd.Flags().GetString("agent")
		action, _ := cmd.Flags().GetString("action")
		outputJSON, _ := cmd.Flags().GetBool("json")

		url := fmt.Sprintf("%s/v1/admin/audit?limit=%d", serverURL, limit)
		if agentID != "" {
			url += "&agent_id=" + agentID
		}
		if action != "" {
			url += "&action=" + action
		}

		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		if outputJSON {
			fmt.Println(string(body))
			return nil
		}

		var results []struct {
			ID        string    `json:"id"`
			Timestamp time.Time `json:"timestamp"`
			AgentName string    `json:"agent_name"`
			Action    string    `json:"action"`
			Backend   string    `json:"backend"`
			Details   string    `json:"details"`
			IPAddress string    `json:"ip_address"`
		}
		json.Unmarshal(body, &results)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TIME\tAGENT\tACTION\tBACKEND\tIP")
		for _, r := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				r.Timestamp.Format("2006-01-02 15:04:05"),
				r.AgentName,
				r.Action,
				r.Backend,
				r.IPAddress,
			)
		}
		w.Flush()

		return nil
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.Flags().Int("limit", 50, "Number of entries to show")
	auditCmd.Flags().String("agent", "", "Filter by agent ID")
	auditCmd.Flags().String("action", "", "Filter by action (token_issued, agent_created, key_accessed)")
	auditCmd.Flags().Bool("json", false, "Output as JSON")
}
