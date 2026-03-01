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

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage signing keys",
}

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all public signing keys",
	Long:  `List all agent public keys. These can be added to GitHub for commit signature verification.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := viper.GetString("admin.url")

		resp, err := http.Get(serverURL + "/v1/admin/keys")
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		var results []struct {
			KeyID     string    `json:"key_id"`
			AgentID   string    `json:"agent_id"`
			Email     string    `json:"email"`
			Name      string    `json:"name"`
			PublicKey string    `json:"public_key"`
			CreatedAt time.Time `json:"created_at"`
		}
		json.Unmarshal(body, &results)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "KEY ID\tEMAIL\tNAME\tCREATED")
		for _, r := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				r.KeyID,
				r.Email,
				r.Name,
				r.CreatedAt.Format("2006-01-02"),
			)
		}
		w.Flush()

		return nil
	},
}

var keysExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all public keys (for GitHub)",
	Long:  `Export all agent public keys in a format suitable for adding to GitHub.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := viper.GetString("admin.url")

		resp, err := http.Get(serverURL + "/v1/admin/keys")
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		var results []struct {
			KeyID     string `json:"key_id"`
			Email     string `json:"email"`
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
		}
		json.Unmarshal(body, &results)

		for _, r := range results {
			fmt.Printf("# %s <%s>\n", r.Name, r.Email)
			fmt.Printf("# Key ID: %s\n", r.KeyID)
			fmt.Println(r.PublicKey)
			fmt.Println()
		}

		return nil
	},
}

var keysGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get your signing key (for agents)",
	Long:  `Fetch your agent's signing key for git commit signing.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		flagServer, _ := cmd.Flags().GetString("server")
		serverURL := getServerURL(flagServer)
		token := viper.GetString("token")

		if token == "" {
			if token == "" {
			return fmt.Errorf("not enrolled. Run 'creddy init <server-url>' first")
		}
		}

		format, _ := cmd.Flags().GetString("format")
		url := serverURL + "/v1/signing-key"
		if format != "" {
			url += "?format=" + format
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
		}

		outputJSON, _ := cmd.Flags().GetBool("json")
		if outputJSON {
			fmt.Println(string(body))
			return nil
		}

		var result struct {
			KeyID      string `json:"key_id"`
			Email      string `json:"email"`
			Name       string `json:"name"`
			PublicKey  string `json:"public_key"`
			PrivateKey string `json:"private_key"`
		}
		json.Unmarshal(body, &result)

		fmt.Printf("Key ID: %s\n", result.KeyID)
		fmt.Printf("Email: %s\n", result.Email)
		fmt.Printf("Name: %s\n", result.Name)
		fmt.Println("\nPublic Key:")
		fmt.Println(result.PublicKey)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(keysCmd)
	keysCmd.AddCommand(keysListCmd)
	keysCmd.AddCommand(keysExportCmd)
	keysCmd.AddCommand(keysGetCmd)

	keysGetCmd.Flags().String("format", "", "Output format (git)")
	keysGetCmd.Flags().Bool("json", false, "Output as JSON")
}
