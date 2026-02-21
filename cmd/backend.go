package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
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
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TYPE\tNAME\tSTATUS")
		// TODO: List from database
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
		// TODO: Remove from database
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
	backendAddCmd.Flags().String("name", "", "Name for this backend (defaults to type)")
}

func addGitHubBackend(cmd *cobra.Command) error {
	appID, _ := cmd.Flags().GetInt64("app-id")
	privateKeyPath, _ := cmd.Flags().GetString("private-key")
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

	// Verify private key exists
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("private key file not found: %s", privateKeyPath)
	}

	// TODO: Store in database
	fmt.Printf("GitHub backend added: %s\n", name)
	fmt.Printf("  App ID: %d\n", appID)
	fmt.Printf("  Private Key: %s\n", privateKeyPath)

	return nil
}
