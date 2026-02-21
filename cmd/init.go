package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize creddy configuration",
	Long:  `Create the creddy configuration directory and default config file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		configDir := filepath.Join(home, ".creddy")
		configFile := filepath.Join(configDir, "config.yaml")
		dbFile := filepath.Join(configDir, "creddy.db")

		// Create config directory
		if err := os.MkdirAll(configDir, 0700); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}

		// Create default config if it doesn't exist
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			defaultConfig := `# Creddy configuration

server:
  listen: "127.0.0.1:8400"

# For agents connecting to a remote server:
# url: "http://creddy-server:8400"
# token: "ckr_your_agent_token"

database:
  path: "` + dbFile + `"
`
			if err := os.WriteFile(configFile, []byte(defaultConfig), 0600); err != nil {
				return fmt.Errorf("failed to write config file: %w", err)
			}
			fmt.Printf("Created config file: %s\n", configFile)
		} else {
			fmt.Printf("Config file already exists: %s\n", configFile)
		}

		fmt.Println("\nNext steps:")
		fmt.Println("  1. Start the server:     creddy server")
		fmt.Println("  2. Add a backend:        creddy backend add github --app-id X --private-key ./key.pem")
		fmt.Println("  3. Create an agent:      creddy agent create my-bot --can github:read,write")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
