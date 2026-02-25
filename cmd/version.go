package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

const cliManifestURL = "https://get.creddy.dev/cli/latest/manifest.json"

type cliManifest struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	ReleasedAt string `json:"released_at"`
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number and check for updates",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("creddy %s\n", Version)
		
		// Check for updates
		latest, err := fetchLatestVersion()
		if err != nil {
			// Silently ignore errors checking for updates
			return
		}
		
		if latest != Version && Version != "dev" {
			fmt.Printf("\nUpdate available: %s → %s\n", Version, latest)
			fmt.Println("Run 'creddy upgrade' to update")
		}
	},
}

func fetchLatestVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", cliManifestURL, nil)
	if err != nil {
		return "", err
	}
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	
	var manifest cliManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return "", err
	}
	
	return manifest.Version, nil
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
