package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

const cliManifestURL = "https://get.creddy.dev/cli/latest/manifest.json"

// Set via ldflags
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type cliManifest struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	ReleasedAt string `json:"released_at"`
}

type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Path      string `json:"path"`
	Checksum  string `json:"checksum,omitempty"`
	Latest    string `json:"latest,omitempty"`
}

var versionJSON bool

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number and check for updates",
	RunE: func(cmd *cobra.Command, args []string) error {
		info := VersionInfo{
			Version:   Version,
			Commit:    Commit,
			BuildDate: BuildDate,
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
		}

		// Get executable path and checksum
		if execPath, err := os.Executable(); err == nil {
			info.Path = execPath
			if f, err := os.Open(execPath); err == nil {
				h := sha256.New()
				if _, err := io.Copy(h, f); err == nil {
					info.Checksum = hex.EncodeToString(h.Sum(nil))
				}
				f.Close()
			}
		}

		// Check for updates (even for JSON output)
		if latest, err := fetchLatestVersion(); err == nil {
			info.Latest = latest
		}

		if versionJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(info)
		}

		// Human output
		fmt.Printf("creddy %s\n", Version)
		if Commit != "unknown" && Commit != "" {
			fmt.Printf("  commit:  %s\n", Commit)
		}
		if BuildDate != "unknown" && BuildDate != "" {
			fmt.Printf("  built:   %s\n", BuildDate)
		}
		fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)

		if info.Latest != "" && info.Latest != Version && Version != "dev" {
			fmt.Printf("\nUpdate available: %s → %s\n", Version, info.Latest)
			fmt.Println("Run 'creddy upgrade' to update")
		}

		return nil
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
	versionCmd.Flags().BoolVar(&versionJSON, "json", false, "Output as JSON")
}
