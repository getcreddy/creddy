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

type cliBinary struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	URL      string `json:"url"`
}

type cliManifestFull struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	ReleasedAt string      `json:"released_at"`
	Binaries   []cliBinary `json:"binaries"`
}

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade creddy to the latest version",
	RunE:  runUpgrade,
}

func init() {
	rootCmd.AddCommand(upgradeCmd)
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	fmt.Printf("Current version: %s\n", Version)
	
	// Fetch manifest
	fmt.Println("Checking for updates...")
	manifest, err := fetchCliManifest()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}
	
	if manifest.Version == Version {
		fmt.Println("Already at latest version!")
		return nil
	}
	
	fmt.Printf("New version available: %s\n", manifest.Version)
	
	// Find binary for current platform
	var binary *cliBinary
	for _, b := range manifest.Binaries {
		if b.OS == runtime.GOOS && b.Arch == runtime.GOARCH {
			binary = &b
			break
		}
	}
	
	if binary == nil {
		return fmt.Errorf("no binary available for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	
	// Download to temp file
	fmt.Printf("Downloading %s...\n", binary.Filename)
	tmpFile, err := os.CreateTemp("", "creddy-upgrade-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", binary.URL, nil)
	if err != nil {
		return err
	}
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: status %d", resp.StatusCode)
	}
	
	// Download and calculate checksum
	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)
	
	if _, err := io.Copy(writer, resp.Body); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	
	// Verify checksum
	actualChecksum := hex.EncodeToString(hasher.Sum(nil))
	if actualChecksum != binary.SHA256 {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", binary.SHA256, actualChecksum)
	}
	fmt.Println("Checksum verified ✓")
	
	// Get current executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	
	// Replace the binary
	// On Unix, we can rename over a running binary
	tmpFile.Close()
	
	// Make executable
	if err := os.Chmod(tmpFile.Name(), 0755); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}
	
	// Atomic rename
	if err := os.Rename(tmpFile.Name(), execPath); err != nil {
		// If rename fails (cross-device), try copy
		if err := copyFile(tmpFile.Name(), execPath); err != nil {
			return fmt.Errorf("failed to replace binary: %w", err)
		}
	}
	
	fmt.Printf("✓ Upgraded to %s\n", manifest.Version)
	fmt.Println("Restart any running creddy processes to use the new version")
	
	return nil
}

func fetchCliManifest() (*cliManifestFull, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", cliManifestURL, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	
	var manifest cliManifestFull
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}
	
	return &manifest, nil
}

func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	
	dest, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer dest.Close()
	
	_, err = io.Copy(dest, source)
	return err
}
