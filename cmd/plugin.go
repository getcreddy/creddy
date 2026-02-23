package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/getcreddy/creddy/pkg/plugin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

const (
	defaultRegistry = "https://plugins.creddy.dev"
)

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage Creddy plugins",
	Long:  `Install, upgrade, and manage Creddy credential plugins.`,
}

var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed and available plugins",
	RunE:  runPluginList,
}

var pluginInstallCmd = &cobra.Command{
	Use:   "install <plugin[@version]> [plugin[@version]...]",
	Short: "Install plugins",
	Long: `Install plugins from the registry, OCI registry, or a URL.

Examples:
  creddy plugin install github
  creddy plugin install github@0.2.0
  creddy plugin install github anthropic doppler
  creddy plugin install https://example.com/creddy-custom.tar.gz
  creddy plugin install ttl.sh/creddy-github:1h
  creddy plugin install plugins.creddy.dev/github:0.1.0`,
	Args: cobra.MinimumNArgs(1),
	RunE: runPluginInstall,
}

var pluginUpgradeCmd = &cobra.Command{
	Use:   "upgrade [plugin...]",
	Short: "Upgrade plugins to latest version",
	Long: `Upgrade installed plugins to their latest versions.

Examples:
  creddy plugin upgrade github
  creddy plugin upgrade --all`,
	RunE: runPluginUpgrade,
}

var pluginRemoveCmd = &cobra.Command{
	Use:   "remove <plugin> [plugin...]",
	Short: "Remove installed plugins",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runPluginRemove,
}

var pluginInfoCmd = &cobra.Command{
	Use:   "info <plugin>",
	Short: "Show detailed plugin information",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginInfo,
}

var (
	pluginListInstalled bool
	pluginUpgradeAll    bool
)

func init() {
	rootCmd.AddCommand(pluginCmd)
	pluginCmd.AddCommand(pluginListCmd)
	pluginCmd.AddCommand(pluginInstallCmd)
	pluginCmd.AddCommand(pluginUpgradeCmd)
	pluginCmd.AddCommand(pluginRemoveCmd)
	pluginCmd.AddCommand(pluginInfoCmd)

	pluginListCmd.Flags().BoolVar(&pluginListInstalled, "installed", false, "Show only installed plugins")
	pluginUpgradeCmd.Flags().BoolVar(&pluginUpgradeAll, "all", false, "Upgrade all installed plugins")
}

// RegistryIndex represents the plugin registry index
type RegistryIndex struct {
	Plugins map[string]RegistryPlugin `json:"plugins"`
}

// RegistryPlugin represents a plugin in the registry
type RegistryPlugin struct {
	Description string                       `json:"description"`
	Latest      string                       `json:"latest"`
	Versions    map[string]RegistryVersion   `json:"versions"`
}

// RegistryVersion represents a version of a plugin
type RegistryVersion struct {
	URL            string            `json:"url"`
	SHA256         map[string]string `json:"sha256"`
	MinCreddy      string            `json:"min_creddy_version"`
}

func getPluginDir() string {
	dir := viper.GetString("plugin.dir")
	if dir != "" {
		return dir
	}
	if envDir := os.Getenv("CREDDY_PLUGIN_DIR"); envDir != "" {
		return envDir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".creddy", "plugins")
}

func getRegistry() string {
	reg := viper.GetString("plugin.registry")
	if reg != "" {
		return reg
	}
	if envReg := os.Getenv("CREDDY_PLUGIN_REGISTRY"); envReg != "" {
		return envReg
	}
	return defaultRegistry
}

// triggerPluginReload tells the running server to reload plugins.
// If the server isn't reachable, it prints a message suggesting a restart.
func triggerPluginReload() {
	serverURL := viper.GetString("admin.url")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8400"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", serverURL+"/v1/admin/plugins/reload", bytes.NewReader(nil))
	if err != nil {
		fmt.Println("Note: Restart the creddy server to load the new plugin")
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Note: Restart the creddy server to load the new plugin")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var result struct {
			Loaded  []string `json:"loaded"`
			Plugins []string `json:"plugins"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			if len(result.Loaded) > 0 {
				fmt.Printf("Server reloaded: %d new plugin(s) loaded\n", len(result.Loaded))
			}
		}
	} else {
		fmt.Println("Note: Restart the creddy server to load the new plugin")
	}
}

func fetchRegistryIndex() (*RegistryIndex, error) {
	registry := getRegistry()
	url := registry + "/index.json"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	var index RegistryIndex
	if err := json.NewDecoder(resp.Body).Decode(&index); err != nil {
		return nil, fmt.Errorf("failed to parse registry index: %w", err)
	}

	return &index, nil
}

func getInstalledPlugins() (map[string]string, error) {
	pluginDir := getPluginDir()
	loader := plugin.NewLoader(pluginDir)

	plugins, err := loader.DiscoverPlugins()
	if err != nil {
		return nil, err
	}

	installed := make(map[string]string)
	for _, name := range plugins {
		// Try to load and get version
		p, err := loader.LoadPlugin(name)
		if err != nil {
			installed[name] = "unknown"
			continue
		}
		installed[name] = p.Info.Version
		loader.UnloadPlugin(name)
	}

	return installed, nil
}

func runPluginList(cmd *cobra.Command, args []string) error {
	installed, err := getInstalledPlugins()
	if err != nil {
		return fmt.Errorf("failed to get installed plugins: %w", err)
	}

	if pluginListInstalled {
		// Show only installed plugins
		if len(installed) == 0 {
			fmt.Println("No plugins installed.")
			fmt.Println("\nInstall plugins with: creddy plugin install <name>")
			return nil
		}

		fmt.Printf("%-15s %-10s\n", "NAME", "VERSION")
		for name, version := range installed {
			fmt.Printf("%-15s %-10s\n", name, version)
		}
		return nil
	}

	// Fetch registry and show all
	index, err := fetchRegistryIndex()
	if err != nil {
		// If registry is unavailable, just show installed
		fmt.Println("Warning: Could not fetch registry, showing installed plugins only")
		fmt.Println()
		for name, version := range installed {
			fmt.Printf("%-15s %-10s (installed)\n", name, version)
		}
		return nil
	}

	fmt.Printf("%-15s %-10s %-45s %-10s\n", "NAME", "VERSION", "DESCRIPTION", "INSTALLED")
	for name, p := range index.Plugins {
		installedVersion := "-"
		if v, ok := installed[name]; ok {
			installedVersion = "✓ " + v
		}
		desc := p.Description
		if len(desc) > 43 {
			desc = desc[:40] + "..."
		}
		fmt.Printf("%-15s %-10s %-45s %-10s\n", name, p.Latest, desc, installedVersion)
	}

	return nil
}

// isOCIReference checks if the argument looks like an OCI registry reference
// OCI refs have format: registry/repo:tag (e.g., ttl.sh/creddy-github:1h)
func isOCIReference(arg string) bool {
	// Must contain both / and : but not be a URL
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		return false
	}
	// Must have at least one / and exactly one :
	hasSlash := strings.Contains(arg, "/")
	colonCount := strings.Count(arg, ":")
	return hasSlash && colonCount == 1
}

// installFromOCI pulls a plugin from an OCI registry using ORAS
func installFromOCI(reference, pluginDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Parse the reference to extract registry and repository
	repo, err := remote.NewRepository(reference)
	if err != nil {
		return fmt.Errorf("invalid OCI reference: %w", err)
	}

	// Use anonymous access (no auth) - ttl.sh and public registries don't require it
	repo.PlainHTTP = strings.HasPrefix(reference, "localhost") || strings.Contains(reference, "localhost:")

	// Create a temporary directory for the pulled content
	tmpDir, err := os.MkdirTemp("", "creddy-oci-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a file store to pull content into
	fs, err := file.New(tmpDir)
	if err != nil {
		return fmt.Errorf("failed to create file store: %w", err)
	}
	defer fs.Close()

	// Extract tag from reference
	tag := "latest"
	if idx := strings.LastIndex(reference, ":"); idx != -1 {
		tag = reference[idx+1:]
	}

	// Pull the artifact
	desc, err := oras.Copy(ctx, repo, tag, fs, tag, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("failed to pull from OCI registry: %w", err)
	}

	fmt.Printf("  Pulled %s (digest: %s)\n", reference, desc.Digest.String()[:12])

	// Debug: show what's in the temp directory
	fmt.Printf("  Debug: temp dir = %s\n", tmpDir)
	filepath.WalkDir(tmpDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(tmpDir, path)
		info, _ := d.Info()
		if info != nil {
			fmt.Printf("  Debug: %s (size=%d, dir=%v)\n", rel, info.Size(), d.IsDir())
		} else {
			fmt.Printf("  Debug: %s (dir=%v)\n", rel, d.IsDir())
		}
		return nil
	})

	// Determine the current platform suffix (e.g., "linux-amd64", "darwin-arm64")
	platformSuffix := fmt.Sprintf("-%s-%s", runtime.GOOS, runtime.GOARCH)

	// Find and copy the binary from the pulled content
	// ORAS may place files in subdirectories (e.g., bin/), so walk recursively
	var platformBinary string
	var platformBinaryPath string
	var allBinaries []string

	err = filepath.WalkDir(tmpDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// Skip manifest and config files
		if strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		allBinaries = append(allBinaries, d.Name())
		if strings.HasSuffix(d.Name(), platformSuffix) {
			platformBinary = d.Name()
			platformBinaryPath = path
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to scan pulled content: %w", err)
	}

	// Extract plugin name from reference (e.g., ttl.sh/creddy-github:1h -> creddy-github)
	refParts := strings.Split(reference, "/")
	lastPart := refParts[len(refParts)-1]
	if colonIdx := strings.Index(lastPart, ":"); colonIdx != -1 {
		lastPart = lastPart[:colonIdx]
	}
	pluginName := lastPart

	if platformBinary == "" {
		if len(allBinaries) == 0 {
			return fmt.Errorf("no plugin binary found in OCI artifact")
		}
		// If there are binaries but none match our platform, show helpful error
		return fmt.Errorf("no binary for platform %s/%s found in OCI artifact (available: %s)",
			runtime.GOOS, runtime.GOARCH, strings.Join(allBinaries, ", "))
	}

	srcPath := platformBinaryPath

	// Determine destination name: strip platform suffix
	// e.g., "creddy-github-linux-amd64" -> "creddy-github"
	destName := strings.TrimSuffix(platformBinary, platformSuffix)
	if destName == "" {
		destName = pluginName
	}

	destPath := filepath.Join(pluginDir, destName)

	// Copy the platform-specific binary
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source binary: %w", err)
	}
	defer srcFile.Close()

	destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create plugin file: %w", err)
	}
	defer destFile.Close()

	if _, err = io.Copy(destFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy plugin: %w", err)
	}

	fmt.Printf("  Installed %s for %s/%s\n", destName, runtime.GOOS, runtime.GOARCH)

	return nil
}

func runPluginInstall(cmd *cobra.Command, args []string) error {
	pluginDir := getPluginDir()

	// Ensure plugin directory exists
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	var index *RegistryIndex

	for _, arg := range args {
		// Check if it's an OCI reference (e.g., ttl.sh/creddy-github:1h)
		if isOCIReference(arg) {
			fmt.Printf("Installing from OCI registry: %s\n", arg)
			if err := installFromOCI(arg, pluginDir); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to install from OCI: %v\n", err)
				continue
			}
			fmt.Printf("✓ Installed plugin from %s\n", arg)
			continue
		}

		// Check if it's a URL
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			if err := installFromURL(arg, pluginDir); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to install from %s: %v\n", arg, err)
				continue
			}
			fmt.Printf("✓ Installed plugin from %s\n", arg)
			continue
		}

		// Parse name@version
		name, version := parsePluginSpec(arg)

		// Fetch registry if needed
		if index == nil {
			var err error
			index, err = fetchRegistryIndex()
			if err != nil {
				return fmt.Errorf("failed to fetch registry: %w", err)
			}
		}

		// Find plugin in registry
		p, ok := index.Plugins[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "Plugin not found: %s\n", name)
			continue
		}

		// Use latest if no version specified
		if version == "" {
			version = p.Latest
		}

		// Get version info
		v, ok := p.Versions[version]
		if !ok {
			fmt.Fprintf(os.Stderr, "Version not found: %s@%s\n", name, version)
			continue
		}

		// Build URL with OS/arch
		url := strings.ReplaceAll(v.URL, "{os}", runtime.GOOS)
		url = strings.ReplaceAll(url, "{arch}", runtime.GOARCH)

		// Get expected checksum
		checksumKey := runtime.GOOS + "-" + runtime.GOARCH
		expectedChecksum := v.SHA256[checksumKey]

		if err := installFromURL(url, pluginDir, expectedChecksum); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to install %s: %v\n", name, err)
			continue
		}

		fmt.Printf("✓ Installed %s@%s\n", name, version)
	}

	// Tell the server to reload plugins
	triggerPluginReload()

	return nil
}

func installFromURL(url, pluginDir string, expectedChecksum ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "creddy-plugin-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Download and calculate checksum
	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	if _, err := io.Copy(writer, resp.Body); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Verify checksum if provided
	if len(expectedChecksum) > 0 && expectedChecksum[0] != "" {
		actualChecksum := hex.EncodeToString(hasher.Sum(nil))
		if actualChecksum != expectedChecksum[0] {
			return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum[0], actualChecksum)
		}
	}

	// Reset file for reading
	tmpFile.Seek(0, 0)

	// Extract if tar.gz, otherwise copy directly
	if strings.HasSuffix(url, ".tar.gz") || strings.HasSuffix(url, ".tgz") {
		return extractTarGz(tmpFile, pluginDir)
	}

	// Assume single binary - extract name from URL
	name := filepath.Base(url)
	name = strings.TrimSuffix(name, ".tar.gz")
	name = strings.TrimSuffix(name, ".tgz")

	destPath := filepath.Join(pluginDir, name)
	destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer destFile.Close()

	tmpFile.Seek(0, 0)
	_, err = io.Copy(destFile, tmpFile)
	return err
}

func extractTarGz(r io.Reader, destDir string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Only extract files (skip directories)
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Security: prevent path traversal
		name := filepath.Base(header.Name)
		if strings.Contains(name, "..") {
			continue
		}

		destPath := filepath.Join(destDir, name)
		destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return err
		}

		if _, err := io.Copy(destFile, tr); err != nil {
			destFile.Close()
			return err
		}
		destFile.Close()
	}

	return nil
}

func parsePluginSpec(spec string) (name, version string) {
	parts := strings.SplitN(spec, "@", 2)
	name = parts[0]
	if len(parts) > 1 {
		version = parts[1]
	}
	return
}

func runPluginUpgrade(cmd *cobra.Command, args []string) error {
	installed, err := getInstalledPlugins()
	if err != nil {
		return fmt.Errorf("failed to get installed plugins: %w", err)
	}

	if len(installed) == 0 {
		fmt.Println("No plugins installed.")
		return nil
	}

	index, err := fetchRegistryIndex()
	if err != nil {
		return fmt.Errorf("failed to fetch registry: %w", err)
	}

	var toUpgrade []string

	if pluginUpgradeAll {
		for name := range installed {
			toUpgrade = append(toUpgrade, name)
		}
	} else if len(args) > 0 {
		toUpgrade = args
	} else {
		return fmt.Errorf("specify plugins to upgrade or use --all")
	}

	pluginDir := getPluginDir()

	for _, name := range toUpgrade {
		currentVersion, ok := installed[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "Plugin not installed: %s\n", name)
			continue
		}

		p, ok := index.Plugins[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "Plugin not in registry: %s\n", name)
			continue
		}

		if currentVersion == p.Latest {
			fmt.Printf("✓ %s is already at latest (%s)\n", name, currentVersion)
			continue
		}

		v := p.Versions[p.Latest]
		url := strings.ReplaceAll(v.URL, "{os}", runtime.GOOS)
		url = strings.ReplaceAll(url, "{arch}", runtime.GOARCH)

		checksumKey := runtime.GOOS + "-" + runtime.GOARCH
		expectedChecksum := v.SHA256[checksumKey]

		if err := installFromURL(url, pluginDir, expectedChecksum); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to upgrade %s: %v\n", name, err)
			continue
		}

		fmt.Printf("✓ Upgraded %s: %s → %s\n", name, currentVersion, p.Latest)
	}

	return nil
}

func runPluginRemove(cmd *cobra.Command, args []string) error {
	pluginDir := getPluginDir()

	for _, name := range args {
		// Try different naming conventions
		paths := []string{
			filepath.Join(pluginDir, "creddy-"+name),
			filepath.Join(pluginDir, name),
		}

		removed := false
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				if err := os.Remove(path); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to remove %s: %v\n", name, err)
				} else {
					fmt.Printf("✓ Removed %s\n", name)
					removed = true
				}
				break
			}
		}

		if !removed {
			fmt.Fprintf(os.Stderr, "Plugin not found: %s\n", name)
		}
	}

	return nil
}

func runPluginInfo(cmd *cobra.Command, args []string) error {
	name := args[0]
	pluginDir := getPluginDir()
	loader := plugin.NewLoader(pluginDir)

	p, err := loader.LoadPlugin(name)
	if err != nil {
		return fmt.Errorf("failed to load plugin: %w", err)
	}
	defer loader.UnloadPlugin(name)

	fmt.Printf("Name:               %s\n", p.Info.Name)
	fmt.Printf("Version:            %s\n", p.Info.Version)
	fmt.Printf("Description:        %s\n", p.Info.Description)
	fmt.Printf("Min Creddy Version: %s\n", p.Info.MinCreddyVersion)
	fmt.Printf("Installed:          %s\n", loader.PluginDir())

	// Get scopes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	scopes, err := p.Plugin.Scopes(ctx)
	if err != nil {
		return fmt.Errorf("failed to get scopes: %w", err)
	}

	fmt.Println("\nScopes:")
	for _, s := range scopes {
		fmt.Printf("  %-25s %s\n", s.Pattern, s.Description)
	}

	return nil
}
