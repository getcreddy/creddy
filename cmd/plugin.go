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

var pluginOutdatedCmd = &cobra.Command{
	Use:   "outdated",
	Short: "Show installed plugins that have updates available",
	RunE:  runPluginOutdated,
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
	pluginCmd.AddCommand(pluginOutdatedCmd)
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
	Description string                     `json:"description"`
	Latest      string                     `json:"latest"`
	Versions    map[string]RegistryVersion `json:"versions"`
}

// RegistryVersion represents a version of a plugin
type RegistryVersion struct {
	URL       string            `json:"url"`
	SHA256    map[string]string `json:"sha256"`
	MinCreddy string            `json:"min_creddy_version"`
}

// PluginManifest represents the manifest.json published with each plugin version
type PluginManifest struct {
	Name       string           `json:"name"`
	Version    string           `json:"version"`
	ReleasedAt string           `json:"released_at"`
	Binaries   []ManifestBinary `json:"binaries"`
}

// ManifestBinary represents a binary entry in the plugin manifest
type ManifestBinary struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	URL      string `json:"url"`
}

// Plugin directory search order:
// 1. CREDDY_PLUGIN_DIR env var (if set)
// 2. ~/.local/share/creddy/plugins (user plugins)
// 3. /usr/local/lib/creddy/plugins (system plugins)
//
// This unified search order works regardless of which binary is running,
// so user and system installs share the same plugin universe.

func getUserPluginDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "creddy", "plugins")
}

func getSystemPluginDir() string {
	return "/usr/local/lib/creddy/plugins"
}

// getPluginDir returns the directory where plugins should be installed.
// For installs, this is the user plugin directory by default.
func getPluginDir() string {
	// If running as root, use system dir
	if os.Getuid() == 0 {
		return getSystemPluginDir()
	}
	if envDir := os.Getenv("CREDDY_PLUGIN_DIR"); envDir != "" {
		return envDir
	}
	dir := viper.GetString("plugin.dir")
	if dir != "" {
		return dir
	}
	// Default to user plugins
	return getUserPluginDir()
}

// getPluginSearchPaths returns all directories to search for plugins
func getPluginSearchPaths() []string {
	paths := []string{}
	if envDir := os.Getenv("CREDDY_PLUGIN_DIR"); envDir != "" {
		paths = append(paths, envDir)
	}
	paths = append(paths, getUserPluginDir(), getSystemPluginDir())
	return paths
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
// triggerPluginReload tells the running server to reload plugins.
// If the server isn't reachable, it prints a helpful message.
func triggerPluginReload() {
	serverURL := viper.GetString("admin.url")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8400"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", serverURL+"/v1/admin/plugins/reload", bytes.NewReader(nil))
	if err != nil {
		fmt.Printf("Note: Server not reachable. Run 'creddy server reload-plugins' after starting.\n")
		return
	}

	// Try to add admin token if available
	dataDir := viper.GetString("data-dir")
	if dataDir == "" {
		home, _ := os.UserHomeDir()
		dataDir = filepath.Join(home, ".creddy")
	}
	tokenPath := filepath.Join(dataDir, ".admin-token")
	if tokenBytes, err := os.ReadFile(tokenPath); err == nil {
		req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Note: Server not running. Plugin will load on next start.\n")
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
				fmt.Printf("✓ Server reloaded %d plugin(s)\n", len(result.Loaded))
			} else {
				fmt.Println("✓ Server notified (plugin already loaded or no changes)")
			}
		}
	} else {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Note: Reload failed (%d): %s\n", resp.StatusCode, string(body))
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

// fetchPluginManifest fetches the manifest.json for a specific plugin version
// from the registry. Uses "latest" if version is empty.
func fetchPluginManifest(name, version string) (*PluginManifest, error) {
	registry := getRegistry()
	if version == "" {
		version = "latest"
	}

	url := fmt.Sprintf("%s/%s/%s/manifest.json", registry, name, version)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("plugin %s@%s not found in registry", name, version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	var manifest PluginManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, nil
}

// getBinaryFromManifest finds the binary for the current OS/arch in the manifest
func getBinaryFromManifest(manifest *PluginManifest) (*ManifestBinary, error) {
	for _, b := range manifest.Binaries {
		if b.OS == runtime.GOOS && b.Arch == runtime.GOARCH {
			return &b, nil
		}
	}
	return nil, fmt.Errorf("no binary for %s/%s in manifest", runtime.GOOS, runtime.GOARCH)
}

func getInstalledPlugins() (map[string]string, error) {
	installed := make(map[string]string)

	// Search all plugin directories
	for _, pluginDir := range getPluginSearchPaths() {
		if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
			continue
		}

		loader := plugin.NewLoader(pluginDir)
		plugins, err := loader.DiscoverPlugins()
		if err != nil {
			continue
		}

		for _, name := range plugins {
			// Skip if already found in higher-priority directory
			if _, exists := installed[name]; exists {
				continue
			}

			// Try to load and get version
			p, err := loader.LoadPlugin(name)
			if err != nil {
				installed[name] = "unknown"
				continue
			}
			installed[name] = p.Info.Version
			loader.UnloadPlugin(name)
		}
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

	// Write to temp file first, then atomic rename (handles "text file busy" on running plugins)
	tmpPath := destPath + ".tmp"
	destFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create temp plugin file: %w", err)
	}

	if _, err = io.Copy(destFile, srcFile); err != nil {
		destFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to copy plugin: %w", err)
	}
	destFile.Close()

	// Get hash of new binary
	newHash := hashFile(tmpPath)

	// Get hash of existing binary (if any)
	oldHash := hashFile(destPath)

	// Atomic rename - works even if destination is busy
	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to install plugin: %w", err)
	}

	shortHash := newHash
	if len(shortHash) > 8 {
		shortHash = shortHash[:8]
	}

	// Extract plugin type from name (e.g., "creddy-github" -> "github")
	pluginType := destName
	if strings.HasPrefix(pluginType, "creddy-") {
		pluginType = strings.TrimPrefix(pluginType, "creddy-")
	}

	if oldHash == newHash {
		fmt.Printf("  Plugin unchanged (%s) for %s/%s\n", shortHash, runtime.GOOS, runtime.GOARCH)
	} else if oldHash == "" {
		fmt.Printf("  Installed %s (%s) for %s/%s\n", destName, shortHash, runtime.GOOS, runtime.GOARCH)
		fmt.Printf("  Next: configure with 'creddy backend add %s'\n", pluginType)
	} else {
		oldShort := oldHash
		if len(oldShort) > 8 {
			oldShort = oldShort[:8]
		}
		fmt.Printf("  Updated %s (%s → %s) for %s/%s\n", destName, oldShort, shortHash, runtime.GOOS, runtime.GOARCH)

		// Trigger reload on the server for upgraded plugins
		if err := reloadPlugin(pluginType); err != nil {
			fmt.Printf("  ⚠️  Could not reload plugin: %v (restart server manually)\n", err)
		} else {
			fmt.Printf("  ✓ Plugin reloaded\n")
		}
	}

	return nil
}

func runPluginInstall(cmd *cobra.Command, args []string) error {
	pluginDir := getPluginDir()

	// Ensure plugin directory exists
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

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

		// Fetch plugin manifest from registry
		// Uses "latest" if no version specified
		manifest, err := fetchPluginManifest(name, version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to find plugin %s: %v\n", name, err)
			continue
		}

		// Find binary for current platform
		binary, err := getBinaryFromManifest(manifest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Plugin %s: %v\n", name, err)
			continue
		}

		// Install from the URL in the manifest
		if err := installFromURL(binary.URL, pluginDir, binary.SHA256); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to install %s: %v\n", name, err)
			continue
		}

		fmt.Printf("✓ Installed %s@%s\n", name, manifest.Version)
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
	name = strings.TrimSuffix(name, ".exe")
	
	// Strip platform suffix (e.g., -linux-amd64, -darwin-arm64)
	platformSuffixes := []string{
		"-linux-amd64", "-linux-arm64",
		"-darwin-amd64", "-darwin-arm64",
		"-windows-amd64", "-windows-arm64",
	}
	for _, suffix := range platformSuffixes {
		name = strings.TrimSuffix(name, suffix)
	}

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

		// Fetch latest manifest
		manifest, err := fetchPluginManifest(name, "latest")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Plugin %s not in registry: %v\n", name, err)
			continue
		}

		if currentVersion == manifest.Version {
			fmt.Printf("✓ %s is already at latest (%s)\n", name, currentVersion)
			continue
		}

		// Find binary for current platform
		binary, err := getBinaryFromManifest(manifest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Plugin %s: %v\n", name, err)
			continue
		}

		if err := installFromURL(binary.URL, pluginDir, binary.SHA256); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to upgrade %s: %v\n", name, err)
			continue
		}

		fmt.Printf("✓ Upgraded %s: %s → %s\n", name, currentVersion, manifest.Version)
	}

	return nil
}

func runPluginOutdated(cmd *cobra.Command, args []string) error {
	installed, err := getInstalledPlugins()
	if err != nil {
		return fmt.Errorf("failed to get installed plugins: %w", err)
	}

	if len(installed) == 0 {
		fmt.Println("No plugins installed.")
		return nil
	}

	type outdatedPlugin struct {
		name           string
		currentVersion string
		latestVersion  string
	}

	var outdated []outdatedPlugin
	var upToDate []string
	var checkFailed []string

	for name, currentVersion := range installed {
		// Fetch latest manifest for this plugin
		manifest, err := fetchPluginManifest(name, "latest")
		if err != nil {
			checkFailed = append(checkFailed, name)
			continue
		}

		if currentVersion != manifest.Version {
			outdated = append(outdated, outdatedPlugin{
				name:           name,
				currentVersion: currentVersion,
				latestVersion:  manifest.Version,
			})
		} else {
			upToDate = append(upToDate, name)
		}
	}

	if len(outdated) == 0 {
		fmt.Println("All plugins are up to date!")
		return nil
	}

	fmt.Printf("%-15s %-12s %-12s\n", "PLUGIN", "INSTALLED", "LATEST")
	for _, p := range outdated {
		fmt.Printf("%-15s %-12s %-12s\n", p.name, p.currentVersion, p.latestVersion)
	}

	if len(outdated) > 0 {
		fmt.Println()
		fmt.Println("Run 'creddy plugin upgrade --all' to upgrade all plugins")
	}

	if len(checkFailed) > 0 {
		fmt.Println()
		fmt.Printf("Could not check: %s (not in registry)\n", strings.Join(checkFailed, ", "))
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

	// Get constraints
	constraints, err := p.Plugin.Constraints(ctx)
	if err != nil {
		return fmt.Errorf("failed to get constraints: %w", err)
	}

	fmt.Println("\nTTL Constraints:")
	if constraints == nil {
		fmt.Println("  No TTL constraints (any TTL is acceptable)")
	} else {
		if constraints.MaxTTL > 0 {
			fmt.Printf("  Max TTL: %s\n", constraints.MaxTTL)
		} else {
			fmt.Println("  Max TTL: none")
		}
		if constraints.MinTTL > 0 {
			fmt.Printf("  Min TTL: %s\n", constraints.MinTTL)
		} else {
			fmt.Println("  Min TTL: none")
		}
		if constraints.Description != "" {
			fmt.Printf("  Note:    %s\n", constraints.Description)
		}
	}

	return nil
}

// reloadPlugin tells the server to reload a specific plugin
func reloadPlugin(pluginName string) error {
	serverURL := viper.GetString("admin.url")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8400"
	}

	url := fmt.Sprintf("%s/v1/admin/plugins/%s/reload", serverURL, pluginName)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// hashFile returns sha256 hash of a file, or empty string if file doesn't exist
func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
