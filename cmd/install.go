package cmd

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

const systemdUnit = `[Unit]
Description=Creddy - Ephemeral credentials for AI agents
After=network.target

[Service]
Type=simple
ExecStart={{EXEC_START}}
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={{DATA_DIR}}

[Install]
WantedBy=multi-user.target
`

const systemBinaryPath = "/usr/local/bin/creddy"

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install creddy as a systemd service",
	Long: `Install and start creddy server as a systemd service.

Requires root/sudo. Creates a systemd unit file and enables the service.

If invoked from a user-space binary (e.g., ~/.local/bin/creddy), the binary
is automatically copied to /usr/local/bin/creddy for the systemd service.
This keeps user and system binaries intentionally separate.

Example:
  sudo creddy install --listen 0.0.0.0:8400
  sudo creddy install --listen 0.0.0.0:8400 --agent-inactivity-days 30`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS != "linux" {
			return fmt.Errorf("install command only supports Linux with systemd")
		}

		if os.Geteuid() != 0 {
			return fmt.Errorf("install requires root privileges (use sudo)")
		}

		listen, _ := cmd.Flags().GetString("listen")
		dataDir, _ := cmd.Flags().GetString("data-dir")
		agentInactivityDays, _ := cmd.Flags().GetInt("agent-inactivity-days")

		// Find the currently running binary
		execPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to find creddy binary: %w", err)
		}
		execPath, _ = filepath.Abs(execPath)
		// Resolve symlinks
		if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
			execPath = resolved
		}

		// Self-heal: ensure /usr/local/bin/creddy exists and matches the running binary
		serverBinary, err := ensureSystemBinary(execPath)
		if err != nil {
			return fmt.Errorf("failed to set up system binary: %w", err)
		}

		// Build ExecStart command using the system binary
		execStart := fmt.Sprintf("%s server --listen %s --db %s/creddy.db",
			serverBinary, listen, dataDir)
		if agentInactivityDays > 0 {
			execStart += fmt.Sprintf(" --agent-inactivity-days %d", agentInactivityDays)
		}

		// Create data directory
		if err := os.MkdirAll(dataDir, 0700); err != nil {
			return fmt.Errorf("failed to create data directory: %w", err)
		}

		// Create system plugin directory
		systemPluginDir := "/usr/local/lib/creddy/plugins"
		if err := os.MkdirAll(systemPluginDir, 0755); err != nil {
			return fmt.Errorf("failed to create system plugin directory: %w", err)
		}

		// Generate unit file
		unit := systemdUnit
		unit = strings.ReplaceAll(unit, "{{EXEC_START}}", execStart)
		unit = strings.ReplaceAll(unit, "{{DATA_DIR}}", dataDir)

		// Write unit file
		unitPath := "/etc/systemd/system/creddy.service"
		if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
			return fmt.Errorf("failed to write unit file: %w", err)
		}
		fmt.Printf("Created %s\n", unitPath)

		// Reload systemd
		if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
			return fmt.Errorf("failed to reload systemd: %w", err)
		}

		// Enable service
		if err := exec.Command("systemctl", "enable", "creddy").Run(); err != nil {
			return fmt.Errorf("failed to enable service: %w", err)
		}
		fmt.Println("Enabled creddy service")

		// Start service
		if err := exec.Command("systemctl", "start", "creddy").Run(); err != nil {
			return fmt.Errorf("failed to start service: %w", err)
		}
		fmt.Println("Started creddy service")

		fmt.Printf("\n✓ Creddy installed and running\n")
		fmt.Printf("  Server binary: %s\n", serverBinary)
		fmt.Printf("  Listening:     %s\n", listen)
		fmt.Printf("  Data dir:      %s\n", dataDir)
		fmt.Printf("  Plugin dir:    %s\n", systemPluginDir)
		fmt.Printf("\nManage with:\n")
		fmt.Printf("  systemctl status creddy\n")
		fmt.Printf("  journalctl -u creddy -f\n")

		return nil
	},
}

// ensureSystemBinary makes sure /usr/local/bin/creddy exists and matches
// the source binary's checksum. Returns the path to use for the service.
func ensureSystemBinary(sourcePath string) (string, error) {
	// If already running from system path, use it directly
	if sourcePath == systemBinaryPath {
		fmt.Printf("Using system binary: %s\n", systemBinaryPath)
		return systemBinaryPath, nil
	}

	// Compute hash of the source binary
	sourceHash, err := fileHash(sourcePath)
	if err != nil {
		return "", fmt.Errorf("failed to hash source binary: %w", err)
	}

	// Check if system binary exists and matches
	if existingHash, err := fileHash(systemBinaryPath); err == nil {
		if existingHash == sourceHash {
			fmt.Printf("System binary already up to date: %s\n", systemBinaryPath)
			return systemBinaryPath, nil
		}
		fmt.Printf("Updating system binary: %s\n", systemBinaryPath)
	} else {
		fmt.Printf("Installing system binary: %s\n", systemBinaryPath)
	}

	// Copy source binary to system path
	if err := copyBinary(sourcePath, systemBinaryPath); err != nil {
		return "", err
	}

	// Verify the copy
	newHash, err := fileHash(systemBinaryPath)
	if err != nil {
		return "", fmt.Errorf("failed to verify copied binary: %w", err)
	}
	if newHash != sourceHash {
		return "", fmt.Errorf("checksum mismatch after copy")
	}

	return systemBinaryPath, nil
}

// fileHash returns the SHA256 hash of a file
func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// copyBinary copies a binary file to a destination with proper permissions
func copyBinary(src, dst string) error {
	// Read source
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source: %w", err)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to temp file first (atomic)
	tmpPath := dst + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0755); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to install binary: %w", err)
	}

	return nil
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall creddy systemd service",
	Long: `Stop and remove the creddy systemd service.

Requires root/sudo. Does not remove data directory or binaries.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS != "linux" {
			return fmt.Errorf("uninstall command only supports Linux with systemd")
		}

		if os.Geteuid() != 0 {
			return fmt.Errorf("uninstall requires root privileges (use sudo)")
		}

		// Stop service (ignore error if not running)
		exec.Command("systemctl", "stop", "creddy").Run()
		fmt.Println("Stopped creddy service")

		// Disable service (ignore error if not enabled)
		exec.Command("systemctl", "disable", "creddy").Run()
		fmt.Println("Disabled creddy service")

		// Remove unit file
		unitPath := "/etc/systemd/system/creddy.service"
		if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove unit file: %w", err)
		}
		fmt.Printf("Removed %s\n", unitPath)

		// Reload systemd
		exec.Command("systemctl", "daemon-reload").Run()

		fmt.Println("\n✓ Creddy service uninstalled")
		fmt.Println("  Binaries and data directory were not removed")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)

	installCmd.Flags().String("listen", "0.0.0.0:8400", "Address to listen on")
	installCmd.Flags().String("data-dir", "/var/lib/creddy", "Data directory")
	installCmd.Flags().Int("agent-inactivity-days", 0, "Auto-unenroll inactive agents (0 = disabled)")
}
