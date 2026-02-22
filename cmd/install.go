package cmd

import (
	"fmt"
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

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install creddy as a systemd service",
	Long: `Install and start creddy server as a systemd service.

Requires root/sudo. Creates a systemd unit file and enables the service.

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

		// Find creddy binary
		execPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to find creddy binary: %w", err)
		}
		execPath, _ = filepath.Abs(execPath)

		// Build ExecStart command
		execStart := fmt.Sprintf("%s server --listen %s --db %s/creddy.db",
			execPath, listen, dataDir)
		if agentInactivityDays > 0 {
			execStart += fmt.Sprintf(" --agent-inactivity-days %d", agentInactivityDays)
		}

		// Create data directory
		if err := os.MkdirAll(dataDir, 0700); err != nil {
			return fmt.Errorf("failed to create data directory: %w", err)
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
		fmt.Printf("  Listening: %s\n", listen)
		fmt.Printf("  Data dir:  %s\n", dataDir)
		fmt.Printf("\nManage with:\n")
		fmt.Printf("  systemctl status creddy\n")
		fmt.Printf("  journalctl -u creddy -f\n")

		return nil
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall creddy systemd service",
	Long: `Stop and remove the creddy systemd service.

Requires root/sudo. Does not remove data directory.`,
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

		fmt.Println("\n✓ Creddy uninstalled")
		fmt.Println("  Data directory was not removed")

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
