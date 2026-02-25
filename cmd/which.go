package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var whichJSON bool

type WhichInfo struct {
	Binary      BinaryInfo   `json:"binary"`
	Config      ConfigInfo   `json:"config"`
	Plugins     PluginInfo   `json:"plugins"`
	Service     *ServiceInfo `json:"service,omitempty"`
}

type BinaryInfo struct {
	Path     string `json:"path"`
	Checksum string `json:"checksum,omitempty"`
}

type ConfigInfo struct {
	SearchPaths []string `json:"search_paths"`
	ActivePath  string   `json:"active_path,omitempty"`
}

type PluginInfo struct {
	SearchPaths []string `json:"search_paths"`
	UserDir     string   `json:"user_dir"`
	SystemDir   string   `json:"system_dir"`
}

type ServiceInfo struct {
	UnitFile  string `json:"unit_file"`
	ExecStart string `json:"exec_start,omitempty"`
	Status    string `json:"status,omitempty"`
}

var whichCmd = &cobra.Command{
	Use:   "which",
	Short: "Show paths and diagnostics for creddy installation",
	Long: `Display diagnostic information about the creddy installation.

Shows:
  - Running binary path and checksum
  - Config file search paths and active config
  - Plugin search paths
  - Systemd service status (if installed)`,
	RunE: runWhich,
}

func init() {
	rootCmd.AddCommand(whichCmd)
	whichCmd.Flags().BoolVar(&whichJSON, "json", false, "Output as JSON")
}

func runWhich(cmd *cobra.Command, args []string) error {
	info := WhichInfo{}

	// Binary info
	execPath, err := os.Executable()
	if err != nil {
		execPath = "unknown"
	} else {
		execPath, _ = filepath.Abs(execPath)
		// Resolve symlinks
		if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
			execPath = resolved
		}
	}
	info.Binary.Path = execPath
	info.Binary.Checksum = hashFile(execPath)

	// Config paths (matches initConfig search order)
	home, _ := os.UserHomeDir()
	info.Config.SearchPaths = []string{
		filepath.Join(home, ".config", "creddy", "config.yaml"),
		filepath.Join(home, ".creddy", "config.yaml"), // legacy
		"/etc/creddy/config.yaml",
	}
	// Check which one is active
	for _, p := range info.Config.SearchPaths {
		if _, err := os.Stat(p); err == nil {
			info.Config.ActivePath = p
			break
		}
	}

	// Plugin paths - unified across both binaries
	info.Plugins.UserDir = filepath.Join(home, ".local", "share", "creddy", "plugins")
	info.Plugins.SystemDir = "/usr/local/lib/creddy/plugins"
	info.Plugins.SearchPaths = []string{}
	if envDir := os.Getenv("CREDDY_PLUGIN_DIR"); envDir != "" {
		info.Plugins.SearchPaths = append(info.Plugins.SearchPaths, envDir)
	}
	info.Plugins.SearchPaths = append(info.Plugins.SearchPaths, info.Plugins.UserDir, info.Plugins.SystemDir)

	// Systemd service info (Linux only)
	if runtime.GOOS == "linux" {
		unitPath := "/etc/systemd/system/creddy.service"
		if _, err := os.Stat(unitPath); err == nil {
			svc := &ServiceInfo{UnitFile: unitPath}

			// Read ExecStart from unit file
			if content, err := os.ReadFile(unitPath); err == nil {
				for _, line := range strings.Split(string(content), "\n") {
					if strings.HasPrefix(line, "ExecStart=") {
						svc.ExecStart = strings.TrimPrefix(line, "ExecStart=")
						break
					}
				}
			}

			// Get service status
			out, err := exec.Command("systemctl", "is-active", "creddy").Output()
			if err == nil {
				svc.Status = strings.TrimSpace(string(out))
			} else {
				svc.Status = "inactive"
			}

			info.Service = svc
		}
	}

	if whichJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	// Human-readable output
	fmt.Println("Binary:")
	fmt.Printf("  Path:     %s\n", info.Binary.Path)
	if info.Binary.Checksum != "" {
		fmt.Printf("  Checksum: %s\n", info.Binary.Checksum[:16]+"...")
	}

	fmt.Println("\nConfig:")
	for _, p := range info.Config.SearchPaths {
		marker := "  "
		if p == info.Config.ActivePath {
			marker = "→ "
		}
		exists := "✗"
		if _, err := os.Stat(p); err == nil {
			exists = "✓"
		}
		fmt.Printf("  %s%s %s\n", marker, exists, p)
	}

	fmt.Println("\nPlugins:")
	fmt.Printf("  Search order:\n")
	for i, p := range info.Plugins.SearchPaths {
		exists := "✗"
		if _, err := os.Stat(p); err == nil {
			exists = "✓"
		}
		label := ""
		if p == info.Plugins.UserDir {
			label = " (user)"
		} else if p == info.Plugins.SystemDir {
			label = " (system)"
		} else if i == 0 && os.Getenv("CREDDY_PLUGIN_DIR") != "" {
			label = " (env)"
		}
		fmt.Printf("    %d. %s %s%s\n", i+1, exists, p, label)
	}

	if info.Service != nil {
		fmt.Println("\nService:")
		fmt.Printf("  Unit:     %s\n", info.Service.UnitFile)
		fmt.Printf("  ExecStart: %s\n", info.Service.ExecStart)
		fmt.Printf("  Status:   %s\n", info.Service.Status)
	} else if runtime.GOOS == "linux" {
		fmt.Println("\nService: not installed")
	}

	return nil
}
