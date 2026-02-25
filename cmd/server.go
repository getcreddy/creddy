package cmd

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/getcreddy/creddy/pkg/plugin"
	"github.com/getcreddy/creddy/pkg/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run the creddy server",
	Long:  `Start the creddy server to handle credential requests from agents.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		listen := viper.GetString("server.listen")
		if listen == "" {
			listen = "127.0.0.1:8400"
		}

		dbPath := viper.GetString("database.path")
		if dbPath == "" {
			if home, err := os.UserHomeDir(); err == nil {
				dbPath = filepath.Join(home, ".creddy", "creddy.db")
			} else {
				// No HOME (e.g., systemd service) - use /var/lib/creddy
				dbPath = "/var/lib/creddy/creddy.db"
			}
		}

		domain := viper.GetString("server.domain")
		if domain == "" {
			domain = "creddy.local"
		}

		agentInactivityDays := viper.GetInt("server.agent_inactivity_days")
		var agentInactivityLimit time.Duration
		if agentInactivityDays > 0 {
			agentInactivityLimit = time.Duration(agentInactivityDays) * 24 * time.Hour
		}

		// Ensure directory exists
		os.MkdirAll(filepath.Dir(dbPath), 0700)

		// Load plugins from multiple directories
		pluginDirs := []string{}
		
		if envDir := os.Getenv("CREDDY_PLUGIN_DIR"); envDir != "" {
			pluginDirs = append(pluginDirs, envDir)
		}
		if configDir := viper.GetString("plugin.dir"); configDir != "" {
			pluginDirs = append(pluginDirs, configDir)
		}
		// User plugins
		if home, err := os.UserHomeDir(); err == nil {
			pluginDirs = append(pluginDirs, filepath.Join(home, ".local", "share", "creddy", "plugins"))
		}
		// System plugins
		pluginDirs = append(pluginDirs, "/usr/local/lib/creddy/plugins")
		
		// Use the first existing directory, or the system dir as fallback
		pluginDir := "/usr/local/lib/creddy/plugins"
		for _, dir := range pluginDirs {
			if _, err := os.Stat(dir); err == nil {
				pluginDir = dir
				break
			}
		}

		pluginLoader := plugin.NewLoader(pluginDir)
		if err := pluginLoader.LoadAllPlugins(); err != nil {
			log.Printf("Warning: failed to load plugins: %v", err)
		}

		// Register plugin loader as the default
		plugin.NewLoaderBridge(pluginLoader).Register()

		// Log loaded plugins
		loadedPlugins := pluginLoader.ListPlugins()
		if len(loadedPlugins) > 0 {
			fmt.Printf("Loaded %d plugins:\n", len(loadedPlugins))
			for _, p := range loadedPlugins {
				fmt.Printf("  - %s v%s\n", p.Info.Name, p.Info.Version)
			}
		}

		srv, err := server.New(server.Config{
			DBPath:               dbPath,
			Domain:               domain,
			AgentInactivityLimit: agentInactivityLimit,
			PluginLoader:         pluginLoader,
		})
		if err != nil {
			return fmt.Errorf("failed to start server: %w", err)
		}
		defer srv.Close()

		// Handle graceful shutdown
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigCh
			fmt.Println("\nShutting down...")
			pluginLoader.UnloadAll()
			srv.Close()
			os.Exit(0)
		}()

		fmt.Printf("Starting creddy server on %s\n", listen)
		fmt.Printf("Database: %s\n", dbPath)
		if agentInactivityLimit > 0 {
			fmt.Printf("Agent inactivity limit: %v\n", agentInactivityLimit)
		}
		return http.ListenAndServe(listen, srv.Handler())
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().String("listen", "127.0.0.1:8400", "Address to listen on")
	serverCmd.Flags().String("db", "", "Database path")
	serverCmd.Flags().String("domain", "creddy.local", "Domain for agent email addresses")
	serverCmd.Flags().Int("agent-inactivity-days", 0, "Auto-unenroll agents inactive for this many days (0 = disabled)")
	viper.BindPFlag("server.listen", serverCmd.Flags().Lookup("listen"))
	viper.BindPFlag("database.path", serverCmd.Flags().Lookup("db"))
	viper.BindPFlag("server.domain", serverCmd.Flags().Lookup("domain"))
	viper.BindPFlag("server.agent_inactivity_days", serverCmd.Flags().Lookup("agent-inactivity-days"))
}
