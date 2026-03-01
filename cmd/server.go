package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/getcreddy/creddy/pkg/plugin"
	"log"
	"github.com/getcreddy/creddy/pkg/config"
	"github.com/getcreddy/creddy/pkg/policy"
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
		// System plugins first (higher priority)
		pluginDirs = append(pluginDirs, "/usr/local/lib/creddy/plugins")
		// User plugins
		if home, err := os.UserHomeDir(); err == nil {
			pluginDirs = append(pluginDirs, filepath.Join(home, ".local", "share", "creddy", "plugins"))
		}
		
		pluginLoader := plugin.LoadFromDirectories(pluginDirs, nil)

		// Register plugin loader as the default
		plugin.NewLoaderBridge(pluginLoader).Register()
		plugin.NewLoaderBridge(pluginLoader).Register()

		// Log loaded plugins
		loadedPlugins := pluginLoader.ListPlugins()
		if len(loadedPlugins) > 0 {
			fmt.Printf("Loaded %d plugins:\n", len(loadedPlugins))
			for _, p := range loadedPlugins {
				fmt.Printf("  - %s v%s\n", p.Info.Name, p.Info.Version)
			}
		}


		// Load policies from config
		var policyEngine *policy.Engine
		configPath := viper.ConfigFileUsed()
		if configPath != "" {
			cfg, err := config.Load(configPath)
			if err != nil {
				log.Printf("Warning: failed to load config: %v", err)
			} else if len(cfg.Policies) > 0 {
				policyEngine = policy.NewEngine(cfg.Policies)
				fmt.Printf("Loaded %d auto-approval policies\n", len(cfg.Policies))
			}
		}

		srv, err := server.New(server.Config{
			DBPath:               dbPath,
			DataDir:              filepath.Dir(dbPath), // Directory containing the database
			Domain:               domain,
			AgentInactivityLimit: agentInactivityLimit,
			PluginLoader:         pluginLoader,
			PolicyEngine:         policyEngine,
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
