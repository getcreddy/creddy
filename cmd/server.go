package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/getcreddy/creddy/pkg/config"
	"github.com/getcreddy/creddy/pkg/logger"
	"github.com/getcreddy/creddy/pkg/plugin"
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
		
		logger.Debug("searching for plugins", "dirs", pluginDirs)
		pluginLoader := plugin.LoadFromDirectories(pluginDirs, logger.ForPlugin())

		// Register plugin loader as the default
		plugin.NewLoaderBridge(pluginLoader).Register()

		// Log loaded plugins
		loadedPlugins := pluginLoader.ListPlugins()
		if len(loadedPlugins) > 0 {
			logger.Info("loaded plugins", "count", len(loadedPlugins))
			for _, p := range loadedPlugins {
				logger.Debug("plugin loaded", "name", p.Info.Name, "version", p.Info.Version)
				fmt.Printf("  - %s v%s\n", p.Info.Name, p.Info.Version)
			}
		}


		// Load policies from config
		var policyEngine *policy.Engine
		configPath := viper.ConfigFileUsed()
		if configPath != "" {
			cfg, err := config.Load(configPath)
			if err != nil {
				logger.Warn("failed to load config", "error", err)
			} else if len(cfg.Policies) > 0 {
				policyEngine = policy.NewEngine(cfg.Policies)
				logger.Info("loaded auto-approval policies", "count", len(cfg.Policies))
				fmt.Printf("Loaded %d auto-approval policies\n", len(cfg.Policies))
			}
		}

		// Set server version for health endpoint
		server.ServerVersion = Version
		server.ServerCommit = Commit

		// OIDC configuration
		oidcIssuer := viper.GetString("oidc.issuer")

		srv, err := server.New(server.Config{
			DBPath:               dbPath,
			DataDir:              filepath.Dir(dbPath), // Directory containing the database
			Domain:               domain,
			AgentInactivityLimit: agentInactivityLimit,
			PluginLoader:         pluginLoader,
			PolicyEngine:         policyEngine,
			OIDCIssuer:           oidcIssuer,
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
		fmt.Printf("Database: %s\n", dbPath)
		if agentInactivityLimit > 0 {
			fmt.Printf("Agent inactivity limit: %v\n", agentInactivityLimit)
		}
		if oidcIssuer != "" {
			fmt.Printf("OIDC Issuer: %s\n", oidcIssuer)
			fmt.Printf("  Discovery: %s/.well-known/openid-configuration\n", oidcIssuer)
			fmt.Printf("  JWKS: %s/.well-known/jwks.json\n", oidcIssuer)
		}

		handler := srv.Handler()
		errCh := make(chan error, 2)

		// Always listen on localhost for local CLI access
		localAddr := "127.0.0.1:8400"
		if listen != localAddr && !strings.HasPrefix(listen, "127.0.0.1:") {
			go func() {
				logger.Info("listening", "addr", localAddr, "type", "local admin")
				fmt.Printf("Listening on %s (local admin)\n", localAddr)
				errCh <- http.ListenAndServe(localAddr, handler)
			}()
		}

		// Listen on configured address
		go func() {
			logger.Info("listening", "addr", listen)
			fmt.Printf("Listening on %s\n", listen)
			errCh <- http.ListenAndServe(listen, handler)
		}()

		// Wait for either to fail
		return <-errCh
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().String("listen", "127.0.0.1:8400", "Address to listen on")
	serverCmd.Flags().String("db", "", "Database path")
	serverCmd.Flags().String("domain", "creddy.local", "Domain for agent email addresses")
	serverCmd.Flags().Int("agent-inactivity-days", 0, "Auto-unenroll agents inactive for this many days (0 = disabled)")
	serverCmd.Flags().String("oidc-issuer", "", "OIDC issuer URL (enables OIDC provider, e.g., https://creddy.example.com)")
	viper.BindPFlag("server.listen", serverCmd.Flags().Lookup("listen"))
	viper.BindPFlag("database.path", serverCmd.Flags().Lookup("db"))
	viper.BindPFlag("server.domain", serverCmd.Flags().Lookup("domain"))
	viper.BindPFlag("server.agent_inactivity_days", serverCmd.Flags().Lookup("agent-inactivity-days"))
	viper.BindPFlag("oidc.issuer", serverCmd.Flags().Lookup("oidc-issuer"))
}
