package cmd

import (
	"fmt"
	"os"

	"github.com/getcreddy/creddy/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var debug bool

var rootCmd = &cobra.Command{
	Version: Version,
	Use:   "creddy",
	Short: "Ephemeral credentials for AI agents",
	Long: `Creddy is a central identity service that provides scoped, 
time-limited credentials to AI agents without exposing master secrets.

Agents authenticate to Creddy, and Creddy issues ephemeral tokens
for services like GitHub, AWS, and more.`,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize logger based on --debug flag or CREDDY_DEBUG env var
		debugMode := debug || os.Getenv("CREDDY_DEBUG") == "1"
		logger.Init(debugMode)
		if debugMode {
			logger.Debug("debug logging enabled")
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/creddy/config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// Try to get home dir, but don't fail if not available (e.g., systemd service)
		if home, err := os.UserHomeDir(); err == nil {
			// Search order: ~/.config/creddy, ~/.creddy (legacy), current dir
			viper.AddConfigPath(home + "/.config/creddy")
			viper.AddConfigPath(home + "/.creddy")
		}
		// Also check /etc/creddy for system-wide config
		viper.AddConfigPath("/etc/creddy")
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	viper.SetEnvPrefix("CREDDY")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		// Config loaded
	}
}
