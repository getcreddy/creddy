package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "creddy",
	Short: "Ephemeral credentials for AI agents",
	Long: `Creddy is a central identity service that provides scoped, 
time-limited credentials to AI agents without exposing master secrets.

Agents authenticate to Creddy, and Creddy issues ephemeral tokens
for services like GitHub, AWS, and more.`,
	SilenceErrors: true,
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
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search order: ~/.config/creddy, ~/.creddy (legacy), current dir
		viper.AddConfigPath(home + "/.config/creddy")
		viper.AddConfigPath(home + "/.creddy")
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
