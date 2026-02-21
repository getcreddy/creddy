package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

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
			home, _ := os.UserHomeDir()
			dbPath = filepath.Join(home, ".creddy", "creddy.db")
		}

		domain := viper.GetString("server.domain")
		if domain == "" {
			domain = "creddy.local"
		}

		// Ensure directory exists
		os.MkdirAll(filepath.Dir(dbPath), 0700)

		srv, err := server.New(server.Config{
			DBPath: dbPath,
			Domain: domain,
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
			srv.Close()
			os.Exit(0)
		}()

		fmt.Printf("Starting creddy server on %s\n", listen)
		fmt.Printf("Database: %s\n", dbPath)
		return http.ListenAndServe(listen, srv.Handler())
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().String("listen", "127.0.0.1:8400", "Address to listen on")
	serverCmd.Flags().String("db", "", "Database path")
	serverCmd.Flags().String("domain", "creddy.local", "Domain for agent email addresses")
	viper.BindPFlag("server.listen", serverCmd.Flags().Lookup("listen"))
	viper.BindPFlag("database.path", serverCmd.Flags().Lookup("db"))
	viper.BindPFlag("server.domain", serverCmd.Flags().Lookup("domain"))
}
