package cmd

import (
	"fmt"
	"net/http"

	"github.com/marccampbell/creddy/pkg/server"
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

		srv := server.New()
		fmt.Printf("Starting creddy server on %s\n", listen)
		return http.ListenAndServe(listen, srv.Handler())
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.Flags().String("listen", "127.0.0.1:8400", "Address to listen on")
	viper.BindPFlag("server.listen", serverCmd.Flags().Lookup("listen"))
}
