package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Manage agent identities",
}

var agentCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new agent identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		scopes, _ := cmd.Flags().GetStringSlice("can")

		// Generate agent token
		token := generateAgentToken()

		// TODO: Store in database
		fmt.Printf("Agent created: %s\n", name)
		fmt.Printf("Scopes: %v\n", scopes)
		fmt.Printf("\nAgent token (save this, it won't be shown again):\n")
		fmt.Printf("  %s\n", token)

		return nil
	},
}

var agentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSCOPES\tCREATED\tLAST USED")
		// TODO: List from database
		w.Flush()
		return nil
	},
}

var agentRevokeCmd = &cobra.Command{
	Use:   "revoke [name]",
	Short: "Revoke an agent's token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		// TODO: Revoke in database
		fmt.Printf("Agent revoked: %s\n", name)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)
	agentCmd.AddCommand(agentCreateCmd)
	agentCmd.AddCommand(agentListCmd)
	agentCmd.AddCommand(agentRevokeCmd)

	agentCreateCmd.Flags().StringSlice("can", []string{}, "Scopes this agent can request (e.g., github:read,write)")
}

func generateAgentToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return "ckr_" + hex.EncodeToString(b)
}
