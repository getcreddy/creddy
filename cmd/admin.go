package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/getcreddy/creddy/pkg/enrollment"
	"github.com/getcreddy/creddy/pkg/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Admin commands for managing clients and enrollments",
}

var adminEnrollmentsCmd = &cobra.Command{
	Use:   "enrollments",
	Short: "List enrollment requests",
	RunE:  runAdminEnrollments,
}

var adminApproveCmd = &cobra.Command{
	Use:   "approve <enrollment_id>",
	Short: "Approve an enrollment request",
	Args:  cobra.ExactArgs(1),
	RunE:  runAdminApprove,
}

var adminDenyCmd = &cobra.Command{
	Use:   "deny <enrollment_id>",
	Short: "Deny an enrollment request",
	Args:  cobra.ExactArgs(1),
	RunE:  runAdminDeny,
}

var adminClientsCmd = &cobra.Command{
	Use:   "clients",
	Short: "List registered clients",
	RunE:  runAdminClients,
}

var adminRevokeCmd = &cobra.Command{
	Use:   "revoke <client_id>",
	Short: "Revoke a client",
	Args:  cobra.ExactArgs(1),
	RunE:  runAdminRevoke,
}

var (
	adminApproveRole   string
	adminApproveNote   string
	adminDenyReason    string
	adminRevokeReason  string
	adminListStatus    string
)

func init() {
	rootCmd.AddCommand(adminCmd)
	
	adminCmd.AddCommand(adminEnrollmentsCmd)
	adminCmd.AddCommand(adminApproveCmd)
	adminCmd.AddCommand(adminDenyCmd)
	adminCmd.AddCommand(adminClientsCmd)
	adminCmd.AddCommand(adminRevokeCmd)
	
	adminEnrollmentsCmd.Flags().StringVar(&adminListStatus, "status", "pending", "Filter by status (pending, approved, denied)")
	
	adminApproveCmd.Flags().StringVar(&adminApproveRole, "role", "operator", "Client role (operator, admin)")
	adminApproveCmd.Flags().StringVar(&adminApproveNote, "note", "", "Admin note")
	
	adminDenyCmd.Flags().StringVar(&adminDenyReason, "reason", "", "Reason for denial")
	
	adminRevokeCmd.Flags().StringVar(&adminRevokeReason, "reason", "", "Reason for revocation")
}

func getStore() (*store.Store, error) {
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		home, _ := os.UserHomeDir()
		dbPath = home + "/.creddy/creddy.db"
	}
	return store.New(dbPath)
}

func runAdminEnrollments(cmd *cobra.Command, args []string) error {
	st, err := getStore()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()
	
	enrollments, err := st.ListEnrollments(enrollment.Status(adminListStatus))
	if err != nil {
		return fmt.Errorf("failed to list enrollments: %w", err)
	}
	
	if len(enrollments) == 0 {
		fmt.Println("No enrollments found")
		return nil
	}
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tUSER\tHOST\tIP\tEXPIRES")
	
	for _, e := range enrollments {
		user := e.Metadata["username"]
		host := e.Metadata["hostname"]
		expires := ""
		if e.Status == enrollment.StatusPending {
			remaining := time.Until(e.ExpiresAt)
			if remaining > 0 {
				expires = fmt.Sprintf("%d:%02d", int(remaining.Minutes()), int(remaining.Seconds())%60)
			} else {
				expires = "expired"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.Name, user, host, e.IPAddress, expires)
	}
	
	w.Flush()
	return nil
}

func runAdminApprove(cmd *cobra.Command, args []string) error {
	enrollmentID := args[0]
	
	st, err := getStore()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()
	
	// Verify the enrollment exists and is pending
	e, err := st.GetEnrollment(enrollmentID)
	if err != nil {
		return fmt.Errorf("enrollment not found: %w", err)
	}
	
	if e.Status != enrollment.StatusPending {
		return fmt.Errorf("enrollment is not pending (status: %s)", e.Status)
	}
	
	if time.Now().After(e.ExpiresAt) {
		return fmt.Errorf("enrollment has expired")
	}
	
	// Get approver identity (for now, just use username)
	approvedBy := os.Getenv("USER")
	if approvedBy == "" {
		approvedBy = "admin"
	}
	
	// Approve
	client, err := st.ApproveEnrollment(enrollmentID, approvedBy, adminApproveRole, adminApproveNote)
	if err != nil {
		return fmt.Errorf("failed to approve enrollment: %w", err)
	}
	
	fmt.Printf("✓ Approved %s (%s)\n", e.Name, client.ID)
	fmt.Printf("  Role: %s\n", client.Role)
	return nil
}

func runAdminDeny(cmd *cobra.Command, args []string) error {
	enrollmentID := args[0]
	
	st, err := getStore()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()
	
	// Verify the enrollment exists and is pending
	e, err := st.GetEnrollment(enrollmentID)
	if err != nil {
		return fmt.Errorf("enrollment not found: %w", err)
	}
	
	if e.Status != enrollment.StatusPending {
		return fmt.Errorf("enrollment is not pending (status: %s)", e.Status)
	}
	
	deniedBy := os.Getenv("USER")
	if deniedBy == "" {
		deniedBy = "admin"
	}
	
	if err := st.DenyEnrollment(enrollmentID, deniedBy, adminDenyReason); err != nil {
		return fmt.Errorf("failed to deny enrollment: %w", err)
	}
	
	fmt.Printf("✗ Denied %s\n", e.Name)
	return nil
}

func runAdminClients(cmd *cobra.Command, args []string) error {
	st, err := getStore()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()
	
	clients, err := st.ListClients(adminListStatus)
	if err != nil {
		return fmt.Errorf("failed to list clients: %w", err)
	}
	
	if len(clients) == 0 {
		fmt.Println("No clients found")
		return nil
	}
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tROLE\tLAST SEEN\tSTATUS")
	
	for _, c := range clients {
		lastSeen := "never"
		if c.LastSeen != nil {
			lastSeen = c.LastSeen.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", c.ID, c.Name, c.Role, lastSeen, c.Status)
	}
	
	w.Flush()
	return nil
}

func runAdminRevoke(cmd *cobra.Command, args []string) error {
	clientID := args[0]
	
	st, err := getStore()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()
	
	// Verify the client exists
	c, err := st.GetClient(clientID)
	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}
	
	if c.Status == "revoked" {
		return fmt.Errorf("client is already revoked")
	}
	
	revokedBy := os.Getenv("USER")
	if revokedBy == "" {
		revokedBy = "admin"
	}
	
	if err := st.RevokeClient(clientID, revokedBy, adminRevokeReason); err != nil {
		return fmt.Errorf("failed to revoke client: %w", err)
	}
	
	fmt.Printf("✓ Revoked %s\n", c.Name)
	return nil
}
