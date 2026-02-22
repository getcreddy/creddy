package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/getcreddy/creddy/pkg/client"
	"github.com/getcreddy/creddy/pkg/enrollment"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize and enroll with a Creddy server",
	Long: `Generate a keypair and enroll with a Creddy server.

The enrollment requires admin approval unless an admin token is provided.`,
	RunE: runInit,
}

var (
	initName       string
	initServer     string
	initAdminToken string
	initTimeout    time.Duration
)

func init() {
	rootCmd.AddCommand(initCmd)
	
	initCmd.Flags().StringVar(&initName, "name", "", "Client name (defaults to hostname)")
	initCmd.Flags().StringVar(&initServer, "server", "", "Server URL (required)")
	initCmd.Flags().StringVar(&initAdminToken, "admin-token", "", "Bootstrap admin token (first admin only)")
	initCmd.Flags().DurationVar(&initTimeout, "timeout", 5*time.Minute, "Enrollment timeout")
	
	initCmd.MarkFlagRequired("server")
}

func runInit(cmd *cobra.Command, args []string) error {
	// Check if already initialized
	if _, err := client.Load(); err == nil {
		return fmt.Errorf("client already initialized. Run 'creddy status' to view")
	}
	
	// Get client name
	name := initName
	if name == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		name = hostname
	}
	
	// Generate keypair
	fmt.Print("Generating keypair... ")
	pubKey, privKey, err := client.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}
	fmt.Println("done")
	
	fingerprint := client.Fingerprint(pubKey)
	
	// Get metadata
	metadata := map[string]string{
		"hostname": name,
	}
	if user := os.Getenv("USER"); user != "" {
		metadata["username"] = user
	}
	
	// Initiate enrollment
	fmt.Print("Registering with server... ")
	
	reqBody := enrollment.InitiateRequest{
		PublicKey: client.EncodePublicKey(pubKey),
		Name:      name,
		Metadata:  metadata,
	}
	
	reqJSON, _ := json.Marshal(reqBody)
	
	resp, err := http.Post(initServer+"/api/v1/enrollments", "application/json", bytes.NewReader(reqJSON))
	if err != nil {
		return fmt.Errorf("failed to contact server: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enrollment failed: %s", string(body))
	}
	
	var initResp enrollment.InitiateResponse
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	fmt.Println("done")
	
	// Wait for approval
	fmt.Println()
	fmt.Println("Waiting for approval...")
	fmt.Printf("  Name:        %s\n", name)
	fmt.Printf("  Fingerprint: %s\n", fingerprint)
	fmt.Println()
	fmt.Println("Ask an admin to approve, or run:")
	fmt.Printf("  creddy admin approve %s\n", initResp.EnrollmentID)
	fmt.Println()
	
	pollInterval := time.Duration(initResp.PollIntervalMs) * time.Millisecond
	if pollInterval == 0 {
		pollInterval = 2 * time.Second
	}
	
	deadline := time.Now().Add(initTimeout)
	spinner := []string{"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"}
	spinIdx := 0
	
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline).Round(time.Second)
		fmt.Printf("\r%s Waiting for approval... (%s remaining)   ", spinner[spinIdx], remaining)
		spinIdx = (spinIdx + 1) % len(spinner)
		
		// Poll status
		statusResp, err := http.Get(initServer + "/api/v1/enrollments/" + initResp.EnrollmentID + "/status")
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}
		
		var status enrollment.StatusResponse
		if err := json.NewDecoder(statusResp.Body).Decode(&status); err != nil {
			statusResp.Body.Close()
			time.Sleep(pollInterval)
			continue
		}
		statusResp.Body.Close()
		
		switch status.Status {
		case enrollment.StatusApproved:
			fmt.Println("\r✓ Approved!                                    ")
			fmt.Printf("✓ Client registered: %s\n", status.ClientID)
			
			// Save credentials
			c := &client.Client{
				ID:         status.ClientID,
				Name:       name,
				PrivateKey: privKey,
				PublicKey:  pubKey,
				ServerURL:  initServer,
			}
			
			if err := c.Save(); err != nil {
				return fmt.Errorf("failed to save credentials: %w", err)
			}
			
			dir, _ := client.CredentialsDir()
			fmt.Printf("✓ Credentials saved to %s/\n", dir)
			fmt.Println()
			fmt.Println("Ready. Try: creddy backends")
			return nil
			
		case enrollment.StatusDenied:
			fmt.Printf("\r✗ Denied: %s\n", status.Reason)
			return fmt.Errorf("enrollment denied")
			
		case enrollment.StatusExpired:
			fmt.Println("\r✗ Enrollment expired")
			return fmt.Errorf("enrollment expired")
		}
		
		time.Sleep(pollInterval)
	}
	
	fmt.Println("\r✗ Enrollment timed out")
	return fmt.Errorf("enrollment timed out after %s", initTimeout)
}
