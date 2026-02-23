package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/getcreddy/creddy/pkg/plugin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

// ConfigField mirrors the SDK's ConfigField for JSON unmarshaling
type ConfigField struct {
	Name        string `json:"Name"`
	Type        string `json:"Type"`
	Description string `json:"Description"`
	Required    bool   `json:"Required"`
	Default     string `json:"Default"`
}

var backendCmd = &cobra.Command{
	Use:   "backend",
	Short: "Manage credential backends",
}

var backendAddCmd = &cobra.Command{
	Use:   "add <plugin-type>",
	Short: "Add a credential backend",
	Long: `Add a credential backend using any installed plugin.

Interactive mode (default):
  creddy backend add github
  creddy backend add anthropic --name anthropic-prod

CLI flags mode (for automation):
  creddy backend add github --app-id 123 --private-key-pem-file ./key.pem
  creddy backend add anthropic --admin-key-file ./key.txt

Legacy JSON mode:
  creddy backend add github --config '{"app_id": 123, ...}'
  creddy backend add aws --config-file ./aws-config.json

Use 'creddy plugin list' to see available plugins.`,
	DisableFlagParsing: true, // We handle flags ourselves for dynamic schema
	SilenceUsage:       true, // We print our own usage in help
	SilenceErrors:      true, // We handle errors ourselves
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("plugin type is required\n\nUsage: creddy backend add <plugin-type> [flags]")
		}
		return addBackendDynamic(args)
	},
}

var backendListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured backends",
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL := viper.GetString("admin.url")
		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}

		resp, err := http.Get(serverURL + "/v1/admin/backends")
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		var results []struct {
			ID        string    `json:"id"`
			Type      string    `json:"type"`
			Name      string    `json:"name"`
			CreatedAt time.Time `json:"created_at"`
		}
		json.Unmarshal(body, &results)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tTYPE\tCREATED")
		for _, r := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Name, r.Type, r.CreatedAt.Format(time.RFC3339))
		}
		w.Flush()

		return nil
	},
}

var backendRemoveCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Remove a credential backend",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		serverURL := viper.GetString("admin.url")
		if serverURL == "" {
			serverURL = "http://127.0.0.1:8400"
		}

		req, _ := http.NewRequest("DELETE", serverURL+"/v1/admin/backends/"+name, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
		}

		fmt.Printf("Backend removed: %s\n", name)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(backendCmd)
	backendCmd.AddCommand(backendAddCmd)
	backendCmd.AddCommand(backendListCmd)
	backendCmd.AddCommand(backendRemoveCmd)
}

// addBackendDynamic handles the backend add command with dynamic schema support
func addBackendDynamic(args []string) error {
	// Parse our custom args
	pluginType, name, configJSON, configFile, fieldValues, fieldFiles, err := parseBackendAddArgs(args)
	if err != nil {
		return err
	}

	// If legacy --config or --config-file was provided, use that directly
	if configJSON != "" || configFile != "" {
		return addBackendLegacy(pluginType, name, configJSON, configFile)
	}

	// Get the plugin schema
	schema, err := getPluginSchema(pluginType)
	if err != nil {
		return fmt.Errorf("failed to get plugin schema: %w", err)
	}

	// If no field flags provided, use interactive mode
	if len(fieldValues) == 0 && len(fieldFiles) == 0 {
		return addBackendInteractive(pluginType, name, schema)
	}

	// Build config from provided flags
	return addBackendFromFlags(pluginType, name, schema, fieldValues, fieldFiles)
}

// parseBackendAddArgs parses the raw args for backend add
func parseBackendAddArgs(args []string) (pluginType, name, configJSON, configFile string, fieldValues, fieldFiles map[string]string, err error) {
	fieldValues = make(map[string]string)
	fieldFiles = make(map[string]string)

	if len(args) == 0 {
		err = fmt.Errorf("plugin type is required")
		return
	}

	pluginType = args[0]
	args = args[1:]

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if !strings.HasPrefix(arg, "-") {
			err = fmt.Errorf("unexpected argument: %s", arg)
			return
		}

		// Strip leading dashes
		key := strings.TrimLeft(arg, "-")

		// Handle special flags
		switch key {
		case "help", "h":
			// Show help with schema
			schema, schemaErr := getPluginSchema(pluginType)
			if schemaErr != nil {
				fmt.Printf("Usage: creddy backend add %s [flags]\n\n", pluginType)
				fmt.Println("Failed to load plugin schema:", schemaErr)
			} else {
				printSchemaHelp(pluginType, schema)
			}
			os.Exit(0)
		case "name":
			if i+1 >= len(args) {
				err = fmt.Errorf("--name requires a value")
				return
			}
			i++
			name = args[i]
		case "config", "c":
			if i+1 >= len(args) {
				err = fmt.Errorf("--config requires a value")
				return
			}
			i++
			configJSON = args[i]
		case "config-file", "f":
			if i+1 >= len(args) {
				err = fmt.Errorf("--config-file requires a value")
				return
			}
			i++
			configFile = args[i]
		default:
			// Dynamic field flag
			if i+1 >= len(args) {
				err = fmt.Errorf("--%s requires a value", key)
				return
			}
			i++
			value := args[i]

			// Check if it's a -file suffix
			if strings.HasSuffix(key, "-file") {
				fieldName := toSnakeCase(strings.TrimSuffix(key, "-file"))
				fieldFiles[fieldName] = value
			} else {
				fieldName := toSnakeCase(key)
				fieldValues[fieldName] = value
			}
		}
	}

	return
}

// getPluginSchema queries the plugin for its configuration schema
func getPluginSchema(pluginType string) ([]ConfigField, error) {
	pluginDir := getPluginDir()
	loader := plugin.NewLoader(pluginDir)

	// Find the plugin binary
	binaryPath := findPluginBinary(pluginDir, pluginType)
	if binaryPath == "" {
		return nil, fmt.Errorf("plugin not found: %s (install with: creddy plugin install %s)", pluginType, pluginType)
	}

	// Run the plugin with 'schema' command
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, "schema")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try loading via gRPC
		p, loadErr := loader.LoadPlugin(pluginType)
		if loadErr != nil {
			return nil, fmt.Errorf("plugin does not support schema command: %w", err)
		}
		defer loader.UnloadPlugin(pluginType)

		fields, schemaErr := p.Plugin.ConfigSchema(ctx)
		if schemaErr != nil {
			return nil, fmt.Errorf("failed to get schema via gRPC: %w", schemaErr)
		}

		// Convert SDK fields to our local type
		result := make([]ConfigField, len(fields))
		for i, f := range fields {
			result[i] = ConfigField{
				Name:        f.Name,
				Type:        f.Type,
				Description: f.Description,
				Required:    f.Required,
				Default:     f.Default,
			}
		}
		return result, nil
	}

	var schema []ConfigField
	if err := json.Unmarshal(output, &schema); err != nil {
		return nil, fmt.Errorf("failed to parse schema: %w", err)
	}

	return schema, nil
}

// findPluginBinary locates the plugin binary
func findPluginBinary(pluginDir, name string) string {
	candidates := []string{
		filepath.Join(pluginDir, "creddy-"+name),
		filepath.Join(pluginDir, name),
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// addBackendInteractive prompts the user for each config field
func addBackendInteractive(pluginType, name string, schema []ConfigField) error {
	fmt.Printf("Adding %s backend...\n\n", pluginType)

	config := make(map[string]interface{})
	reader := bufio.NewReader(os.Stdin)

	for _, field := range schema {
		value, err := promptForField(reader, field)
		if err != nil {
			return err
		}
		if value != nil {
			config[field.Name] = value
		}
	}

	// Default name to plugin type
	if name == "" {
		name = pluginType
	}

	fmt.Println()
	return submitBackend(pluginType, name, config)
}

// promptForField prompts the user for a single config field
func promptForField(reader *bufio.Reader, field ConfigField) (interface{}, error) {
	// Build prompt
	prompt := field.Name
	if field.Description != "" {
		prompt = field.Description
	}

	// Add required/optional indicator
	if field.Required {
		prompt += " (required)"
	} else if field.Default != "" {
		prompt += fmt.Sprintf(" [default: %s]", field.Default)
	} else {
		prompt += " (optional, press Enter to skip)"
	}
	prompt += ": "

	for {
		fmt.Print(prompt)

		var input string
		var err error

		// For secrets, use terminal password input (masked)
		if field.Type == "secret" {
			if term.IsTerminal(int(syscall.Stdin)) {
				byteInput, termErr := term.ReadPassword(int(syscall.Stdin))
				fmt.Println() // New line after hidden input
				if termErr != nil {
					return nil, termErr
				}
				input = string(byteInput)
			} else {
				// Not a terminal, read normally
				input, err = reader.ReadString('\n')
				if err != nil {
					return nil, err
				}
			}
		} else if field.Type == "file" {
			// For file type, show that we accept a path
			fmt.Print("  (enter file path) ")
			input, err = reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
		} else {
			input, err = reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
		}

		input = strings.TrimSpace(input)

		// Handle empty input
		if input == "" {
			if field.Required {
				fmt.Println("  This field is required. Please enter a value.")
				continue
			}
			if field.Default != "" {
				input = field.Default
			} else {
				return nil, nil // Skip optional field
			}
		}

		// Convert value based on type
		switch field.Type {
		case "int":
			intVal, parseErr := strconv.ParseInt(input, 10, 64)
			if parseErr != nil {
				fmt.Printf("  Invalid integer: %s. Please try again.\n", input)
				continue
			}
			return intVal, nil

		case "bool":
			lower := strings.ToLower(input)
			if lower == "true" || lower == "yes" || lower == "y" || lower == "1" {
				return true, nil
			} else if lower == "false" || lower == "no" || lower == "n" || lower == "0" {
				return false, nil
			}
			fmt.Println("  Please enter true/false, yes/no, or y/n.")
			continue

		case "file":
			// Read file contents
			content, readErr := os.ReadFile(input)
			if readErr != nil {
				fmt.Printf("  Could not read file: %v. Please try again.\n", readErr)
				continue
			}
			return string(content), nil

		case "secret", "string":
			return input, nil

		default:
			return input, nil
		}
	}
}

// addBackendFromFlags builds config from CLI flags
func addBackendFromFlags(pluginType, name string, schema []ConfigField, fieldValues, fieldFiles map[string]string) error {
	config := make(map[string]interface{})

	// Track if any secrets were passed directly (for warning)
	var secretsInHistory []string

	for _, field := range schema {
		var rawValue string
		var fromFile bool

		// Check for file flag first
		if filePath, ok := fieldFiles[field.Name]; ok {
			content, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read %s from file: %w", field.Name, err)
			}
			rawValue = strings.TrimSpace(string(content))
			fromFile = true
		} else if val, ok := fieldValues[field.Name]; ok {
			rawValue = val
			// Warn about secrets in command line
			if field.Type == "secret" {
				secretsInHistory = append(secretsInHistory, field.Name)
			}
		} else if field.Default != "" {
			rawValue = field.Default
		} else if field.Required {
			return fmt.Errorf("missing required field: --%s", toKebabCase(field.Name))
		} else {
			continue // Skip optional field with no value
		}

		// Convert value based on type
		switch field.Type {
		case "int":
			intVal, err := strconv.ParseInt(rawValue, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid integer for %s: %s", field.Name, rawValue)
			}
			config[field.Name] = intVal

		case "bool":
			lower := strings.ToLower(rawValue)
			if lower == "true" || lower == "yes" || lower == "y" || lower == "1" {
				config[field.Name] = true
			} else {
				config[field.Name] = false
			}

		case "file":
			if !fromFile {
				// Value is a path, read it
				content, err := os.ReadFile(rawValue)
				if err != nil {
					return fmt.Errorf("failed to read %s file: %w", field.Name, err)
				}
				config[field.Name] = string(content)
			} else {
				config[field.Name] = rawValue
			}

		default:
			config[field.Name] = rawValue
		}
	}

	// Warn about secrets in bash history
	if len(secretsInHistory) > 0 {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: secret values passed via command line may be visible in shell history\n")
		fmt.Fprintf(os.Stderr, "   Consider using --%s-file instead\n\n", toKebabCase(secretsInHistory[0]))
	}

	// Default name to plugin type
	if name == "" {
		name = pluginType
	}

	return submitBackend(pluginType, name, config)
}

// addBackendLegacy handles the legacy --config / --config-file mode
func addBackendLegacy(pluginType, name, configJSON, configFile string) error {
	if configJSON != "" && configFile != "" {
		return fmt.Errorf("cannot specify both --config and --config-file")
	}

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		configJSON = string(data)
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return fmt.Errorf("invalid JSON config: %w", err)
	}

	if name == "" {
		name = pluginType
	}

	return submitBackend(pluginType, name, config)
}

// submitBackend sends the backend configuration to the server
func submitBackend(pluginType, name string, config map[string]interface{}) error {
	serverURL := viper.GetString("admin.url")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8400"
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	reqBody, _ := json.Marshal(map[string]interface{}{
		"type":   pluginType,
		"name":   name,
		"config": json.RawMessage(configJSON),
	})

	resp, err := http.Post(serverURL+"/v1/admin/backends", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("✓ Backend '%s' added successfully (type: %s)\n", result.Name, result.Type)
	return nil
}

// printSchemaHelp prints help with schema information
func printSchemaHelp(pluginType string, schema []ConfigField) {
	fmt.Printf("Usage: creddy backend add %s [flags]\n\n", pluginType)
	fmt.Println("Interactive mode (default, no flags required):")
	fmt.Printf("  creddy backend add %s\n\n", pluginType)
	fmt.Println("CLI flags mode (for automation):")

	var example strings.Builder
	example.WriteString(fmt.Sprintf("  creddy backend add %s", pluginType))

	fmt.Println("\nConfiguration fields:")
	for _, field := range schema {
		flagName := toKebabCase(field.Name)
		required := ""
		if field.Required {
			required = " (required)"
		}

		// Show the flag
		fmt.Printf("  --%s%s\n", flagName, required)
		if field.Description != "" {
			fmt.Printf("        %s\n", field.Description)
		}
		if field.Type == "file" || field.Type == "secret" {
			fmt.Printf("        Use --%s-file to read from file\n", flagName)
		}
		if field.Default != "" {
			fmt.Printf("        Default: %s\n", field.Default)
		}

		// Build example
		if field.Required {
			switch field.Type {
			case "int":
				example.WriteString(fmt.Sprintf(" --%s 123", flagName))
			case "file":
				example.WriteString(fmt.Sprintf(" --%s-file ./key.pem", flagName))
			case "secret":
				example.WriteString(fmt.Sprintf(" --%s-file ./secret.txt", flagName))
			default:
				example.WriteString(fmt.Sprintf(" --%s value", flagName))
			}
		}
	}

	fmt.Println("\nExample:")
	fmt.Println(example.String())

	fmt.Println("\nOther flags:")
	fmt.Println("  --name          Name for this backend instance (defaults to plugin type)")
	fmt.Println("  --config, -c    Raw JSON configuration (legacy)")
	fmt.Println("  --config-file   Path to JSON config file (legacy)")
}

// toSnakeCase converts kebab-case to snake_case
func toSnakeCase(s string) string {
	return strings.ReplaceAll(s, "-", "_")
}

// toKebabCase converts snake_case to kebab-case
func toKebabCase(s string) string {
	return strings.ReplaceAll(s, "_", "-")
}
