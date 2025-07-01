package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/openadp/openadp/sdk/go/ocrypt"
	"golang.org/x/term"
)

// TestResult represents the output format for test mode
type TestResult struct {
	Secret      string `json:"secret"`
	NewMetadata string `json:"new_metadata"`
}

// safeWriteFile safely writes data to a file, backing up existing file first
func safeWriteFile(filename string, data []byte, perm os.FileMode) error {
	// Check if file exists
	if _, err := os.Stat(filename); err == nil {
		// File exists, create backup
		backupName := filename + ".old"
		fmt.Fprintf(os.Stderr, "📋 Backing up existing %s to %s\n", filename, backupName)

		if err := os.Rename(filename, backupName); err != nil {
			return fmt.Errorf("failed to backup existing file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "✅ Backup created: %s\n", backupName)
	}

	// Write new file
	if err := os.WriteFile(filename, data, perm); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	return nil
}

func main() {
	var (
		metadata   = flag.String("metadata", "", "Metadata blob from registration (required)")
		password   = flag.String("password", "", "Password/PIN to unlock the secret (will prompt if not provided)")
		serversURL = flag.String("servers-url", "", "Custom URL for server registry (empty uses default)")
		output     = flag.String("output", "", "File to write new metadata JSON (writes to stdout if not specified)")
		debugMode  = flag.Bool("debug", false, "Enable debug mode (deterministic operations)")
		testMode   = flag.Bool("test-mode", false, "Enable test mode (outputs JSON with secret and metadata)")
		help       = flag.Bool("help", false, "Show help message")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Recover a long-term secret and re-register with fresh cryptographic material.\n\n")
		fmt.Fprintf(os.Stderr, "This tool:\n")
		fmt.Fprintf(os.Stderr, "  1. Recovers your secret from old metadata\n")
		fmt.Fprintf(os.Stderr, "  2. Re-registers it with fresh cryptographic material\n")
		fmt.Fprintf(os.Stderr, "  3. Outputs new metadata (automatically backs up existing files)\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  --metadata string\n        Metadata blob from registration (required)\n")
		fmt.Fprintf(os.Stderr, "  --password string\n        Password/PIN to unlock the secret (will prompt if not provided)\n")
		fmt.Fprintf(os.Stderr, "  --servers-url string\n        Custom URL for server registry (default: https://servers.openadp.org/api/servers.json)\n")
		fmt.Fprintf(os.Stderr, "  --output string\n        File to write new metadata JSON (writes to stdout if not specified)\n")
		fmt.Fprintf(os.Stderr, "        Note: Existing files are automatically backed up with .old extension\n")
		fmt.Fprintf(os.Stderr, "  --debug\n        Enable debug mode (deterministic operations)\n")
		fmt.Fprintf(os.Stderr, "  --test-mode\n        Enable test mode (outputs JSON with secret and metadata)\n")
		fmt.Fprintf(os.Stderr, "  --help\n        Show help message\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --metadata '{\"servers\":[...]}'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --metadata \"$(cat metadata.json)\" --output metadata.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --metadata \"$(cat metadata.json)\" --password mypin\n", os.Args[0])
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	// Set debug mode if requested
	if *debugMode {
		fmt.Fprintf(os.Stderr, "🐛 Debug mode enabled - using deterministic operations\n")
		ocrypt.SetDebugMode(true)
	}

	// Validate required parameters
	if *metadata == "" {
		fmt.Fprintf(os.Stderr, "Error: --metadata is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// Handle password input
	var pin string
	if *password != "" {
		pin = *password
	} else {
		fmt.Fprint(os.Stderr, "Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nError reading password: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr) // Print newline after password input
		pin = string(passwordBytes)

		if pin == "" {
			fmt.Fprintf(os.Stderr, "Error: password cannot be empty\n")
			os.Exit(1)
		}
	}

	// Call the new RecoverAndReregister API
	result, err := ocrypt.RecoverAndReregister([]byte(*metadata), pin, *serversURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Recovery and re-registration failed: %v\n", err)
		os.Exit(1)
	}

	// Handle test mode
	if *testMode {
		testResult := TestResult{
			Secret:      string(result.Secret),
			NewMetadata: string(result.NewMetadata),
		}
		jsonOutput, err := json.Marshal(testResult)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal test result: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonOutput))
		return
	}

	// Normal mode: Print recovered secret to stderr for user verification
	fmt.Fprintf(os.Stderr, "🔑 Recovered secret: %s\n", string(result.Secret))

	// Output new metadata
	if *output != "" {
		// Write to file with safe backup
		err := safeWriteFile(*output, result.NewMetadata, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write metadata to file %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "✅ New metadata written to %s\n", *output)
	} else {
		// Write to stdout
		fmt.Println(string(result.NewMetadata))
	}
}
