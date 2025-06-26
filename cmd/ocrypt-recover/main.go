package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/openadp/ocrypt/ocrypt"
	"golang.org/x/term"
)

// RecoverResult represents the JSON output format for the recover command
type RecoverResult struct {
	Secret           string `json:"secret"`
	RemainingGuesses int    `json:"remaining_guesses"`
	UpdatedMetadata  string `json:"updated_metadata"`
}

func main() {
	var (
		metadata   = flag.String("metadata", "", "Metadata blob from registration (required)")
		password   = flag.String("password", "", "Password/PIN to unlock the secret (will prompt if not provided)")
		serversURL = flag.String("servers-url", "", "Custom URL for server registry (empty uses default)")
		output     = flag.String("output", "", "File to write recovery result JSON (writes to stdout if not specified)")
		help       = flag.Bool("help", false, "Show help message")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Recover a long-term secret using Ocrypt distributed cryptography.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  --metadata string\n        Metadata blob from registration (required)\n")
		fmt.Fprintf(os.Stderr, "  --password string\n        Password/PIN to unlock the secret (will prompt if not provided)\n")
		fmt.Fprintf(os.Stderr, "  --servers-url string\n        Custom URL for server registry (empty uses default)\n")
		fmt.Fprintf(os.Stderr, "  --output string\n        File to write recovery result JSON (writes to stdout if not specified)\n")
		fmt.Fprintf(os.Stderr, "  --help\n        Show help message\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --metadata '{\"servers\":[...]}'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --metadata \"$(cat metadata.json)\" --output result.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --metadata \"$(cat metadata.json)\" --password mypin\n", os.Args[0])
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
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

	// Call ocrypt.Recover
	secret, remainingGuesses, updatedMetadata, err := ocrypt.Recover([]byte(*metadata), pin, *serversURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Recovery failed: %v\n", err)
		os.Exit(1)
	}

	// Create JSON tuple output
	result := RecoverResult{
		Secret:           string(secret),
		RemainingGuesses: remainingGuesses,
		UpdatedMetadata:  string(updatedMetadata),
	}

	outputBytes, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON encoding failed: %v\n", err)
		os.Exit(1)
	}

	// Output result as JSON
	if *output != "" {
		// Write to file
		err := os.WriteFile(*output, outputBytes, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write result to file %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "✅ Recovery result written to %s\n", *output)
	} else {
		// Write to stdout
		fmt.Println(string(outputBytes))
	}
}
