package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/openadp/ocrypt/ocrypt"
	"golang.org/x/term"
)

func main() {
	var (
		userID         = flag.String("user-id", "", "Unique identifier for the user (required)")
		appID          = flag.String("app-id", "", "Application identifier to namespace secrets per app (required)")
		longTermSecret = flag.String("long-term-secret", "", "Long-term secret to protect (required)")
		password       = flag.String("password", "", "Password/PIN to unlock the secret (will prompt if not provided)")
		maxGuesses     = flag.Int("max-guesses", 10, "Maximum wrong PIN attempts before lockout")
		serversURL     = flag.String("servers-url", "", "Custom URL for server registry (empty uses default)")
		output         = flag.String("output", "", "File to write metadata JSON (writes to stdout if not specified)")
		help           = flag.Bool("help", false, "Show help message")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Register a long-term secret using Ocrypt distributed cryptography.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  --user-id string\n        Unique identifier for the user (required)\n")
		fmt.Fprintf(os.Stderr, "  --app-id string\n        Application identifier to namespace secrets per app (required)\n")
		fmt.Fprintf(os.Stderr, "  --long-term-secret string\n        Long-term secret to protect (required)\n")
		fmt.Fprintf(os.Stderr, "  --password string\n        Password/PIN to unlock the secret (will prompt if not provided)\n")
		fmt.Fprintf(os.Stderr, "  --max-guesses int\n        Maximum wrong PIN attempts before lockout (default 10)\n")
		fmt.Fprintf(os.Stderr, "  --servers-url string\n        Custom URL for server registry (empty uses default)\n")
		fmt.Fprintf(os.Stderr, "  --output string\n        File to write metadata JSON (writes to stdout if not specified)\n")
		fmt.Fprintf(os.Stderr, "  --help\n        Show help message\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --user-id alice@example.com --app-id myapp --long-term-secret \"my secret key\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --user-id alice@example.com --app-id myapp --long-term-secret \"my secret key\" --output metadata.json\n", os.Args[0])
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	// Validate required parameters
	if *userID == "" {
		fmt.Fprintf(os.Stderr, "Error: --user-id is required\n")
		flag.Usage()
		os.Exit(1)
	}
	if *appID == "" {
		fmt.Fprintf(os.Stderr, "Error: --app-id is required\n")
		flag.Usage()
		os.Exit(1)
	}
	if *longTermSecret == "" {
		fmt.Fprintf(os.Stderr, "Error: --long-term-secret is required\n")
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

	// Call ocrypt.Register
	metadata, err := ocrypt.Register(*userID, *appID, []byte(*longTermSecret), pin, *maxGuesses, *serversURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Registration failed: %v\n", err)
		os.Exit(1)
	}

	// Output metadata as JSON
	if *output != "" {
		// Write to file
		err := os.WriteFile(*output, metadata, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write metadata to file %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "✅ Metadata written to %s\n", *output)
	} else {
		// Write to stdout
		fmt.Println(string(metadata))
	}
}
