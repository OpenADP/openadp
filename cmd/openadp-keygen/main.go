package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/openadp/common/crypto"
)

const version = "1.0.0"

func main() {
	// Check for help flag
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		printHelp()
		return
	}

	// Check for version flag
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version") {
		fmt.Printf("OpenADP Key Generator v%s\n", version)
		return
	}

	// Generate keypair
	privateKey, publicKey, err := crypto.X25519GenerateKeypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keypair: %v\n", err)
		os.Exit(1)
	}

	// Save private key
	keyFilename := "server_sk.key"
	err = os.WriteFile(keyFilename, privateKey, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Printf("Private key saved to %s\n", keyFilename)
	fmt.Println("Add the following public key to your servers.json file:")
	fmt.Println(base64.StdEncoding.EncodeToString(publicKey))
}

func printHelp() {
	fmt.Printf(`OpenADP Key Generator v%s

DESCRIPTION:
    Generates a static X25519 keypair for the OpenADP server.
    
    The private key is saved to 'server_sk.key' and the public key
    is printed to standard output in Base64 format.

USAGE:
    openadp-keygen [OPTIONS]

OPTIONS:
    -h, --help      Show this help message
    -v, --version   Show version information

EXAMPLES:
    # Generate a new server keypair
    openadp-keygen
    
    # The private key will be saved to server_sk.key (mode 0600)
    # The public key will be printed in Base64 format

SECURITY:
    - The private key file is created with restrictive permissions (0600)
    - Store the private key securely and do not share it
    - The public key can be safely shared and added to servers.json

`, version)
}
