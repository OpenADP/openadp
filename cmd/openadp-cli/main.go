// Package main provides a command-line interface for OpenADP operations.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/openadp/openadp/pkg/auth"
	"github.com/openadp/openadp/pkg/keygen"
)

const (
	version = "1.0.0"
	banner  = `
 ██████╗ ██████╗ ███████╗███╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔══██╗
██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████║██║  ██║██████╔╝
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██╔══██║██║  ██║██╔═══╝ 
╚██████╔╝██║     ███████╗██║ ╚████║██║  ██║██████╔╝██║     
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚═╝     
                                                            
Open Authenticated Data Protection - Go Implementation v%s
`
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "Show version information")
		showHelp    = flag.Bool("help", false, "Show help information")
		command     = flag.String("command", "", "Command to execute")
		filename    = flag.String("file", "", "File to encrypt/decrypt")
		userID      = flag.String("user", "", "User ID (UUID)")
		servers     = flag.String("servers", "", "Comma-separated list of server URLs")
		interactive = flag.Bool("interactive", false, "Run in interactive mode")
	)

	flag.Parse()

	if *showVersion {
		fmt.Printf("OpenADP Go Implementation v%s\n", version)
		return
	}

	if *showHelp {
		showHelpText()
		return
	}

	fmt.Printf(banner, version)

	if *interactive {
		runInteractiveMode()
		return
	}

	if *command == "" {
		fmt.Println("No command specified. Use -help for usage information.")
		return
	}

	switch *command {
	case "generate-auth":
		generateAuthCode()
	case "derive-key":
		if *filename == "" || *userID == "" {
			fmt.Println("Error: -file and -user are required for derive-key command")
			return
		}
		deriveKey(*filename, *userID, *servers)
	case "test":
		runTests()
	default:
		fmt.Printf("Unknown command: %s\n", *command)
		showHelpText()
	}
}

func showHelpText() {
	fmt.Print(`OpenADP Command Line Interface

USAGE:
    openadp-cli [OPTIONS]

OPTIONS:
    -version              Show version information
    -help                 Show this help message
    -interactive          Run in interactive mode
    -command <cmd>        Command to execute
    -file <path>          File to encrypt/decrypt
    -user <uuid>          User ID (UUID)
    -servers <urls>       Comma-separated server URLs

COMMANDS:
    generate-auth         Generate a new authentication code
    derive-key            Derive encryption key for a file
    test                  Run system tests

EXAMPLES:
    # Generate authentication code
    openadp-cli -command generate-auth

    # Derive key for file
    openadp-cli -command derive-key -file document.txt -user user-uuid-123

    # Run in interactive mode
    openadp-cli -interactive
`)
}

func generateAuthCode() {
	fmt.Println("\n🔑 Generating Authentication Code...")
	fmt.Println("=====================================")

	manager := auth.NewAuthCodeManager()
	authCode, err := manager.GenerateAuthCode()
	if err != nil {
		fmt.Printf("❌ Error generating authentication code: %v\n", err)
		return
	}

	fmt.Printf("✅ Generated Authentication Code: %s\n", authCode)
	fmt.Printf("📏 Length: %d characters (128 bits)\n", len(authCode))

	// Format with spacing for readability
	formatted := manager.FormatAuthCode(authCode, true)
	fmt.Printf("📋 Formatted: %s\n", formatted)

	// Validate
	if manager.ValidateBaseCodeFormat(authCode) {
		fmt.Println("✅ Format validation: PASSED")
	} else {
		fmt.Println("❌ Format validation: FAILED")
	}
}

func deriveKey(filename, userID, serversStr string) {
	fmt.Printf("\n🗝️  Deriving Encryption Key for: %s\n", filename)
	fmt.Println("==========================================")

	// Get password securely
	fmt.Print("Enter password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("\n❌ Error reading password: %v\n", err)
		return
	}
	password := string(passwordBytes)
	fmt.Println() // New line after password input

	// Parse server URLs
	var serverURLs []string
	if serversStr != "" {
		serverURLs = strings.Split(serversStr, ",")
		for i, url := range serverURLs {
			serverURLs[i] = strings.TrimSpace(url)
		}
	} else {
		// Default test servers
		serverURLs = []string{
			"https://server1.openadp.org",
			"https://server2.openadp.org",
		}
	}

	// Derive identifiers
	uid, did, bid := keygen.DeriveIdentifiers(filename, userID, "")
	fmt.Printf("📋 Identifiers:\n")
	fmt.Printf("   UID: %s\n", uid)
	fmt.Printf("   DID: %s\n", did)
	fmt.Printf("   BID: %s\n", bid)

	// Convert password to PIN
	pin := keygen.PasswordToPin(password)
	fmt.Printf("🔢 PIN: %02x%02x\n", pin[0], pin[1])

	// Generate key
	fmt.Printf("🔄 Generating encryption key using %d servers...\n", len(serverURLs))
	result := keygen.GenerateEncryptionKey(filename, password, userID, 10, 0, serverURLs)

	if result.Error != "" {
		fmt.Printf("❌ Key generation failed: %s\n", result.Error)
		return
	}

	fmt.Printf("✅ Successfully generated encryption key!\n")
	fmt.Printf("🔑 Key length: %d bytes\n", len(result.EncryptionKey))
	fmt.Printf("🌐 Servers used: %d\n", len(result.ServerURLs))
	fmt.Printf("🎯 Threshold: %d\n", result.Threshold)
	fmt.Printf("🔐 Key preview: %x...\n", result.EncryptionKey[:8])
}

func runTests() {
	fmt.Println("\n🧪 Running OpenADP System Tests...")
	fmt.Println("==================================")

	// Test 1: Authentication codes
	fmt.Print("1. Authentication Code Manager... ")
	manager := auth.NewAuthCodeManager()
	authCode, err := manager.GenerateAuthCode()
	if err != nil || !manager.ValidateBaseCodeFormat(authCode) {
		fmt.Println("❌ FAILED")
		return
	}
	fmt.Println("✅ PASSED")

	// Test 2: Key derivation
	fmt.Print("2. Key Derivation... ")
	uid, did, bid := keygen.DeriveIdentifiers("test.txt", "test-user", "")
	pin := keygen.PasswordToPin("test-password")
	if len(pin) != 2 || uid == "" || did == "" || bid == "" {
		fmt.Println("❌ FAILED")
		return
	}
	fmt.Println("✅ PASSED")

	fmt.Println("\n🎉 All tests passed! OpenADP is working correctly.")
}

func runInteractiveMode() {
	fmt.Println("\n🎮 Interactive Mode")
	fmt.Println("===================")
	fmt.Println("Available commands:")
	fmt.Println("  1. generate-auth  - Generate authentication code")
	fmt.Println("  2. derive-key     - Derive encryption key")
	fmt.Println("  3. test           - Run system tests")
	fmt.Println("  4. help           - Show help")
	fmt.Println("  5. quit           - Exit")

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("\nopenadp> ")
		if !scanner.Scan() {
			break
		}

		command := strings.TrimSpace(scanner.Text())
		switch command {
		case "1", "generate-auth":
			generateAuthCode()
		case "2", "derive-key":
			fmt.Print("Enter filename: ")
			if !scanner.Scan() {
				continue
			}
			filename := strings.TrimSpace(scanner.Text())

			fmt.Print("Enter user ID: ")
			if !scanner.Scan() {
				continue
			}
			userID := strings.TrimSpace(scanner.Text())

			fmt.Print("Enter server URLs (comma-separated, or press Enter for defaults): ")
			if !scanner.Scan() {
				continue
			}
			servers := strings.TrimSpace(scanner.Text())

			deriveKey(filename, userID, servers)
		case "3", "test":
			runTests()
		case "4", "help":
			showHelpText()
		case "5", "quit", "exit":
			fmt.Println("👋 Goodbye!")
			return
		case "":
			continue
		default:
			fmt.Printf("Unknown command: %s\n", command)
			fmt.Println("Type 'help' for available commands.")
		}
	}
}
