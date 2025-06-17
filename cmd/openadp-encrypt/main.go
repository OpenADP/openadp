package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"

	"github.com/openadp/openadp/pkg/client"
	"github.com/openadp/openadp/pkg/keygen"
)

const (
	version   = "1.0.0"
	nonceSize = 12 // ChaCha20-Poly1305 nonce size
)

// Metadata represents the metadata stored with encrypted files
type Metadata struct {
	Servers     []string          `json:"servers"`
	Threshold   int               `json:"threshold"`
	AuthEnabled bool              `json:"auth_enabled"`
	Version     string            `json:"version"`
	AuthCodes   AuthCodesMetadata `json:"auth_codes"`
	UserID      string            `json:"user_id"`
}

// AuthCodesMetadata represents authentication codes in metadata
type AuthCodesMetadata struct {
	BaseAuthCode    string            `json:"base_auth_code"`
	ServerAuthCodes map[string]string `json:"server_auth_codes"`
}

func main() {
	var (
		filename    = flag.String("file", "", "File to encrypt (required)")
		password    = flag.String("password", "", "Password for key derivation (will prompt if not provided)")
		serversFlag = flag.String("servers", "", "Comma-separated list of server URLs (optional)")
		serversURL  = flag.String("servers-url", "https://servers.openadp.org", "URL to scrape for server list")
		help        = flag.Bool("help", false, "Show help information")
		showVersion = flag.Bool("version", false, "Show version information")
	)

	flag.Parse()

	if *showVersion {
		fmt.Printf("OpenADP File Encryption Tool v%s\n", version)
		return
	}

	if *help {
		showHelp()
		return
	}

	if *filename == "" {
		fmt.Println("Error: -file is required")
		showHelp()
		os.Exit(1)
	}

	// Check if input file exists
	if _, err := os.Stat(*filename); os.IsNotExist(err) {
		fmt.Printf("Error: Input file '%s' not found.\n", *filename)
		os.Exit(1)
	}

	// Get password (priority: flag > environment > prompt)
	var passwordStr string
	if *password != "" {
		passwordStr = *password
		fmt.Println("⚠️  Warning: Password provided via command line (visible in process list)")
	} else if envPassword := os.Getenv("OPENADP_PASSWORD"); envPassword != "" {
		passwordStr = envPassword
		fmt.Println("Using password from environment variable")
	} else {
		fmt.Print("Enter password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Printf("\nError reading password: %v\n", err)
			os.Exit(1)
		}
		passwordStr = string(passwordBytes)
		fmt.Println() // New line after password input
	}

	// Get server list
	var serverURLs []string
	if *serversFlag != "" {
		serverURLs = strings.Split(*serversFlag, ",")
		for i, url := range serverURLs {
			serverURLs[i] = strings.TrimSpace(url)
		}
	} else {
		serverURLs = client.DiscoverServerURLs(*serversURL)
	}

	if len(serverURLs) == 0 {
		fmt.Println("Error: No servers available")
		os.Exit(1)
	}

	fmt.Printf("🌐 Using %d servers for encryption\n", len(serverURLs))

	// Encrypt the file
	if err := encryptFile(*filename, passwordStr, serverURLs, *serversURL); err != nil {
		fmt.Printf("❌ Encryption failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ File encrypted successfully!")
}

func showHelp() {
	fmt.Print(`OpenADP File Encryption Tool

USAGE:
    openadp-encrypt -file <filename> [OPTIONS]

OPTIONS:
    -file <path>          File to encrypt (required)
    -password <password>  Password for key derivation (will prompt if not provided)
    -servers <urls>       Comma-separated list of server URLs (optional)
    -servers-url <url>    URL to scrape for server list (default: https://servers.openadp.org)
    -version              Show version information
    -help                 Show this help message

EXAMPLES:
    # Encrypt a file using discovered servers
    openadp-encrypt -file document.txt

    # Encrypt using specific servers
    openadp-encrypt -file document.txt -servers "https://server1.com,https://server2.com"

The encrypted file will be saved as <filename>.enc
`)
}

func encryptFile(inputFilename, password string, serverURLs []string, serversURL string) error {
	outputFilename := inputFilename + ".enc"

	// Generate user ID
	userID := generateUserID()
	fmt.Printf("🔐 Generated user ID: %s\n", userID)

	// Generate encryption key using OpenADP with full distributed protocol
	fmt.Println("🔄 Generating encryption key using OpenADP servers...")
	result := keygen.GenerateEncryptionKey(inputFilename, password, userID, 10, 0, serverURLs)
	if result.Error != "" {
		return fmt.Errorf("failed to generate encryption key: %s", result.Error)
	}

	// Extract information from the result
	encKey := result.EncryptionKey
	authCodes := result.AuthCodes
	actualServerURLs := result.ServerURLs
	threshold := result.Threshold

	fmt.Printf("🔑 Generated authentication codes for %d servers\n", len(authCodes.ServerAuthCodes))
	fmt.Printf("🔑 Key generated successfully (UID=%s, DID=%s, BID=%s)\n", userID, getHostname(), "file://"+filepath.Base(inputFilename))

	// Read input file
	plaintext, err := os.ReadFile(inputFilename)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	// Generate random nonce
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Create metadata using the actual results from keygen
	metadata := Metadata{
		Servers:     actualServerURLs,
		Threshold:   threshold,
		AuthEnabled: true,
		Version:     "2.0",
		AuthCodes: AuthCodesMetadata{
			BaseAuthCode:    authCodes.BaseAuthCode,
			ServerAuthCodes: authCodes.ServerAuthCodes,
		},
		UserID: userID,
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %v", err)
	}

	// Encrypt the file using metadata as additional authenticated data
	cipher, err := chacha20poly1305.New(encKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	ciphertext := cipher.Seal(nil, nonce, plaintext, metadataJSON)

	// Write encrypted file: [metadata_length][metadata][nonce][encrypted_data]
	file, err := os.Create(outputFilename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	// Write metadata length (4 bytes, little endian)
	metadataLen := uint32(len(metadataJSON))
	if err := writeUint32LE(file, metadataLen); err != nil {
		return fmt.Errorf("failed to write metadata length: %v", err)
	}

	// Write metadata
	if _, err := file.Write(metadataJSON); err != nil {
		return fmt.Errorf("failed to write metadata: %v", err)
	}

	// Write nonce
	if _, err := file.Write(nonce); err != nil {
		return fmt.Errorf("failed to write nonce: %v", err)
	}

	// Write encrypted data
	if _, err := file.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write encrypted data: %v", err)
	}

	fmt.Printf("📁 Input:  %s (%d bytes)\n", inputFilename, len(plaintext))
	fmt.Printf("📁 Output: %s (%d bytes)\n", outputFilename, 4+len(metadataJSON)+nonceSize+len(ciphertext))
	fmt.Printf("🔐 Encryption: ChaCha20-Poly1305\n")
	fmt.Printf("🌐 Servers: %d servers used\n", len(actualServerURLs))
	fmt.Printf("🎯 Threshold: %d-of-%d recovery\n", threshold, len(actualServerURLs))

	return nil
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func generateUserID() string {
	// Generate a random 32-character hex string
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

func writeUint32LE(w io.Writer, value uint32) error {
	bytes := []byte{
		byte(value),
		byte(value >> 8),
		byte(value >> 16),
		byte(value >> 24),
	}
	_, err := w.Write(bytes)
	return err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
