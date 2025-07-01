package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/openadp/openadp/sdk/go/client"
)

const (
	version   = "0.1.3"
	nonceSize = 12 // AES-GCM nonce size
)

// Metadata represents the metadata stored with encrypted files
type Metadata struct {
	Servers   []string `json:"servers"`
	Threshold int      `json:"threshold"`
	Version   string   `json:"version"`
	AuthCode  string   `json:"auth_code"` // Single base auth code (32 bytes hex)
	UserID    string   `json:"user_id"`
	DeviceID  string   `json:"device_id"` // Device identifier for portability
	BackupID  string   `json:"backup_id"` // Backup identifier for portability
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
		userID      = flag.String("user-id", "", "User ID for secret ownership (will prompt if not provided)")
		serversFlag = flag.String("servers", "", "Comma-separated list of server URLs (optional)")
		serversURL  = flag.String("servers-url", "https://servers.openadp.org", "URL to scrape for server list")
		debugMode   = flag.Bool("debug", false, "Enable debug mode (deterministic operations)")
		help        = flag.Bool("help", false, "Show help information")
		showVersion = flag.Bool("version", false, "Show version information")
	)

	// Custom flag parsing to support double-dash arguments
	flag.Usage = func() {
		showHelp()
	}

	// Parse arguments manually to support double-dash
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Convert --arg to -arg for flag package
		if strings.HasPrefix(arg, "--") {
			args[i] = "-" + arg[2:]
		}
	}

	// Replace os.Args with modified args
	oldArgs := os.Args
	os.Args = append([]string{os.Args[0]}, args...)
	defer func() { os.Args = oldArgs }()

	flag.Parse()

	if *showVersion {
		fmt.Printf("OpenADP File Encryption Tool v%s\n", version)
		return
	}

	if *help {
		showHelp()
		return
	}

	// Set debug mode if requested
	if *debugMode {
		fmt.Println("🐛 Debug mode enabled - using deterministic operations")
		client.SetDebugMode(true)
	}

	if *filename == "" {
		fmt.Println("Error: --file is required")
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

	// Get user ID (priority: flag > environment > prompt)
	var userIDStr string
	if *userID != "" {
		userIDStr = *userID
		fmt.Println("⚠️  Warning: User ID provided via command line (visible in process list)")
	} else if envUserID := os.Getenv("OPENADP_USER_ID"); envUserID != "" {
		userIDStr = envUserID
		fmt.Println("Using user ID from environment variable")
	} else {
		fmt.Print("Enter your user ID (this identifies your secrets): ")
		fmt.Scanln(&userIDStr)
		if strings.TrimSpace(userIDStr) == "" {
			fmt.Println("Error: User ID cannot be empty")
			os.Exit(1)
		}
	}

	// Validate user ID
	userIDStr = strings.TrimSpace(userIDStr)
	if len(userIDStr) < 3 {
		fmt.Println("Error: User ID must be at least 3 characters long")
		os.Exit(1)
	}
	if len(userIDStr) > 64 {
		fmt.Println("Error: User ID must be at most 64 characters long")
		os.Exit(1)
	}

	// Get server list
	var serverInfos []client.ServerInfo
	if *serversFlag != "" {
		fmt.Println("📋 Using manually specified servers...")
		serverURLs := strings.Split(*serversFlag, ",")
		for i, url := range serverURLs {
			serverURLs[i] = strings.TrimSpace(url)
		}
		fmt.Printf("   Servers specified: %d\n", len(serverURLs))
		for i, url := range serverURLs {
			fmt.Printf("   %d. %s\n", i+1, url)
		}

		// Get public keys directly from each server via GetServerInfo
		fmt.Println("   🔍 Querying servers for public keys...")
		serverInfos = make([]client.ServerInfo, 0, len(serverURLs))
		for _, url := range serverURLs {
			// Create a basic client to call GetServerInfo
			basicClient := client.NewOpenADPClient(url)
			serverInfo, err := basicClient.GetServerInfo()
			if err != nil {
				fmt.Printf("   ⚠️  Failed to get server info from %s: %v\n", url, err)
				// Add server without public key as fallback
				serverInfos = append(serverInfos, client.ServerInfo{
					URL:       url,
					PublicKey: "",
					Country:   "Unknown",
				})
				continue
			}

			// Extract public key from server info
			publicKey := ""
			if noiseKey, ok := serverInfo["noise_nk_public_key"].(string); ok && noiseKey != "" {
				publicKey = "ed25519:" + noiseKey
			}

			serverInfos = append(serverInfos, client.ServerInfo{
				URL:       url,
				PublicKey: publicKey,
				Country:   "Unknown",
			})

			keyStatus := "❌ No public key"
			if publicKey != "" {
				keyStatus = "🔐 Public key available"
			}
			fmt.Printf("   ✅ %s - %s\n", url, keyStatus)
		}
	} else {
		fmt.Printf("🌐 Discovering servers from registry: %s\n", *serversURL)

		// Try to get full server information including public keys
		var err error
		serverInfos, err = client.GetServers(*serversURL)
		if err != nil || len(serverInfos) == 0 {
			fmt.Printf("   ⚠️  Failed to fetch from registry: %v\n", err)
			fmt.Println("   🔄 Falling back to hardcoded servers...")
			serverInfos = client.GetFallbackServerInfo()
			fmt.Printf("   Fallback servers: %d\n", len(serverInfos))
		} else {
			fmt.Printf("   ✅ Successfully fetched %d servers from registry\n", len(serverInfos))
		}

		fmt.Println("   📋 Server list with public keys:")
		for i, server := range serverInfos {
			keyStatus := "❌ No public key"
			if server.PublicKey != "" {
				keyStatus = "🔐 Public key available"
			}
			fmt.Printf("      %d. %s [%s] - %s\n", i+1, server.URL, server.Country, keyStatus)
		}
	}

	if len(serverInfos) == 0 {
		fmt.Println("❌ Error: No servers available")
		os.Exit(1)
	}

	// Extract URLs for compatibility with existing code
	serverURLs := make([]string, len(serverInfos))
	for i, server := range serverInfos {
		serverURLs[i] = server.URL
	}

	// Encrypt the file
	if err := encryptFile(*filename, passwordStr, userIDStr, serverInfos, *serversURL); err != nil {
		fmt.Printf("❌ Encryption failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ File encrypted successfully!")
}

func showHelp() {
	fmt.Print(`OpenADP File Encryption Tool

USAGE:
    openadp-encrypt --file <filename> [OPTIONS]

OPTIONS:
    --file <path>          File to encrypt (required)
    --password <password>  Password for key derivation (will prompt if not provided)
    --user-id <id>         User ID for secret ownership (will prompt if not provided)
    --servers <urls>       Comma-separated list of server URLs (optional)
    --servers-url <url>    URL to scrape for server list (default: https://servers.openadp.org)
    --debug                Enable debug mode (deterministic operations)
    --version              Show version information
    --help                 Show this help message

USER ID SECURITY:
    Your User ID uniquely identifies your secrets on the servers. It is critical that:
    • You use the same User ID for all your files
    • You keep your User ID private (anyone with it can overwrite your secrets)
    • You choose a unique User ID that others won't guess
    • You remember your User ID for future decryption

    You can set the OPENADP_USER_ID environment variable to avoid typing it repeatedly.

SERVER DISCOVERY:
    By default, the tool fetches the server list from servers.openadp.org/api/servers.json
    If the registry is unavailable, it falls back to hardcoded servers.
    Use -servers to specify your own server list and skip discovery.

EXAMPLES:
    # Encrypt a file using discovered servers (fetches from servers.openadp.org)
    openadp-encrypt --file document.txt

    # Encrypt using specific servers (skip discovery)
    openadp-encrypt --file document.txt --servers "https://server1.com,https://server2.com"

    # Use a different server registry
    openadp-encrypt --file document.txt --servers-url "https://my-registry.com"

    # Use environment variables to avoid prompts
    export OPENADP_PASSWORD="mypassword"
    export OPENADP_USER_ID="myuserid"
    openadp-encrypt --file document.txt

    # Enable debug mode for deterministic testing
    openadp-encrypt --file document.txt --debug

The encrypted file will be saved as <filename>.enc
`)
}

func encryptFile(inputFilename, password, userID string, serverInfos []client.ServerInfo, serversURL string) error {
	outputFilename := inputFilename + ".enc"

	// Create Identity struct for the new API
	identity := &client.Identity{
		UID: userID,
		DID: getHostname(),                            // Use hostname as device ID
		BID: "file://" + filepath.Base(inputFilename), // Use file path as backup ID
	}

	// Generate encryption key using OpenADP with full distributed protocol
	fmt.Println("🔄 Generating encryption key using OpenADP servers...")
	result := client.GenerateEncryptionKey(identity, password, 10, 0, serverInfos)
	if result.Error != "" {
		return fmt.Errorf("failed to generate encryption key: %s", result.Error)
	}

	// Extract information from the result
	encKey := result.EncryptionKey
	authCodes := result.AuthCodes
	actualServerURLs := result.ServerURLs
	threshold := result.Threshold

	fmt.Printf("🔑 Generated authentication codes for %d servers\n", len(authCodes.ServerAuthCodes))
	fmt.Printf("🔑 Key generated successfully (UID=%s, DID=%s, BID=%s)\n", identity.UID, identity.DID, identity.BID)

	// Show which servers were actually used for key generation
	if len(actualServerURLs) > 0 && len(actualServerURLs) != len(serverInfos) {
		fmt.Printf("📋 Servers actually used for key generation (%d):\n", len(actualServerURLs))
		for i, url := range actualServerURLs {
			fmt.Printf("   %d. %s\n", i+1, url)
		}
	}

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
		Servers:   actualServerURLs,
		Threshold: threshold,
		Version:   "1.0",
		AuthCode:  authCodes.BaseAuthCode,
		UserID:    userID,
		DeviceID:  identity.DID, // Store device_id for portability
		BackupID:  identity.BID, // Store backup_id for portability
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %v", err)
	}

	// Encrypt the file using metadata as additional authenticated data
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, metadataJSON)

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
	fmt.Printf("🔐 Encryption: AES-GCM\n")
	fmt.Printf("🌐 Servers: %d servers used\n", len(actualServerURLs))
	fmt.Printf("🎯 Threshold: %d-of-%d recovery\n", threshold, len(actualServerURLs))

	// Show final server list stored in metadata
	fmt.Printf("📋 Servers stored in encrypted file metadata:\n")
	for i, url := range actualServerURLs {
		fmt.Printf("   %d. %s\n", i+1, url)
	}

	return nil
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
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
