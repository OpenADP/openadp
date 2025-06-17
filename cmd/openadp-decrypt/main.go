package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"

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
		filename        = flag.String("file", "", "File to decrypt (required)")
		password        = flag.String("password", "", "Password for key derivation (will prompt if not provided)")
		overrideServers = flag.String("servers", "", "Comma-separated list of server URLs to override metadata servers")
		help            = flag.Bool("help", false, "Show help information")
		showVersion     = flag.Bool("version", false, "Show version information")
	)

	flag.Parse()

	if *showVersion {
		fmt.Printf("OpenADP File Decryption Tool v%s\n", version)
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

	// Parse override servers if provided
	var overrideServerURLs []string
	if *overrideServers != "" {
		overrideServerURLs = strings.Split(*overrideServers, ",")
		for i, url := range overrideServerURLs {
			overrideServerURLs[i] = strings.TrimSpace(url)
		}
	}

	// Decrypt the file
	if err := decryptFile(*filename, passwordStr, overrideServerURLs); err != nil {
		fmt.Printf("❌ Decryption failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ File decrypted successfully!")
}

func showHelp() {
	fmt.Print(`OpenADP File Decryption Tool

USAGE:
    openadp-decrypt -file <filename> [OPTIONS]

OPTIONS:
    -file <path>          File to decrypt (required)
    -password <password>  Password for key derivation (will prompt if not provided)
    -servers <urls>       Comma-separated list of server URLs to override metadata servers
    -version              Show version information
    -help                 Show this help message

EXAMPLES:
    # Decrypt a file using servers from metadata
    openadp-decrypt -file document.txt.enc

    # Decrypt using override servers
    openadp-decrypt -file document.txt.enc -servers "https://server1.com,https://server2.com"

    # Decrypt with password flag (not recommended for security)
    openadp-decrypt -file document.txt.enc -password "mypassword"

The decrypted file will be saved without the .enc extension
`)
}

func decryptFile(inputFilename, password string, overrideServers []string) error {
	// Determine output filename
	var outputFilename string
	if strings.HasSuffix(inputFilename, ".enc") {
		outputFilename = strings.TrimSuffix(inputFilename, ".enc")
	} else {
		outputFilename = inputFilename + ".dec"
		fmt.Printf("Warning: Input file doesn't end with .enc, using '%s' for output\n", outputFilename)
	}

	// Read the encrypted file
	fileData, err := os.ReadFile(inputFilename)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	// Validate file size
	minSize := 4 + 1 + nonceSize + 1 // metadata_length + minimal_metadata + nonce + minimal_ciphertext
	if len(fileData) < minSize {
		return fmt.Errorf("file is too small to be a valid encrypted file (expected at least %d bytes, got %d)", minSize, len(fileData))
	}

	// Extract metadata length (first 4 bytes, little endian)
	metadataLength := readUint32LE(fileData[:4])

	// Validate metadata length
	if int(metadataLength) > len(fileData)-4-nonceSize {
		return fmt.Errorf("invalid metadata length %d", metadataLength)
	}

	// Extract components: [metadata_length][metadata][nonce][encrypted_data]
	metadataStart := 4
	metadataEnd := metadataStart + int(metadataLength)
	nonceStart := metadataEnd
	nonceEnd := nonceStart + nonceSize

	metadataJSON := fileData[metadataStart:metadataEnd]
	nonce := fileData[nonceStart:nonceEnd]
	ciphertext := fileData[nonceEnd:]

	// Parse metadata
	var metadata Metadata
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		return fmt.Errorf("failed to parse metadata: %v", err)
	}

	serverURLs := metadata.Servers
	if len(serverURLs) == 0 {
		return fmt.Errorf("no server URLs found in metadata")
	}

	fmt.Printf("Found metadata with %d servers, threshold %d\n", len(serverURLs), metadata.Threshold)
	fmt.Printf("File version: %s\n", metadata.Version)

	// Use override servers if provided
	if len(overrideServers) > 0 {
		fmt.Printf("Overriding metadata servers with %d custom servers\n", len(overrideServers))
		serverURLs = overrideServers
	}

	// Check authentication requirements
	if metadata.AuthEnabled {
		fmt.Println("🔒 File was encrypted with authentication (standard)")
	} else {
		fmt.Println("ℹ️  File was encrypted without authentication (legacy), but using auth for decryption")
	}

	// Extract authentication codes and user ID from metadata
	serverAuthCodes, _, userID, err := getAuthCodesFromMetadata(metadata)
	if err != nil {
		return fmt.Errorf("failed to extract auth codes: %v", err)
	}

	// Recover encryption key using OpenADP
	fmt.Println("🔄 Recovering encryption key from OpenADP servers...")
	encKey, err := recoverEncryptionKey(outputFilename, password, userID, serverAuthCodes, serverURLs, metadata.Threshold)
	if err != nil {
		return fmt.Errorf("failed to recover encryption key: %v", err)
	}

	// Decrypt the file using metadata as additional authenticated data
	cipher, err := chacha20poly1305.New(encKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	plaintext, err := cipher.Open(nil, nonce, ciphertext, metadataJSON)
	if err != nil {
		return fmt.Errorf("decryption failed: %v (wrong password or corrupted file)", err)
	}

	// Write the decrypted file
	if err := os.WriteFile(outputFilename, plaintext, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	fmt.Printf("📁 Input:  %s (%d bytes)\n", inputFilename, len(fileData))
	fmt.Printf("📁 Output: %s (%d bytes)\n", outputFilename, len(plaintext))
	fmt.Printf("🌐 Servers: %d servers used\n", len(serverURLs))
	fmt.Printf("🎯 Threshold: %d-of-%d recovery\n", metadata.Threshold, len(serverURLs))
	fmt.Printf("🔐 Authentication: Enabled (Authentication Codes)\n")

	return nil
}

func recoverEncryptionKey(filename, password, userID string, serverAuthCodes map[string]string, serverURLs []string, threshold int) ([]byte, error) {
	// Derive identifiers (same as during encryption)
	uid, did, bid := keygen.DeriveIdentifiers(filename, userID, "")
	fmt.Printf("🔑 Recovering with UID=%s, DID=%s, BID=%s\n", uid, did, bid)

	// Create AuthCodes structure from metadata
	authCodes := &keygen.AuthCodes{
		BaseAuthCode:    "", // Not needed for recovery
		ServerAuthCodes: serverAuthCodes,
		UserID:          userID,
	}

	// Recover encryption key using the full distributed protocol
	result := keygen.RecoverEncryptionKey(filename, password, userID, serverURLs, threshold, authCodes)
	if result.Error != "" {
		return nil, fmt.Errorf("key recovery failed: %s", result.Error)
	}

	fmt.Printf("✅ Key recovered successfully\n")
	return result.EncryptionKey, nil
}

func getAuthCodesFromMetadata(metadata Metadata) (map[string]string, string, string, error) {
	if metadata.AuthCodes.BaseAuthCode == "" {
		return nil, "", "", fmt.Errorf("no authentication codes found in metadata")
	}

	if metadata.UserID == "" {
		return nil, "", "", fmt.Errorf("no user ID found in metadata")
	}

	return metadata.AuthCodes.ServerAuthCodes, metadata.AuthCodes.BaseAuthCode, metadata.UserID, nil
}

func readUint32LE(data []byte) uint32 {
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
}
