package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/openadp/openadp/pkg/client"
	"github.com/openadp/openadp/pkg/keygen"
)

const (
	version   = "1.0.0"
	nonceSize = 12 // AES-GCM nonce size
)

// Metadata represents the metadata stored with encrypted files
type Metadata struct {
	Servers   []string `json:"servers"`
	Threshold int      `json:"threshold"`
	Version   string   `json:"version"`
	AuthCode  string   `json:"auth_code"` // Single base auth code (32 bytes hex)
	UserID    string   `json:"user_id"`
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
		userID          = flag.String("user-id", "", "User ID override (will use metadata or prompt if not provided)")
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
	if err := decryptFile(*filename, passwordStr, *userID, overrideServerURLs); err != nil {
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
    -user-id <id>         User ID override (will use metadata or prompt if not provided)
    -servers <urls>       Comma-separated list of server URLs to override metadata servers
    -version              Show version information
    -help                 Show this help message

USER ID HANDLING:
    The tool will use the User ID in this priority order:
    1. Command line flag (-user-id)
    2. User ID stored in the encrypted file metadata
    3. OPENADP_USER_ID environment variable
    4. Interactive prompt

    You only need to specify a User ID if it's missing from the file metadata
    or if you want to override it for some reason.

EXAMPLES:
    # Decrypt a file using servers from metadata
    openadp-decrypt -file document.txt.enc

    # Decrypt using override servers
    openadp-decrypt -file document.txt.enc -servers "https://server1.com,https://server2.com"

    # Override user ID (useful for corrupted metadata)
    openadp-decrypt -file document.txt.enc -user-id "myuserid"

    # Use environment variables
    export OPENADP_PASSWORD="mypassword"
    export OPENADP_USER_ID="myuserid"
    openadp-decrypt -file document.txt.enc

The decrypted file will be saved without the .enc extension
`)
}

func decryptFile(inputFilename, password, userID string, overrideServers []string) error {
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

	// Show servers from metadata
	fmt.Printf("📋 Servers from encrypted file metadata:\n")
	for i, url := range serverURLs {
		fmt.Printf("   %d. %s\n", i+1, url)
	}

	// Use override servers if provided
	var serverInfos []client.ServerInfo
	if len(overrideServers) > 0 {
		fmt.Printf("🔄 Overriding metadata servers with %d custom servers\n", len(overrideServers))
		fmt.Printf("📋 Override servers:\n")
		for i, url := range overrideServers {
			fmt.Printf("   %d. %s\n", i+1, url)
		}

		// Get public keys directly from each override server via GetServerInfo
		fmt.Println("   🔍 Querying override servers for public keys...")
		serverInfos = make([]client.ServerInfo, 0, len(overrideServers))
		for _, url := range overrideServers {
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

		serverURLs = overrideServers
	} else {
		// Get server information from the secure registry (servers.json) instead of querying each server individually
		fmt.Println("   🔍 Fetching server information from secure registry...")

		// Use the default servers.json registry URL
		serversURL := "https://servers.openadp.org"

		// Try to get full server information including public keys from the registry
		registryServerInfos, err := client.GetServers(serversURL)
		if err != nil || len(registryServerInfos) == 0 {
			fmt.Printf("   ⚠️  Failed to fetch from registry: %v\n", err)
			fmt.Println("   🔄 Falling back to hardcoded servers...")
			registryServerInfos = client.GetFallbackServerInfo()
		} else {
			fmt.Printf("   ✅ Successfully fetched %d servers from registry\n", len(registryServerInfos))
		}

		// Match servers from metadata with registry servers to get public keys
		serverInfos = make([]client.ServerInfo, 0, len(serverURLs))
		for _, metadataURL := range serverURLs {
			// Find matching server in registry
			var matchedServer *client.ServerInfo
			for _, registryServer := range registryServerInfos {
				if registryServer.URL == metadataURL {
					matchedServer = &registryServer
					break
				}
			}

			if matchedServer != nil {
				// Use server info from registry (includes public key)
				serverInfos = append(serverInfos, *matchedServer)
				keyStatus := "❌ No public key"
				if matchedServer.PublicKey != "" {
					keyStatus = "🔐 Public key available (from registry)"
				}
				fmt.Printf("   ✅ %s - %s\n", metadataURL, keyStatus)
			} else {
				// Server not found in registry, add without public key as fallback
				fmt.Printf("   ⚠️  Server %s not found in registry, adding without public key\n", metadataURL)
				serverInfos = append(serverInfos, client.ServerInfo{
					URL:       metadataURL,
					PublicKey: "",
					Country:   "Unknown",
				})
			}
		}
	}

	// Check authentication requirements
	if metadata.AuthCode == "" {
		fmt.Println("ℹ️  File was encrypted without authentication (legacy), but using auth for decryption")
	} else {
		fmt.Println("🔒 File was encrypted with authentication (standard)")
	}

	// Extract authentication codes and user ID from metadata
	baseAuthCode, userIDFromMetadata, err := getAuthCodesFromMetadata(metadata)
	if err != nil {
		return fmt.Errorf("failed to extract auth codes: %v", err)
	}

	// Determine final user ID (priority: flag > metadata > environment > prompt)
	var finalUserID string
	if userID != "" {
		finalUserID = userID
		fmt.Printf("🔐 Using user ID from command line: %s\n", finalUserID)
	} else if userIDFromMetadata != "" {
		finalUserID = userIDFromMetadata
		fmt.Printf("🔐 Using user ID from file metadata: %s\n", finalUserID)
	} else if envUserID := os.Getenv("OPENADP_USER_ID"); envUserID != "" {
		finalUserID = envUserID
		fmt.Println("🔐 Using user ID from environment variable")
	} else {
		fmt.Print("Enter your user ID (same as used during encryption): ")
		fmt.Scanln(&finalUserID)
		if strings.TrimSpace(finalUserID) == "" {
			return fmt.Errorf("user ID cannot be empty")
		}
		finalUserID = strings.TrimSpace(finalUserID)
	}

	// Recover encryption key using OpenADP
	fmt.Println("🔄 Recovering encryption key from OpenADP servers...")
	encKey, err := recoverEncryptionKeyWithServerInfo(outputFilename, password, finalUserID, baseAuthCode, serverInfos, metadata.Threshold)
	if err != nil {
		return fmt.Errorf("failed to recover encryption key: %v", err)
	}

	// Decrypt the file using metadata as additional authenticated data
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, metadataJSON)
	if err != nil {
		// AEAD authentication failure should always be fatal
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

	// Show final server list used for recovery
	fmt.Printf("📋 Servers used for decryption:\n")
	for i, url := range serverURLs {
		fmt.Printf("   %d. %s\n", i+1, url)
	}

	return nil
}

func recoverEncryptionKeyWithServerInfo(filename, password, userID string, baseAuthCode string, serverInfos []client.ServerInfo, threshold int) ([]byte, error) {
	// Derive identifiers (same as during encryption)
	uid, did, bid := keygen.DeriveIdentifiers(filename, userID, "")
	fmt.Printf("🔑 Recovering with UID=%s, DID=%s, BID=%s\n", uid, did, bid)

	// Regenerate server auth codes from base auth code
	serverAuthCodes := make(map[string]string)
	for _, serverInfo := range serverInfos {
		// Derive server-specific code using SHA256 (same as GenerateAuthCodes)
		combined := fmt.Sprintf("%s:%s", baseAuthCode, serverInfo.URL)
		hash := sha256.Sum256([]byte(combined))
		serverAuthCodes[serverInfo.URL] = fmt.Sprintf("%x", hash[:])
	}

	// Create AuthCodes structure from metadata
	authCodes := &keygen.AuthCodes{
		BaseAuthCode:    baseAuthCode,
		ServerAuthCodes: serverAuthCodes,
		UserID:          userID,
	}

	// Recover encryption key using the full distributed protocol
	result := keygen.RecoverEncryptionKeyWithServerInfo(filename, password, userID, serverInfos, threshold, authCodes)
	if result.Error != "" {
		return nil, fmt.Errorf("key recovery failed: %s", result.Error)
	}

	fmt.Printf("✅ Key recovered successfully\n")
	return result.EncryptionKey, nil
}

func getAuthCodesFromMetadata(metadata Metadata) (string, string, error) {
	if metadata.AuthCode == "" {
		return "", "", fmt.Errorf("no authentication code found in metadata")
	}

	if metadata.UserID == "" {
		return "", "", fmt.Errorf("no user ID found in metadata")
	}

	return metadata.AuthCode, metadata.UserID, nil
}

func readUint32LE(data []byte) uint32 {
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
}
