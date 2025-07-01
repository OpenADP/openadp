// Package ocrypt provides a simple 2-function API for distributed password hashing
// using OpenADP's Oblivious Pseudo Random Function (OPRF) cryptography.
//
// This package replaces traditional password hashing functions like bcrypt, scrypt,
// Argon2, and PBKDF2 with distributed threshold cryptography that is resistant to
// nation-state attacks and provides automatic backup refresh.
//
// Key Features:
// - Nation-state resistant security through distributed servers
// - Built-in guess limiting across all servers
// - Automatic backup refresh with crash safety
// - Two-phase commit for reliable backup updates
// - Generic secret protection (not just passwords)
//
// Example Usage:
//
//	// Register a secret
//	metadata, err := ocrypt.Register("alice@example.com", "my_app", secret, "password123", 10, "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Later, recover the secret
//	recoveredSecret, remaining, updatedMetadata, err := ocrypt.Recover(metadata, "password123", "")
//	if err != nil {
//	    log.Fatal(err)
//	}
package ocrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openadp/openadp/sdk/go/client"
	"github.com/openadp/openadp/sdk/go/debug"
)

// OcryptError represents an error in Ocrypt operations
type OcryptError struct {
	Message string
	Code    string
}

func (e *OcryptError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("Ocrypt %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("Ocrypt error: %s", e.Message)
}

// SetDebugMode enables or disables debug mode for deterministic operations.
// When enabled, all cryptographic operations become deterministic for testing.
func SetDebugMode(enabled bool) {
	debug.SetDebugMode(enabled)
}

// Metadata represents the Ocrypt metadata structure
type Metadata struct {
	Servers               []string      `json:"servers"`
	Threshold             int           `json:"threshold"`
	Version               string        `json:"version"`
	AuthCode              string        `json:"auth_code"`
	UserID                string        `json:"user_id"`
	WrappedLongTermSecret WrappedSecret `json:"wrapped_long_term_secret"`
	BackupID              string        `json:"backup_id"`
	AppID                 string        `json:"app_id"`
	MaxGuesses            int           `json:"max_guesses"`
	OcryptVersion         string        `json:"ocrypt_version"`
}

// WrappedSecret represents an AES-GCM encrypted secret
type WrappedSecret struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

// Register protects a long-term secret using OpenADP distributed cryptography.
//
// This function provides a simple interface that replaces traditional password hashing
// functions like bcrypt, scrypt, Argon2, and PBKDF2 with distributed threshold cryptography.
//
// Args:
//
//	userID: Unique identifier for the user (e.g., email, username)
//	appID: Application identifier to namespace secrets per app
//	longTermSecret: User-provided secret to protect (any byte sequence)
//	pin: Password/PIN that will unlock the secret
//	maxGuesses: Maximum wrong PIN attempts before lockout (default: 10)
//	serversURL: Custom URL for server registry (empty string uses default: "https://servers.openadp.org/api/servers.json")
//
// Returns:
//
//	metadata: Opaque blob to store alongside user record
//	error: Any error that occurred during registration
func Register(userID, appID string, longTermSecret []byte, pin string, maxGuesses int, serversURL string) ([]byte, error) {
	return registerWithBID(userID, appID, longTermSecret, pin, maxGuesses, "even", serversURL)
}

// registerWithBID is the internal implementation that allows specifying backup ID
func registerWithBID(userID, appID string, longTermSecret []byte, pin string, maxGuesses int, backupID string, serversURL string) ([]byte, error) {
	// Input validation
	if userID == "" {
		return nil, &OcryptError{Message: "user_id must be a non-empty string", Code: "INVALID_INPUT"}
	}
	if appID == "" {
		return nil, &OcryptError{Message: "app_id must be a non-empty string", Code: "INVALID_INPUT"}
	}
	if len(longTermSecret) == 0 {
		return nil, &OcryptError{Message: "long_term_secret cannot be empty", Code: "INVALID_INPUT"}
	}
	if pin == "" {
		return nil, &OcryptError{Message: "pin must be a non-empty string", Code: "INVALID_INPUT"}
	}
	if maxGuesses <= 0 {
		maxGuesses = 10 // Default value
	}

	fmt.Printf("🔐 Protecting secret for user: %s\n", userID)
	fmt.Printf("📱 Application: %s\n", appID)
	fmt.Printf("🔑 Secret length: %d bytes\n", len(longTermSecret))

	// Step 1: Discover OpenADP servers
	fmt.Println("🌐 Discovering OpenADP servers...")
	serverInfos, err := getServers(serversURL)
	if err != nil {
		return nil, &OcryptError{Message: fmt.Sprintf("Server discovery failed: %v", err), Code: "SERVER_DISCOVERY_FAILED"}
	}

	if len(serverInfos) == 0 {
		return nil, &OcryptError{Message: "No OpenADP servers available", Code: "NO_SERVERS"}
	}

	fmt.Printf("   ✅ Successfully fetched %d servers from registry\n", len(serverInfos))

	// Step 2: Generate encryption key using OpenADP
	fmt.Printf("🔄 Using backup ID: %s\n", backupID)
	fmt.Println("🔑 Generating encryption key using OpenADP servers...")

	// Create Identity for Ocrypt API: UID=userID, DID=appID, BID=backupID
	// This allows same secret recovery across devices for the same app
	identity := &client.Identity{
		UID: userID,   // User identifier
		DID: appID,    // Application identifier (serves as device ID for cross-device compatibility)
		BID: backupID, // Backup identifier (managed by Ocrypt: "even"/"odd")
	}

	result := client.GenerateEncryptionKey(identity, pin, maxGuesses, 0, serverInfos)
	if result.Error != "" {
		return nil, &OcryptError{Message: fmt.Sprintf("OpenADP registration failed: %s", result.Error), Code: "OPENADP_FAILED"}
	}

	fmt.Printf("✅ Generated encryption key with %d servers\n", len(result.ServerURLs))

	// Step 3: Wrap the long-term secret with AES-256-GCM
	fmt.Println("🔐 Wrapping long-term secret...")
	wrappedSecret, err := wrapSecret(longTermSecret, result.EncryptionKey)
	if err != nil {
		return nil, &OcryptError{Message: fmt.Sprintf("Secret wrapping failed: %v", err), Code: "WRAPPING_FAILED"}
	}

	// Step 4: Create metadata
	metadata := &Metadata{
		Servers:               result.ServerURLs,
		Threshold:             result.Threshold,
		Version:               "1.0",
		AuthCode:              result.AuthCodes.BaseAuthCode,
		UserID:                userID,
		WrappedLongTermSecret: *wrappedSecret,
		BackupID:              backupID,
		AppID:                 appID,
		MaxGuesses:            maxGuesses,
		OcryptVersion:         "1.0",
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, &OcryptError{Message: fmt.Sprintf("Metadata serialization failed: %v", err), Code: "SERIALIZATION_FAILED"}
	}

	fmt.Printf("📦 Created metadata (%d bytes)\n", len(metadataBytes))
	fmt.Printf("🎯 Threshold: %d-of-%d recovery\n", result.Threshold, len(result.ServerURLs))

	return metadataBytes, nil
}

// Recover recovers a secret from Ocrypt metadata with automatic backup refresh.
//
// This function implements a two-phase commit pattern for safe backup refresh:
// 1. Recovers the secret using existing backup
// 2. Attempts to refresh backup with opposite backup ID
// 3. Returns updated metadata if refresh succeeds, original if it fails
//
// Args:
//
//	metadata: Metadata blob from Register()
//	pin: Password/PIN to unlock the secret
//	serversURL: Custom URL for server registry (empty string uses default: "https://servers.openadp.org/api/servers.json")
//
// Returns:
//
//	secret: The recovered long-term secret
//	remaining: Number of remaining guess attempts (0 means no limit)
//	updatedMetadata: Updated metadata (may be same as input if refresh failed)
//	error: Any error that occurred during recovery
func Recover(metadataBytes []byte, pin string, serversURL string) ([]byte, int, []byte, error) {
	// Input validation
	if len(metadataBytes) == 0 {
		return nil, 0, nil, &OcryptError{Message: "metadata cannot be empty", Code: "INVALID_INPUT"}
	}
	if pin == "" {
		return nil, 0, nil, &OcryptError{Message: "pin must be a non-empty string", Code: "INVALID_INPUT"}
	}

	// Step 1: Recover with existing backup
	fmt.Println("📋 Step 1: Recovering with existing backup...")
	secret, remaining, err := recoverWithoutRefresh(metadataBytes, pin, serversURL)
	if err != nil {
		return nil, 0, nil, err
	}

	// Step 2: Attempt backup refresh using two-phase commit
	var updatedMetadata []byte

	// Parse metadata to get current backup ID
	var metadata Metadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		// If we can't parse metadata, just return what we have
		return secret, remaining, metadataBytes, nil
	}

	fmt.Printf("📋 Step 2: Attempting backup refresh for BID: %s\n", metadata.BackupID)

	newBackupID := generateNextBackupID(metadata.BackupID)
	fmt.Printf("🔄 Two-phase commit: %s → %s\n", metadata.BackupID, newBackupID)

	refreshedMetadata, err := registerWithCommitInternal(metadata.UserID, metadata.AppID, secret, pin, metadata.MaxGuesses, newBackupID, serversURL)
	if err != nil {
		fmt.Printf("⚠️  Backup refresh failed: %v\n", err)
		fmt.Println("✅ Recovery still successful with existing backup")
		updatedMetadata = metadataBytes // Use original metadata
	} else {
		fmt.Printf("✅ Backup refresh successful: %s → %s\n", metadata.BackupID, newBackupID)
		updatedMetadata = refreshedMetadata
	}

	return secret, remaining, updatedMetadata, nil
}

// RecoverAndReregisterResult represents the result of recovery + re-registration
type RecoverAndReregisterResult struct {
	Secret      []byte // The recovered long-term secret
	NewMetadata []byte // Fresh metadata from re-registration
}

// RecoverAndReregister recovers a secret and re-registers it with fresh cryptographic material.
//
// This provides a cleaner API that combines recovery and re-registration in one call:
// 1. Recovers the secret from old metadata
// 2. Re-registers that secret with fresh cryptographic material
// 3. Returns both the secret (for display) and new metadata (for saving)
//
// Args:
//
//	oldMetadata: Metadata blob from previous registration
//	pin: Password/PIN to unlock the secret
//	serversURL: Custom URL for server registry (empty string uses default: "https://servers.openadp.org/api/servers.json")
//
// Returns:
//
//	RecoverAndReregisterResult containing the secret and fresh metadata
//	error: Any error that occurred during recovery or re-registration
func RecoverAndReregister(oldMetadata []byte, pin string, serversURL string) (*RecoverAndReregisterResult, error) {
	// Use default servers URL if none provided
	if serversURL == "" {
		serversURL = "https://servers.openadp.org/api/servers.json"
	}
	// Step 1: Recover the secret from old metadata
	fmt.Println("🔍 Step 1: Recovering secret from old metadata...")
	secret, _, err := recoverWithoutRefresh(oldMetadata, pin, serversURL)
	if err != nil {
		return nil, fmt.Errorf("recovery failed: %v", err)
	}

	// Parse old metadata to extract registration parameters
	var oldMetadataStruct Metadata
	if err := json.Unmarshal(oldMetadata, &oldMetadataStruct); err != nil {
		return nil, &OcryptError{Message: fmt.Sprintf("Invalid metadata format: %v", err), Code: "INVALID_METADATA"}
	}

	fmt.Println("✅ Secret recovered successfully")

	// Step 2: Re-register the recovered secret with fresh cryptographic material
	fmt.Println("🔄 Step 2: Re-registering with fresh cryptographic material...")

	// Generate next backup ID to ensure alternation (critical for prepare/commit safety)
	newBackupID := generateNextBackupID(oldMetadataStruct.BackupID)
	fmt.Printf("🔄 Backup ID alternation: %s → %s\n", oldMetadataStruct.BackupID, newBackupID)

	newMetadata, err := registerWithBID(
		oldMetadataStruct.UserID,
		oldMetadataStruct.AppID,
		secret,
		pin,
		oldMetadataStruct.MaxGuesses,
		newBackupID,
		serversURL,
	)
	if err != nil {
		return nil, fmt.Errorf("re-registration failed: %v", err)
	}

	fmt.Println("✅ Re-registration completed with fresh metadata")

	return &RecoverAndReregisterResult{
		Secret:      secret,
		NewMetadata: newMetadata,
	}, nil
}

// recoverWithoutRefresh recovers a secret without attempting backup refresh
func recoverWithoutRefresh(metadataBytes []byte, pin string, serversURL string) ([]byte, int, error) {
	// Parse metadata
	var metadata Metadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, 0, &OcryptError{Message: fmt.Sprintf("Invalid metadata format: %v", err), Code: "INVALID_METADATA"}
	}

	fmt.Printf("🔍 Recovering secret for user: %s, app: %s, bid: %s\n", metadata.UserID, metadata.AppID, metadata.BackupID)

	// Get server information
	fmt.Println("🌐 Getting server information from registry...")
	allServers, err := getServers(serversURL)
	if err != nil {
		return nil, 0, &OcryptError{Message: fmt.Sprintf("Server discovery failed: %v", err), Code: "SERVER_DISCOVERY_FAILED"}
	}

	// Match servers from metadata with registry
	var serverInfos []client.ServerInfo
	for _, serverURL := range metadata.Servers {
		for _, serverInfo := range allServers {
			if serverInfo.URL == serverURL {
				serverInfos = append(serverInfos, serverInfo)
				fmt.Printf("   ✅ %s - matched in registry\n", serverURL)
				break
			}
		}
	}

	if len(serverInfos) == 0 {
		return nil, 0, &OcryptError{Message: "No servers from metadata found in registry", Code: "SERVERS_NOT_FOUND"}
	}

	// Recover encryption key from OpenADP
	fmt.Println("🔑 Recovering encryption key from OpenADP servers...")

	// Create Identity for Ocrypt API: UID=userID, DID=appID, BID=backupID
	// This matches the identity used during registration
	identity := &client.Identity{
		UID: metadata.UserID,   // User identifier
		DID: metadata.AppID,    // Application identifier (serves as device ID for cross-device compatibility)
		BID: metadata.BackupID, // Backup identifier (managed by Ocrypt: "even"/"odd")
	}

	// Reconstruct auth codes
	authCodes := &client.AuthCodes{
		BaseAuthCode:    metadata.AuthCode,
		ServerAuthCodes: make(map[string]string),
	}

	// Generate server-specific auth codes
	for _, serverURL := range metadata.Servers {
		combined := fmt.Sprintf("%s:%s", metadata.AuthCode, serverURL)
		hash := sha256.Sum256([]byte(combined))
		authCodes.ServerAuthCodes[serverURL] = fmt.Sprintf("%x", hash[:])
	}

	result := client.RecoverEncryptionKeyWithServerInfo(identity, pin, serverInfos, metadata.Threshold, authCodes)
	if result.Error != "" {
		// Check if the error contains guess information and display it
		if strings.Contains(result.Error, "num_guesses") || strings.Contains(result.Error, "max_guesses") {
			fmt.Fprintf(os.Stderr, "❌ %s\n", result.Error)
		}
		return nil, 0, &OcryptError{Message: fmt.Sprintf("OpenADP recovery failed: %s", result.Error), Code: "OPENADP_RECOVERY_FAILED"}
	}

	fmt.Println("✅ Successfully recovered encryption key")

	// Unwrap the long-term secret
	fmt.Println("🔐 Validating PIN by unwrapping secret...")
	secret, err := unwrapSecret(&metadata.WrappedLongTermSecret, result.EncryptionKey)
	if err != nil {
		// Invalid PIN - show helpful message with actual remaining guesses
		if result.MaxGuesses > 0 && result.NumGuesses > 0 {
			remaining := result.MaxGuesses - result.NumGuesses
			if remaining > 0 {
				fmt.Fprintf(os.Stderr, "❌ Invalid PIN! You have %d guesses remaining.\n", remaining)
			} else {
				fmt.Fprintf(os.Stderr, "❌ Invalid PIN! No more guesses remaining - account may be locked.\n")
			}
		} else {
			fmt.Fprintf(os.Stderr, "❌ Invalid PIN! Check your password and try again.\n")
		}
		return nil, 0, &OcryptError{Message: fmt.Sprintf("Invalid PIN or corrupted data: %v", err), Code: "INVALID_PIN"}
	}

	fmt.Println("✅ PIN validation successful - secret unwrapped")

	// Calculate and return actual remaining guesses
	remaining := 0
	if result.MaxGuesses > 0 && result.NumGuesses >= 0 {
		remaining = result.MaxGuesses - result.NumGuesses
	}

	return secret, remaining, nil
}

// registerWithCommitInternal implements two-phase commit for backup refresh
func registerWithCommitInternal(userID, appID string, longTermSecret []byte, pin string, maxGuesses int, newBackupID string, serversURL string) ([]byte, error) {
	// Phase 1: PREPARE - Register new backup
	fmt.Println("📋 Phase 1: PREPARE - Registering new backup...")
	newMetadata, err := registerWithBID(userID, appID, longTermSecret, pin, maxGuesses, newBackupID, serversURL)
	if err != nil {
		return nil, fmt.Errorf("Phase 1 failed: %v", err)
	}
	fmt.Println("✅ Phase 1 complete: New backup registered")

	// Phase 2: COMMIT - Verify new backup works
	fmt.Println("📋 Phase 2: COMMIT - Verifying new backup...")
	_, _, err = recoverWithoutRefresh(newMetadata, pin, serversURL)
	if err != nil {
		return nil, fmt.Errorf("Phase 2 failed: %v", err)
	}
	fmt.Println("✅ Phase 2 complete: New backup verified and committed")

	return newMetadata, nil
}

// generateNextBackupID generates the next backup ID using smart strategies
func generateNextBackupID(currentBackupID string) string {
	switch currentBackupID {
	case "even":
		return "odd"
	case "odd":
		return "even"
	default:
		// For version numbers like v1, v2, etc.
		if strings.HasPrefix(currentBackupID, "v") && len(currentBackupID) > 1 {
			// Try to parse version number
			versionStr := currentBackupID[1:]
			if version := parseInt(versionStr); version > 0 {
				return fmt.Sprintf("v%d", version+1)
			}
		}

		// Fallback: append timestamp
		timestamp := time.Now().Unix()
		return fmt.Sprintf("%s_v%d", currentBackupID, timestamp)
	}
}

// wrapSecret encrypts a secret using AES-256-GCM
func wrapSecret(secret, key []byte) (*WrappedSecret, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, secret, nil)

	// Split ciphertext and tag (GCM appends tag to ciphertext)
	tagSize := gcm.Overhead()
	if len(ciphertext) < tagSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	actualCiphertext := ciphertext[:len(ciphertext)-tagSize]
	tag := ciphertext[len(ciphertext)-tagSize:]

	return &WrappedSecret{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(actualCiphertext),
		Tag:        base64.StdEncoding.EncodeToString(tag),
	}, nil
}

// unwrapSecret decrypts a secret using AES-256-GCM
func unwrapSecret(wrapped *WrappedSecret, key []byte) ([]byte, error) {
	nonce, err := base64.StdEncoding.DecodeString(wrapped.Nonce)
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(wrapped.Ciphertext)
	if err != nil {
		return nil, err
	}

	tag, err := base64.StdEncoding.DecodeString(wrapped.Tag)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Reconstruct full ciphertext with tag
	fullCiphertext := append(ciphertext, tag...)

	plaintext, err := gcm.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("MAC check failed")
	}

	return plaintext, nil
}

// getServers discovers OpenADP servers from the registry
func getServers(serversURL string) ([]client.ServerInfo, error) {
	// Use the provided URL, or fall back to default registry URL
	registryURL := "https://servers.openadp.org/api/servers.json"
	if serversURL != "" {
		registryURL = serversURL
	}
	return client.GetServers(registryURL)
}

// parseInt parses a string to int, returns 0 if invalid
func parseInt(s string) int {
	result := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			result = result*10 + int(r-'0')
		} else {
			return 0
		}
	}
	return result
}
