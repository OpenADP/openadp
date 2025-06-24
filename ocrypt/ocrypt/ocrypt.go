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
//	metadata, err := ocrypt.Register("alice@example.com", "my_app", secret, "password123", 10)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Later, recover the secret
//	recoveredSecret, remaining, updatedMetadata, err := ocrypt.Recover(metadata, "password123")
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
	"strings"
	"time"

	"github.com/openadp/ocrypt/client"
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
//
// Returns:
//
//	metadata: Opaque blob to store alongside user record
//	error: Any error that occurred during registration
func Register(userID, appID string, longTermSecret []byte, pin string, maxGuesses int) ([]byte, error) {
	return registerWithBID(userID, appID, longTermSecret, pin, maxGuesses, "even")
}

// registerWithBID is the internal implementation that allows specifying backup ID
func registerWithBID(userID, appID string, longTermSecret []byte, pin string, maxGuesses int, backupID string) ([]byte, error) {
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
	serverInfos, err := getServers()
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

	// Create unique filename for this secret
	filename := fmt.Sprintf("file://%s#%s#%s", userID, appID, backupID)

	result := client.GenerateEncryptionKey(filename, pin, userID, maxGuesses, 0, serverInfos)
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
//
// Returns:
//
//	secret: The recovered long-term secret
//	remaining: Number of remaining guess attempts (0 means no limit)
//	updatedMetadata: Updated metadata (may be same as input if refresh failed)
//	error: Any error that occurred during recovery
func Recover(metadataBytes []byte, pin string) ([]byte, int, []byte, error) {
	// Input validation
	if len(metadataBytes) == 0 {
		return nil, 0, nil, &OcryptError{Message: "metadata cannot be empty", Code: "INVALID_INPUT"}
	}
	if pin == "" {
		return nil, 0, nil, &OcryptError{Message: "pin must be a non-empty string", Code: "INVALID_INPUT"}
	}

	// Step 1: Recover with existing backup
	fmt.Println("📋 Step 1: Recovering with existing backup...")
	secret, remaining, err := recoverWithoutRefresh(metadataBytes, pin)
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

	refreshedMetadata, err := registerWithCommitInternal(metadata.UserID, metadata.AppID, secret, pin, metadata.MaxGuesses, newBackupID)
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

// recoverWithoutRefresh recovers a secret without attempting backup refresh
func recoverWithoutRefresh(metadataBytes []byte, pin string) ([]byte, int, error) {
	// Parse metadata
	var metadata Metadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, 0, &OcryptError{Message: fmt.Sprintf("Invalid metadata format: %v", err), Code: "INVALID_METADATA"}
	}

	fmt.Printf("🔍 Recovering secret for user: %s, app: %s, bid: %s\n", metadata.UserID, metadata.AppID, metadata.BackupID)

	// Get server information
	fmt.Println("🌐 Getting server information from registry...")
	allServers, err := getServers()
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
	filename := fmt.Sprintf("file://%s#%s#%s", metadata.UserID, metadata.AppID, metadata.BackupID)

	// Reconstruct auth codes
	authCodes := &client.AuthCodes{
		BaseAuthCode:    metadata.AuthCode,
		ServerAuthCodes: make(map[string]string),
		UserID:          metadata.UserID,
	}

	// Generate server-specific auth codes
	for _, serverURL := range metadata.Servers {
		combined := fmt.Sprintf("%s:%s", metadata.AuthCode, serverURL)
		hash := sha256.Sum256([]byte(combined))
		authCodes.ServerAuthCodes[serverURL] = fmt.Sprintf("%x", hash[:])
	}

	result := client.RecoverEncryptionKeyWithServerInfo(filename, pin, metadata.UserID, serverInfos, metadata.Threshold, authCodes)
	if result.Error != "" {
		return nil, 0, &OcryptError{Message: fmt.Sprintf("OpenADP recovery failed: %s", result.Error), Code: "OPENADP_RECOVERY_FAILED"}
	}

	fmt.Println("✅ Successfully recovered encryption key")

	// Unwrap the long-term secret
	fmt.Println("🔐 Validating PIN by unwrapping secret...")
	secret, err := unwrapSecret(&metadata.WrappedLongTermSecret, result.EncryptionKey)
	if err != nil {
		return nil, 0, &OcryptError{Message: fmt.Sprintf("Invalid PIN or corrupted data: %v", err), Code: "INVALID_PIN"}
	}

	fmt.Println("✅ PIN validation successful - secret unwrapped")

	return secret, 0, nil
}

// registerWithCommitInternal implements two-phase commit for backup refresh
func registerWithCommitInternal(userID, appID string, longTermSecret []byte, pin string, maxGuesses int, newBackupID string) ([]byte, error) {
	// Phase 1: PREPARE - Register new backup
	fmt.Println("📋 Phase 1: PREPARE - Registering new backup...")
	newMetadata, err := registerWithBID(userID, appID, longTermSecret, pin, maxGuesses, newBackupID)
	if err != nil {
		return nil, fmt.Errorf("Phase 1 failed: %v", err)
	}
	fmt.Println("✅ Phase 1 complete: New backup registered")

	// Phase 2: COMMIT - Verify new backup works
	fmt.Println("📋 Phase 2: COMMIT - Verifying new backup...")
	_, _, err = recoverWithoutRefresh(newMetadata, pin)
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
func getServers() ([]client.ServerInfo, error) {
	// Use the default registry URL
	registryURL := "https://servers.openadp.org/api/servers.json"
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
