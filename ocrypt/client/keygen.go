// Package keygen provides high-level functions for generating encryption keys using
// the OpenADP distributed secret sharing system.
//
// This module handles the complete workflow:
// 1. Generate random secrets and split into shares
// 2. Register shares with distributed servers
// 3. Recover secrets from servers during decryption
// 4. Derive encryption keys using cryptographic functions
//
// This replaces traditional password-based key derivation (like Scrypt) with
// a distributed approach that provides better security and recovery properties.
package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/openadp/ocrypt/common"
)

// DeriveIdentifiers derives UID, DID, and BID for OpenADP operations.
//
// Args:
//
//	filename: Name of file being encrypted/decrypted
//	userID: Authenticated user ID (authentication code system - UUID)
//	hostname: Override hostname (auto-detected if empty)
//
// Returns:
//
//	Tuple of (uid, did, bid) identifiers
func DeriveIdentifiers(filename, userID, hostname string) (string, string, string) {
	// Auto-detect hostname if not provided
	if hostname == "" {
		var err error
		hostname, err = os.Hostname()
		if err != nil {
			hostname = "unknown"
		}
	}

	// Phase 4: Use authenticated user ID (UUID) as UID directly
	uid := userID                                            // This is now the authenticated user ID (UUID)
	did := hostname                                          // Device identifier
	bid := fmt.Sprintf("file://%s", filepath.Base(filename)) // Backup identifier for this file

	return uid, did, bid
}

// PasswordToPin converts user password to PIN bytes for cryptographic operations.
//
// Args:
//
//	password: User-provided password string
//
// Returns:
//
//	PIN as bytes suitable for crypto.H()
func PasswordToPin(password string) []byte {
	// Hash password to get consistent bytes, then take first 2 bytes as PIN
	hash := sha256.Sum256([]byte(password))
	return hash[:2] // Use first 2 bytes as PIN
}

// GenerateEncryptionKeyResult represents the result of key generation
type GenerateEncryptionKeyResult struct {
	EncryptionKey []byte
	Error         string
	ServerURLs    []string
	Threshold     int
	AuthCodes     *AuthCodes
}

// GenerateEncryptionKey generates an encryption key using OpenADP distributed secret sharing.
//
// FULL DISTRIBUTED IMPLEMENTATION: This implements the complete OpenADP protocol:
// 1. Derives unique UID/DID/BID from filename and user identity
// 2. Converts password to cryptographic PIN
// 3. Distributes secret shares to OpenADP servers via JSON-RPC
// 4. Uses authentication codes for secure server communication
// 5. Uses threshold cryptography for recovery
func GenerateEncryptionKey(filename, password, userID string, maxGuesses, expiration int,
	serverInfos []ServerInfo) *GenerateEncryptionKeyResult {

	// Input validation
	if filename == "" {
		return &GenerateEncryptionKeyResult{
			Error: "Filename cannot be empty",
		}
	}

	if userID == "" {
		return &GenerateEncryptionKeyResult{
			Error: "User ID cannot be empty",
		}
	}

	if maxGuesses < 0 {
		return &GenerateEncryptionKeyResult{
			Error: "Max guesses cannot be negative",
		}
	}

	// Step 1: Derive identifiers using authenticated user_id
	uid, did, bid := DeriveIdentifiers(filename, userID, "")
	fmt.Printf("OpenADP: UID=%s, DID=%s, BID=%s\n", uid, did, bid)

	// Step 2: Convert password to PIN
	pin := PasswordToPin(password)

	// Step 3: Check if we have servers
	if len(serverInfos) == 0 {
		return &GenerateEncryptionKeyResult{
			Error: "No OpenADP servers available",
		}
	}

	// Step 4: Initialize encrypted clients for each server using public keys from servers.json
	clients := make([]*EncryptedOpenADPClient, 0, len(serverInfos))
	liveServerURLs := make([]string, 0, len(serverInfos))

	for _, serverInfo := range serverInfos {
		var publicKey []byte
		var err error

		// Parse public key if available
		if serverInfo.PublicKey != "" {
			// Handle different key formats
			if strings.HasPrefix(serverInfo.PublicKey, "ed25519:") {
				// Remove ed25519: prefix and decode
				keyB64 := strings.TrimPrefix(serverInfo.PublicKey, "ed25519:")
				publicKey, err = base64.StdEncoding.DecodeString(keyB64)
				if err != nil {
					fmt.Printf("Warning: Invalid public key for server %s: %v\n", serverInfo.URL, err)
					publicKey = nil
				}
			} else {
				// Assume it's already base64
				publicKey, err = base64.StdEncoding.DecodeString(serverInfo.PublicKey)
				if err != nil {
					fmt.Printf("Warning: Invalid public key for server %s: %v\n", serverInfo.URL, err)
					publicKey = nil
				}
			}
		}

		// Create encrypted client with public key from servers.json (secure)
		client := NewEncryptedOpenADPClient(serverInfo.URL, publicKey)
		if err := client.Ping(); err == nil {
			clients = append(clients, client)
			liveServerURLs = append(liveServerURLs, serverInfo.URL)
			if publicKey != nil {
				fmt.Printf("OpenADP: Server %s - Using Noise-NK encryption (key from servers.json)\n", serverInfo.URL)
			} else {
				fmt.Printf("OpenADP: Server %s - No encryption (no public key)\n", serverInfo.URL)
			}
		} else {
			fmt.Printf("Warning: Server %s is not accessible: %v\n", serverInfo.URL, err)
		}
	}

	if len(clients) == 0 {
		return &GenerateEncryptionKeyResult{
			Error: "No live servers available",
		}
	}

	fmt.Printf("OpenADP: Using %d live servers\n", len(clients))

	// Step 5: Generate authentication codes for the live servers
	authCodes := GenerateAuthCodes(liveServerURLs)

	// Step 6: Generate deterministic secret and create point
	// Use deterministic secret derivation for consistent key generation
	secret := common.DeriveSecret([]byte(uid), []byte(did), []byte(bid), pin)

	U := common.H([]byte(uid), []byte(did), []byte(bid), pin)
	S := common.PointMul(secret, U)

	// Step 7: Create shares using secret sharing
	threshold := max(1, min(2, len(clients))) // At least 1, prefer 2 if available
	numShares := len(clients)

	if numShares < threshold {
		return &GenerateEncryptionKeyResult{
			Error: fmt.Sprintf("Need at least %d servers, only %d available", threshold, numShares),
		}
	}

	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		return &GenerateEncryptionKeyResult{
			Error: fmt.Sprintf("Failed to create shares: %v", err),
		}
	}

	fmt.Printf("OpenADP: Created %d shares with threshold %d\n", len(shares), threshold)

	// Step 8: Register shares with servers using authentication codes and encryption
	// Only use encrypted registration for sensitive operations
	version := 1
	registrationErrors := []string{}
	successfulRegistrations := 0

	for i, share := range shares {
		if i >= len(clients) {
			break // More shares than servers
		}

		client := clients[i]
		serverURL := liveServerURLs[i]
		authCode := authCodes.ServerAuthCodes[serverURL]

		// Convert share Y to integer string (server expects integer, not base64)
		yInt := share.Y.String()

		// Use encrypted registration if server has public key, otherwise unencrypted for compatibility
		encrypted := client.HasPublicKey()

		success, err := client.RegisterSecret(
			authCode, uid, did, bid, version, int(share.X.Int64()), yInt, maxGuesses, expiration, encrypted, nil)

		if err != nil {
			registrationErrors = append(registrationErrors, fmt.Sprintf("Server %d (%s): %v", i+1, serverURL, err))
		} else if !success {
			registrationErrors = append(registrationErrors, fmt.Sprintf("Server %d (%s): Registration returned false", i+1, serverURL))
		} else {
			encStatus := "unencrypted"
			if encrypted {
				encStatus = "encrypted"
			}
			fmt.Printf("OpenADP: Registered share %s with server %d (%s) [%s]\n", share.X.String(), i+1, serverURL, encStatus)
			successfulRegistrations++
		}
	}

	if successfulRegistrations == 0 {
		return &GenerateEncryptionKeyResult{
			Error: fmt.Sprintf("Failed to register any shares: %v", registrationErrors),
		}
	}

	// Step 9: Derive encryption key
	encKey := common.DeriveEncKey(S)
	fmt.Println("OpenADP: Successfully generated encryption key")

	return &GenerateEncryptionKeyResult{
		EncryptionKey: encKey,
		ServerURLs:    liveServerURLs,
		Threshold:     threshold,
		AuthCodes:     authCodes, // Include auth codes for metadata
	}
}

// RecoverEncryptionKeyResult represents the result of key recovery
type RecoverEncryptionKeyResult struct {
	EncryptionKey []byte
	Error         string
}

// RecoverEncryptionKeyWithServerInfo recovers an encryption key using OpenADP distributed secret sharing.
//
// FULL DISTRIBUTED IMPLEMENTATION: This implements the complete OpenADP protocol:
// 1. Derives the same UID/DID/BID as during encryption
// 2. Converts password to the same PIN
// 3. Recovers shares from OpenADP servers via JSON-RPC with Noise-NK encryption
// 4. Reconstructs the original secret using threshold cryptography
// 5. Derives the same encryption key
func RecoverEncryptionKeyWithServerInfo(filename, password, userID string, serverInfos []ServerInfo, threshold int, authCodes *AuthCodes) *RecoverEncryptionKeyResult {
	// Input validation
	if filename == "" {
		return &RecoverEncryptionKeyResult{
			Error: "Filename cannot be empty",
		}
	}

	if userID == "" {
		return &RecoverEncryptionKeyResult{
			Error: "User ID cannot be empty",
		}
	}

	if threshold <= 0 {
		return &RecoverEncryptionKeyResult{
			Error: "Threshold must be positive",
		}
	}

	// Step 1: Derive same identifiers as during encryption
	uid, did, bid := DeriveIdentifiers(filename, userID, "")
	fmt.Printf("OpenADP: UID=%s, DID=%s, BID=%s\n", uid, did, bid)

	// Step 2: Convert password to same PIN
	pin := PasswordToPin(password)

	// Step 3: Check if we have servers and auth codes
	if len(serverInfos) == 0 {
		return &RecoverEncryptionKeyResult{
			Error: "No OpenADP servers available",
		}
	}

	if authCodes == nil {
		return &RecoverEncryptionKeyResult{
			Error: "No authentication codes provided",
		}
	}

	// Step 4: Initialize clients for the specific servers, using encryption when public keys are available
	clients := make([]*EncryptedOpenADPClient, 0, len(serverInfos))
	liveServerURLs := make([]string, 0, len(serverInfos))

	for _, serverInfo := range serverInfos {
		var publicKey []byte
		if serverInfo.PublicKey != "" {
			// Parse public key (handles "ed25519:" prefix)
			keyStr := serverInfo.PublicKey
			if strings.HasPrefix(keyStr, "ed25519:") {
				keyStr = strings.TrimPrefix(keyStr, "ed25519:")
			}

			var err error
			publicKey, err = base64.StdEncoding.DecodeString(keyStr)
			if err != nil {
				fmt.Printf("Warning: Invalid public key for server %s: %v\n", serverInfo.URL, err)
				publicKey = nil
			} else {
				fmt.Printf("OpenADP: Using Noise-NK encryption for server %s\n", serverInfo.URL)
			}
		}

		client := NewEncryptedOpenADPClient(serverInfo.URL, publicKey)
		if err := client.Ping(); err == nil {
			clients = append(clients, client)
			liveServerURLs = append(liveServerURLs, serverInfo.URL)
		} else {
			fmt.Printf("Warning: Server %s is not accessible: %v\n", serverInfo.URL, err)
		}
	}

	if len(clients) == 0 {
		return &RecoverEncryptionKeyResult{
			Error: "No servers are accessible",
		}
	}

	fmt.Printf("OpenADP: Using %d live servers\n", len(clients))

	// Step 5: Create cryptographic context (same as encryption)
	U := common.H([]byte(uid), []byte(did), []byte(bid), pin)

	// Generate random r and compute B for recovery protocol
	r, err := rand.Int(rand.Reader, common.Q)
	if err != nil {
		return &RecoverEncryptionKeyResult{
			Error: fmt.Sprintf("Failed to generate random r: %v", err),
		}
	}

	// Compute r^-1 mod q
	rInv := new(big.Int).ModInverse(r, common.Q)
	if rInv == nil {
		return &RecoverEncryptionKeyResult{
			Error: "Failed to compute modular inverse",
		}
	}

	B := common.PointMul(r, U)

	// Convert B to compressed point format (base64 string) - standard format for all servers
	bCompressed := common.PointCompress(B)
	bBase64Format := base64.StdEncoding.EncodeToString(bCompressed)

	// Step 6: Recover shares from servers using authentication codes
	fmt.Println("OpenADP: Recovering shares from servers...")
	recoveredPointShares := make([]*PointShare, 0, len(clients))

	for i, client := range clients {
		serverURL := liveServerURLs[i]
		authCode := authCodes.ServerAuthCodes[serverURL]

		// Get current guess number for this backup from the server
		backups, err := client.ListBackups(uid, false, nil)
		guessNum := 0 // Default to 0 for first guess (0-based indexing)
		if err != nil {
			fmt.Printf("Warning: Could not list backups from server %d: %v\n", i+1, err)
		} else {
			// Find our backup in the list using the complete primary key (UID, DID, BID)
			for _, backupMap := range backups {
				if backupUID, ok := backupMap["uid"].(string); ok && backupUID == uid {
					if backupDID, ok := backupMap["did"].(string); ok && backupDID == did {
						if backupBID, ok := backupMap["bid"].(string); ok && backupBID == bid {
							if numGuesses, ok := backupMap["num_guesses"].(float64); ok {
								// Use current num_guesses as the next guess number (0-based)
								guessNum = int(numGuesses)
							}
							break
						}
					}
				}
			}
		}

		// Try recovery with current guess number, retry once if guess number is wrong
		resultMap, err := client.RecoverSecret(authCode, uid, did, bid, bBase64Format, guessNum, true, nil)

		// If we get a guess number error, try to parse the expected number and retry
		if err != nil && strings.Contains(err.Error(), "expecting guess_num =") {
			// Parse expected guess number from error message like "expecting guess_num = 1"
			errorStr := err.Error()
			if idx := strings.Index(errorStr, "expecting guess_num = "); idx != -1 {
				expectedStr := errorStr[idx+len("expecting guess_num = "):]
				if spaceIdx := strings.Index(expectedStr, " "); spaceIdx != -1 {
					expectedStr = expectedStr[:spaceIdx]
				}
				if expectedGuess, parseErr := strconv.Atoi(expectedStr); parseErr == nil {
					fmt.Printf("Server %d (%s): Retrying with expected guess_num = %d\n", i+1, serverURL, expectedGuess)
					resultMap, err = client.RecoverSecret(authCode, uid, did, bid, bBase64Format, expectedGuess, true, nil)
				}
			}
		}

		if err != nil {
			fmt.Printf("Server %d (%s) recovery failed: %v\n", i+1, serverURL, err)
			continue
		}

		x, ok := resultMap["x"].(float64)
		if !ok {
			fmt.Printf("Server %d (%s): Invalid x field\n", i+1, serverURL)
			continue
		}

		siBBase64, ok := resultMap["si_b"].(string)
		if !ok {
			fmt.Printf("Server %d (%s): Invalid si_b field\n", i+1, serverURL)
			continue
		}

		// Decode si_b from base64
		siBBytes, err := base64.StdEncoding.DecodeString(siBBase64)
		if err != nil {
			fmt.Printf("Server %d (%s): Failed to decode si_b: %v\n", i+1, serverURL, err)
			continue
		}

		// Decompress si_b from the result
		siB4D, err := common.PointDecompress(siBBytes)
		if err != nil {
			fmt.Printf("Server %d (%s): Failed to decompress si_b: %v\n", i+1, serverURL, err)
			continue
		}

		siB := common.Unexpand(siB4D)

		// Create point share from recovered data (si * B point)
		// This matches Python's recover_sb which expects (x, Point2D) pairs
		pointShare := &PointShare{
			X:     big.NewInt(int64(x)),
			Point: siB, // This is si*B point returned by server
		}

		recoveredPointShares = append(recoveredPointShares, pointShare)
		fmt.Printf("OpenADP: Recovered share %d from server %d (%s)\n", int(x), i+1, serverURL)
	}

	if len(recoveredPointShares) < threshold {
		return &RecoverEncryptionKeyResult{
			Error: fmt.Sprintf("Could not recover enough shares (got %d, need at least %d)", len(recoveredPointShares), threshold),
		}
	}

	// Step 7: Reconstruct secret using point-based recovery (like Python recover_sb)
	fmt.Printf("OpenADP: Reconstructing secret from %d point shares...\n", len(recoveredPointShares))

	// Use point-based Lagrange interpolation to recover s*B (like Python recover_sb)
	recoveredSB, err := RecoverPointSecret(recoveredPointShares)
	if err != nil {
		return &RecoverEncryptionKeyResult{
			Error: fmt.Sprintf("Failed to reconstruct point secret: %v", err),
		}
	}

	// Apply r^-1 to get the original secret point: s*U = r^-1 * (s*B)
	// This matches Python: rec_s_point = crypto.point_mul(r_inv, crypto.expand(rec_sb))
	recoveredSB4D := common.Expand(recoveredSB)
	originalSU := common.PointMul(rInv, recoveredSB4D)

	// Step 8: Derive same encryption key
	encKey := common.DeriveEncKey(originalSU)
	fmt.Println("OpenADP: Successfully recovered encryption key")

	return &RecoverEncryptionKeyResult{
		EncryptionKey: encKey,
	}
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// AuthCodes represents authentication codes for OpenADP servers
type AuthCodes struct {
	BaseAuthCode    string            `json:"base_auth_code"`
	ServerAuthCodes map[string]string `json:"server_auth_codes"`
	UserID          string            `json:"user_id"`
}

// GenerateAuthCodes generates authentication codes for OpenADP servers.
//
// This creates a base authentication code (256-bit SHA256 hash) and derives server-specific codes
// for each server URL, matching the expected 64-character hex format.
func GenerateAuthCodes(serverURLs []string) *AuthCodes {
	// Generate base authentication code (256 bits = 32 bytes as hex = 64 chars)
	baseBytes := make([]byte, 32)
	if _, err := rand.Read(baseBytes); err != nil {
		// Fallback to deterministic generation if random fails
		hash := sha256.Sum256([]byte("openadp-fallback"))
		copy(baseBytes, hash[:])
	}
	baseAuthCode := fmt.Sprintf("%x", baseBytes)

	// Generate user ID (UUID-like, 32 chars)
	userBytes := make([]byte, 16)
	if _, err := rand.Read(userBytes); err != nil {
		// Fallback to deterministic generation if random fails
		hash := sha256.Sum256([]byte("openadp-user-" + baseAuthCode))
		copy(userBytes, hash[:16])
	}
	userID := fmt.Sprintf("%x", userBytes)

	// Generate server-specific authentication codes using SHA256
	serverAuthCodes := make(map[string]string)
	for _, serverURL := range serverURLs {
		// Derive server-specific code using SHA256 (matches middleware format)
		combined := fmt.Sprintf("%s:%s", baseAuthCode, serverURL)
		hash := sha256.Sum256([]byte(combined))
		serverAuthCodes[serverURL] = fmt.Sprintf("%x", hash[:])
	}

	return &AuthCodes{
		BaseAuthCode:    baseAuthCode,
		ServerAuthCodes: serverAuthCodes,
		UserID:          userID,
	}
}
