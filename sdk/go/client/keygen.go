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
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/openadp/openadp/sdk/go/common"
	"github.com/openadp/openadp/sdk/go/debug"
)

// SetDebugMode enables or disables debug mode for deterministic operations.
// This function provides access to debug mode for tools that use the client package directly.
func SetDebugMode(enabled bool) {
	debug.SetDebugMode(enabled)
}

// Identity represents the primary key tuple for secret shares stored on servers
type Identity struct {
	UID string `json:"uid"` // User ID - uniquely identifies the user
	DID string `json:"did"` // Device ID - identifies the device/hostname
	BID string `json:"bid"` // Backup ID - identifies the specific backup/file
}

// String returns a human-readable representation of the identity
func (id *Identity) String() string {
	return fmt.Sprintf("UID=%s, DID=%s, BID=%s", id.UID, id.DID, id.BID)
}

// DeriveIdentifiers derives UID, DID, and BID from filename and userID for backward compatibility
func DeriveIdentifiers(filename, userID, deviceID string) (uid, did, bid string) {
	// For backward compatibility with old API
	uid = userID

	// Use deviceID if provided, otherwise use filename as device identifier
	if deviceID != "" {
		did = deviceID
	} else {
		did = filename
	}

	// Use filename as backup identifier
	bid = filename

	return uid, did, bid
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
// 1. Uses the provided Identity (UID, DID, BID) as the primary key
// 2. Converts password to cryptographic PIN
// 3. Distributes secret shares to OpenADP servers via JSON-RPC
// 4. Uses authentication codes for secure server communication
// 5. Uses threshold cryptography for recovery
func GenerateEncryptionKey(identity *Identity, password string, maxGuesses, expiration int,
	serverInfos []ServerInfo) *GenerateEncryptionKeyResult {

	// Input validation
	if identity == nil {
		return &GenerateEncryptionKeyResult{
			Error: "Identity cannot be nil",
		}
	}

	if identity.UID == "" {
		return &GenerateEncryptionKeyResult{
			Error: "UID cannot be empty",
		}
	}

	if identity.DID == "" {
		return &GenerateEncryptionKeyResult{
			Error: "DID cannot be empty",
		}
	}

	if identity.BID == "" {
		return &GenerateEncryptionKeyResult{
			Error: "BID cannot be empty",
		}
	}

	if maxGuesses < 0 {
		return &GenerateEncryptionKeyResult{
			Error: "Max guesses cannot be negative",
		}
	}

	fmt.Printf("OpenADP: Identity=%s\n", identity.String())

	// Step 1: Convert password to PIN
	pin := []byte(password)

	// Step 2: Check if we have servers
	if len(serverInfos) == 0 {
		return &GenerateEncryptionKeyResult{
			Error: "No OpenADP servers available",
		}
	}

	// Step 3: Initialize encrypted clients for each server using public keys from servers.json
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

	// Step 4: Generate authentication codes for the live servers
	authCodes := GenerateAuthCodes(liveServerURLs)

	// Step 5: Generate RANDOM secret and create point
	// SECURITY FIX: Use random secret for Shamir secret sharing, not deterministic
	var secret *big.Int
	var err error

	if debug.IsDebugModeEnabled() {
		// In debug mode, use large deterministic secret
		secret = debug.GetDeterministicMainSecret()
		// Add duplicate debug output to match Python
		_ = debug.GetDeterministicSecret()
	} else {
		// In normal mode, use cryptographically secure random
		secret, err = rand.Int(rand.Reader, common.Q)
		if err != nil {
			return &GenerateEncryptionKeyResult{
				Error: fmt.Sprintf("Failed to generate random secret: %v", err),
			}
		}

		// Ensure secret is not zero
		if secret.Sign() == 0 {
			secret.SetInt64(1)
		}
	}

	U := common.H([]byte(identity.UID), []byte(identity.DID), []byte(identity.BID), pin)

	// Add debug logging to match other SDKs
	if debug.IsDebugModeEnabled() {
		debug.DebugLog(fmt.Sprintf("Computed U point for identity: UID=%s, DID=%s, BID=%s", identity.UID, identity.DID, identity.BID))
	}

	S := common.PointMul(secret, U)

	// Add debug logging to match other SDKs
	if debug.IsDebugModeEnabled() {
		debug.DebugLog("Computed S = secret * U")
	}

	// Step 6: Create shares using secret sharing
	threshold := len(clients)/2 + 1 // Standard majority threshold: floor(N/2) + 1
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

	// Step 7: Register shares with servers using authentication codes and encryption
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

		// Convert share Y to base64-encoded 32-byte little-endian format (per API spec)
		yBytes := make([]byte, 32)
		yBigInt := share.Y
		yBigIntBytes := yBigInt.Bytes() // Big-endian format

		// Convert to little-endian by copying and reversing
		if len(yBigIntBytes) <= 32 {
			copy(yBytes[32-len(yBigIntBytes):], yBigIntBytes) // Right-align in big-endian
			// Convert to little-endian
			for i, j := 0, len(yBytes)-1; i < j; i, j = i+1, j-1 {
				yBytes[i], yBytes[j] = yBytes[j], yBytes[i]
			}
		} else {
			return &GenerateEncryptionKeyResult{
				Error: fmt.Sprintf("Y coordinate too large for 32-byte encoding: %d bytes", len(yBigIntBytes)),
			}
		}

		yBase64 := base64.StdEncoding.EncodeToString(yBytes)

		// Use encrypted registration if server has public key, otherwise unencrypted for compatibility
		encrypted := client.HasPublicKey()

		success, err := client.RegisterSecret(
			authCode, identity.UID, identity.DID, identity.BID, version, int(share.X.Int64()), yBase64, maxGuesses, expiration, encrypted, nil)

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

	if successfulRegistrations < threshold {
		return &GenerateEncryptionKeyResult{
			Error: fmt.Sprintf("Failed to register enough shares: got %d/%d, need %d (threshold). Errors: %v", successfulRegistrations, len(clients), threshold, registrationErrors),
		}
	}

	// Step 8: Derive encryption key
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
	NumGuesses    int // Actual number of guesses used (from server responses)
	MaxGuesses    int // Maximum guesses allowed (from server responses)
}

// RecoverEncryptionKeyWithServerInfo recovers an encryption key using OpenADP distributed secret sharing.
//
// FULL DISTRIBUTED IMPLEMENTATION: This implements the complete OpenADP protocol:
// 1. Uses the provided Identity (UID, DID, BID) as the primary key
// 2. Converts password to the same PIN
// 3. Recovers shares from OpenADP servers via JSON-RPC with Noise-NK encryption
// 4. Reconstructs the original secret using threshold cryptography
// 5. Derives the same encryption key
func RecoverEncryptionKeyWithServerInfo(identity *Identity, password string, serverInfos []ServerInfo, threshold int, authCodes *AuthCodes) *RecoverEncryptionKeyResult {
	// Input validation
	if identity == nil {
		return &RecoverEncryptionKeyResult{
			Error: "Identity cannot be nil",
		}
	}

	if identity.UID == "" {
		return &RecoverEncryptionKeyResult{
			Error: "UID cannot be empty",
		}
	}

	if identity.DID == "" {
		return &RecoverEncryptionKeyResult{
			Error: "DID cannot be empty",
		}
	}

	if identity.BID == "" {
		return &RecoverEncryptionKeyResult{
			Error: "BID cannot be empty",
		}
	}

	if threshold <= 0 {
		return &RecoverEncryptionKeyResult{
			Error: "Threshold must be positive",
		}
	}

	fmt.Printf("OpenADP: Identity=%s\n", identity.String())

	// Step 1: Convert password to same PIN
	pin := []byte(password)

	// Step 2: Check if we have servers and auth codes
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

	// Step 3: Initialize clients for the specific servers, using encryption when public keys are available
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

	// Step 4: Create cryptographic context (same as encryption)
	U := common.H([]byte(identity.UID), []byte(identity.DID), []byte(identity.BID), pin)

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

	// Step 5: Recover shares from servers using authentication codes
	fmt.Println("OpenADP: Recovering shares from servers...")
	recoveredPointShares := make([]*PointShare, 0, len(clients))

	// Track guess information from server responses
	var actualNumGuesses, actualMaxGuesses int

	for i, client := range clients {
		serverURL := liveServerURLs[i]
		authCode := authCodes.ServerAuthCodes[serverURL]

		// Get current guess number for this backup from the server
		backups, err := client.ListBackups(identity.UID, false, nil)
		guessNum := 0 // Default to 0 for first guess (0-based indexing)
		if err != nil {
			fmt.Printf("Warning: Could not list backups from server %d: %v\n", i+1, err)
		} else {
			// Find our backup in the list using the complete primary key (UID, DID, BID)
			for _, backupMap := range backups {
				if backupUID, ok := backupMap["uid"].(string); ok && backupUID == identity.UID {
					if backupDID, ok := backupMap["did"].(string); ok && backupDID == identity.DID {
						if backupBID, ok := backupMap["bid"].(string); ok && backupBID == identity.BID {
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
		resultMap, err := client.RecoverSecret(authCode, identity.UID, identity.DID, identity.BID, bBase64Format, guessNum, true, nil)

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
					resultMap, err = client.RecoverSecret(authCode, identity.UID, identity.DID, identity.BID, bBase64Format, expectedGuess, true, nil)
				}
			}
		}

		if err != nil {
			fmt.Printf("Server %d (%s) recovery failed: %v\n", i+1, serverURL, err)
			continue
		}

		// Capture guess information from server response (first successful server)
		if actualNumGuesses == 0 && actualMaxGuesses == 0 {
			if numGuesses, ok := resultMap["num_guesses"].(float64); ok {
				actualNumGuesses = int(numGuesses)
			}
			if maxGuesses, ok := resultMap["max_guesses"].(float64); ok {
				actualMaxGuesses = int(maxGuesses)
			}
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
			Error:      fmt.Sprintf("Could not recover enough shares (got %d, need at least %d)", len(recoveredPointShares), threshold),
			NumGuesses: actualNumGuesses,
			MaxGuesses: actualMaxGuesses,
		}
	}

	// Step 6: Reconstruct secret using point-based recovery (like Python recover_sb)
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

	// Step 7: Derive same encryption key
	encKey := common.DeriveEncKey(originalSU)
	fmt.Println("OpenADP: Successfully recovered encryption key")

	return &RecoverEncryptionKeyResult{
		EncryptionKey: encKey,
		NumGuesses:    actualNumGuesses,
		MaxGuesses:    actualMaxGuesses,
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
}

// GenerateAuthCodes generates authentication codes for OpenADP servers.
//
// This creates a base authentication code (256-bit SHA256 hash) and derives server-specific codes
// for each server URL, matching the expected 64-character hex format.
func GenerateAuthCodes(serverURLs []string) *AuthCodes {
	// Generate base authentication code (256 bits = 32 bytes as hex = 64 chars)
	var baseAuthCode string

	if debug.IsDebugModeEnabled() {
		// In debug mode, use deterministic base auth code
		baseAuthCode = debug.GetDeterministicBaseAuthCode()
	} else {
		// In normal mode, use cryptographically secure random
		baseBytes := make([]byte, 32)
		if _, err := rand.Read(baseBytes); err != nil {
			// SECURITY: Never use deterministic fallback for cryptographic operations
			panic(fmt.Sprintf("CRITICAL: Cryptographic random number generation failed: %v. Cannot continue with insecure operations.", err))
		}
		baseAuthCode = fmt.Sprintf("%x", baseBytes)
	}

	// Generate server-specific authentication codes using SHA256
	serverAuthCodes := make(map[string]string)
	for _, serverURL := range serverURLs {
		// Derive server-specific code using SHA256 (matches middleware format)
		combined := fmt.Sprintf("%s:%s", baseAuthCode, serverURL)
		hash := sha256.Sum256([]byte(combined))
		serverAuthCodes[serverURL] = fmt.Sprintf("%x", hash[:])

		if debug.IsDebugModeEnabled() {
			debug.DebugLog(fmt.Sprintf("Generated auth code for server: %s", serverURL))
		}
	}

	return &AuthCodes{
		BaseAuthCode:    baseAuthCode,
		ServerAuthCodes: serverAuthCodes,
	}
}

// FetchRemainingGuessesForServers fetches remaining guesses for each server and updates ServerInfo objects.
func FetchRemainingGuessesForServers(identity *Identity, serverInfos []ServerInfo) []ServerInfo {
	updatedServerInfos := make([]ServerInfo, len(serverInfos))

	for i, serverInfo := range serverInfos {
		// Create a copy to avoid modifying the original
		updatedServerInfo := serverInfo

		// Parse public key if available
		var publicKey []byte
		if serverInfo.PublicKey != "" {
			if strings.HasPrefix(serverInfo.PublicKey, "ed25519:") {
				keyB64 := strings.TrimPrefix(serverInfo.PublicKey, "ed25519:")
				if key, err := base64.StdEncoding.DecodeString(keyB64); err == nil {
					publicKey = key
				}
			} else {
				if key, err := base64.StdEncoding.DecodeString(serverInfo.PublicKey); err == nil {
					publicKey = key
				}
			}
		}

		// Create client and try to fetch backup info
		client := NewEncryptedOpenADPClient(serverInfo.URL, publicKey)

		if err := client.Ping(); err == nil {
			// List backups to get remaining guesses
			backups, err := client.ListBackups(identity.UID, false, nil)
			if err == nil {
				// Find our specific backup
				remainingGuesses := -1 // Default to unknown
				for _, backup := range backups {
					if backup["uid"] == identity.UID &&
						backup["did"] == identity.DID &&
						backup["bid"] == identity.BID {
						numGuesses, _ := backup["num_guesses"].(float64)
						maxGuesses, _ := backup["max_guesses"].(float64)
						remainingGuesses = int(math.Max(0, maxGuesses-numGuesses))
						break
					}
				}

				updatedServerInfo.RemainingGuesses = remainingGuesses
				fmt.Printf("OpenADP: Server %s has %d remaining guesses\n", serverInfo.URL, remainingGuesses)
			} else {
				fmt.Printf("Warning: Could not list backups from server %s: %v\n", serverInfo.URL, err)
			}
		} else {
			fmt.Printf("Warning: Could not connect to server %s: %v\n", serverInfo.URL, err)
		}

		updatedServerInfos[i] = updatedServerInfo
	}

	return updatedServerInfos
}

// SelectServersByRemainingGuesses selects servers intelligently based on remaining guesses.
//
// Strategy:
// 1. Filter out servers with 0 remaining guesses (exhausted)
// 2. Sort by remaining guesses (descending) to use servers with most guesses first
// 3. Servers with unknown remaining guesses (-1) are treated as having infinite guesses
// 4. Select threshold + 2 servers for redundancy
func SelectServersByRemainingGuesses(serverInfos []ServerInfo, threshold int) []ServerInfo {
	// Filter out servers with 0 remaining guesses (exhausted)
	var availableServers []ServerInfo
	for _, server := range serverInfos {
		if server.RemainingGuesses != 0 {
			availableServers = append(availableServers, server)
		}
	}

	if len(availableServers) == 0 {
		fmt.Println("Warning: All servers have exhausted their guesses!")
		return serverInfos // Return original list as fallback
	}

	// Sort by remaining guesses (descending)
	// Servers with unknown remaining guesses (-1) are treated as having the highest priority
	sort.Slice(availableServers, func(i, j int) bool {
		aGuesses := availableServers[i].RemainingGuesses
		bGuesses := availableServers[j].RemainingGuesses

		if aGuesses == -1 {
			aGuesses = math.MaxInt32
		}
		if bGuesses == -1 {
			bGuesses = math.MaxInt32
		}

		return aGuesses > bGuesses
	})

	// Select threshold + 2 servers for redundancy, but don't exceed available servers
	numToSelect := min(len(availableServers), threshold+2)
	selectedServers := availableServers[:numToSelect]

	fmt.Printf("OpenADP: Selected %d servers based on remaining guesses:\n", len(selectedServers))
	for i, server := range selectedServers {
		guessesStr := "unknown"
		if server.RemainingGuesses != -1 {
			guessesStr = fmt.Sprintf("%d", server.RemainingGuesses)
		}
		fmt.Printf("  %d. %s (%s remaining guesses)\n", i+1, server.URL, guessesStr)
	}

	return selectedServers
}
