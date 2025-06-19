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
package keygen

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"encoding/base64"

	"github.com/openadp/openadp/pkg/client"
	"github.com/openadp/openadp/pkg/crypto"
	"github.com/openadp/openadp/pkg/sharing"
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
// 1. Derives UID/DID/BID using authenticated user_id
// 2. Converts password to PIN for cryptographic operations
// 3. Generates random secret and splits into shares
// 4. Registers shares with OpenADP servers via JSON-RPC
// 5. Uses threshold cryptography for recovery
func GenerateEncryptionKey(filename, password, userID string, maxGuesses, expiration int,
	serverURLs []string) *GenerateEncryptionKeyResult {

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
	if len(serverURLs) == 0 {
		return &GenerateEncryptionKeyResult{
			Error: "No OpenADP servers available",
		}
	}

	// Step 4: Initialize clients for each server
	clientManager := client.NewClientManager(serverURLs)
	if err := clientManager.TestConnectivity(); err != nil {
		return &GenerateEncryptionKeyResult{
			Error: fmt.Sprintf("No live servers available: %v", err),
		}
	}

	liveClients := clientManager.GetLiveClients()
	liveServerURLs := clientManager.GetLiveServerURLs()
	fmt.Printf("OpenADP: Using %d live servers\n", len(liveClients))

	// Step 5: Generate authentication codes for the live servers
	authCodes := GenerateAuthCodes(liveServerURLs)

	// Step 6: Generate deterministic secret and create point
	// Use deterministic secret derivation for consistent key generation
	secret := crypto.DeriveSecret([]byte(uid), []byte(did), []byte(bid), pin)

	U := crypto.H([]byte(uid), []byte(did), []byte(bid), pin)
	S := crypto.PointMul(secret, U)

	// Debug: Print the point S during encryption
	SCompressed := crypto.PointCompress(S)
	fmt.Printf("DEBUG ENCRYPT: Point S = %x\n", SCompressed)

	// Step 7: Create shares using secret sharing
	threshold := max(1, min(2, len(liveClients))) // At least 1, prefer 2 if available
	numShares := len(liveClients)

	if numShares < threshold {
		return &GenerateEncryptionKeyResult{
			Error: fmt.Sprintf("Need at least %d servers, only %d available", threshold, numShares),
		}
	}

	shares, err := sharing.MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		return &GenerateEncryptionKeyResult{
			Error: fmt.Sprintf("Failed to create shares: %v", err),
		}
	}

	fmt.Printf("OpenADP: Created %d shares with threshold %d\n", len(shares), threshold)

	// Step 8: Register shares with servers using authentication codes
	version := 1
	registrationErrors := []string{}
	successfulRegistrations := 0

	for i, share := range shares {
		if i >= len(liveClients) {
			break // More shares than servers
		}

		client := liveClients[i]
		serverURL := liveServerURLs[i]
		authCode := authCodes.ServerAuthCodes[serverURL]

		// DEBUG: Print the scalar share si and compute si*U
		si := share.Y
		siU := crypto.PointMul(si, U)
		siUCompressed := crypto.PointCompress(siU)
		UCompressed := crypto.PointCompress(U)
		fmt.Printf("DEBUG ENCRYPT: Share[%d] si = %x\n", i+1, si)
		fmt.Printf("DEBUG ENCRYPT: Share[%d] U = %x\n", i+1, UCompressed)
		fmt.Printf("DEBUG ENCRYPT: Share[%d] si*U (SENT) = %x\n", i+1, siUCompressed)

		// Convert share Y to integer string (server expects integer, not base64)
		yInt := share.Y.String()

		success, err := client.RegisterSecretWithAuthCode(
			authCode, did, bid, version, int(share.X.Int64()), yInt, maxGuesses, expiration)

		if err != nil {
			registrationErrors = append(registrationErrors, fmt.Sprintf("Server %d: %v", i+1, err))
		} else if !success {
			registrationErrors = append(registrationErrors, fmt.Sprintf("Server %d: Registration returned false", i+1))
		} else {
			fmt.Printf("OpenADP: Registered share %s with server %d\n", share.X.String(), i+1)
			successfulRegistrations++
		}
	}

	if successfulRegistrations == 0 {
		return &GenerateEncryptionKeyResult{
			Error: fmt.Sprintf("Failed to register any shares: %v", registrationErrors),
		}
	}

	// Step 9: Derive encryption key
	encKey := crypto.DeriveEncKey(S)
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

// RecoverEncryptionKey recovers an encryption key using OpenADP distributed secret sharing.
//
// FULL DISTRIBUTED IMPLEMENTATION: This implements the complete OpenADP protocol:
// 1. Derives the same UID/DID/BID as during encryption
// 2. Converts password to the same PIN
// 3. Recovers shares from OpenADP servers via JSON-RPC
// 4. Reconstructs the original secret using threshold cryptography
// 5. Derives the same encryption key
func RecoverEncryptionKey(filename, password, userID string, serverURLs []string, threshold int, authCodes *AuthCodes) *RecoverEncryptionKeyResult {
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
	if len(serverURLs) == 0 {
		return &RecoverEncryptionKeyResult{
			Error: "No OpenADP servers available",
		}
	}

	if authCodes == nil {
		return &RecoverEncryptionKeyResult{
			Error: "No authentication codes provided",
		}
	}

	// Step 4: Initialize clients for the specific servers from metadata
	clients := make([]*client.OpenADPClient, 0, len(serverURLs))
	liveServerURLs := make([]string, 0, len(serverURLs))

	for _, serverURL := range serverURLs {
		client := client.NewOpenADPClient(serverURL)
		if err := client.Ping(); err == nil {
			clients = append(clients, client)
			liveServerURLs = append(liveServerURLs, serverURL)
		} else {
			fmt.Printf("Warning: Server %s is not accessible: %v\n", serverURL, err)
		}
	}

	if len(clients) == 0 {
		return &RecoverEncryptionKeyResult{
			Error: "No servers from metadata are accessible",
		}
	}

	fmt.Printf("OpenADP: Using %d live servers\n", len(clients))

	// Step 5: Create cryptographic context (same as encryption)
	U := crypto.H([]byte(uid), []byte(did), []byte(bid), pin)

	// Generate random r and compute B for recovery protocol
	r, err := rand.Int(rand.Reader, crypto.Q)
	if err != nil {
		return &RecoverEncryptionKeyResult{
			Error: fmt.Sprintf("Failed to generate random r: %v", err),
		}
	}

	// Compute r^-1 mod q
	rInv := new(big.Int).ModInverse(r, crypto.Q)
	if rInv == nil {
		return &RecoverEncryptionKeyResult{
			Error: "Failed to compute modular inverse",
		}
	}

	B := crypto.PointMul(r, U)

	// Convert B to compressed point format (base64 string) - standard format for all servers
	bCompressed := crypto.PointCompress(B)
	bBase64Format := base64.StdEncoding.EncodeToString(bCompressed)

	// Step 6: Recover shares from servers using authentication codes
	fmt.Println("OpenADP: Recovering shares from servers...")
	recoveredPointShares := make([]*sharing.PointShare, 0, len(clients))

	for i, client := range clients {
		serverURL := liveServerURLs[i]
		authCode := authCodes.ServerAuthCodes[serverURL]

		// Get current guess number for this backup from the server
		fmt.Printf("Debug: Getting current guess number from server %d\n", i+1)
		backups, err := client.ListBackupsWithAuthCode(authCode)
		guessNum := 0 // Default to 0 if we can't determine current state
		if err != nil {
			fmt.Printf("Warning: Could not list backups from server %d: %v\n", i+1, err)
		} else {
			fmt.Printf("Debug: Server %d returned %d backups\n", i+1, len(backups))
			// Find our backup in the list from this server
			for j, backup := range backups {
				fmt.Printf("Debug: Backup %d: BID=%s, NumGuesses=%d\n", j, backup.BID, backup.NumGuesses)
				if backup.BID == bid {
					guessNum = backup.NumGuesses
					fmt.Printf("Debug: Found matching backup with guess_num=%d\n", guessNum)
					break
				}
			}
			if guessNum == 0 {
				fmt.Printf("Debug: No matching backup found for BID=%s\n", bid)
			}
		}

		fmt.Printf("Debug: Using guess_num=%d for server %d\n", guessNum, i+1)

		// Use compressed point format (base64 string) - standard for all servers
		fmt.Printf("Debug: Using compressed point format for server %d\n", i+1)
		result, err := client.RecoverSecretWithAuthCode(authCode, did, bid, bBase64Format, guessNum)

		if err != nil {
			fmt.Printf("Server %d recovery failed: %v\n", i+1, err)
			continue
		}

		// Decompress si_b from the result
		siB4D, err := crypto.PointDecompress(result.SiBBytes)
		if err != nil {
			fmt.Printf("Server %d: Failed to decompress si_b: %v\n", i+1, err)
			continue
		}

		siB := crypto.Unexpand(siB4D)

		// Create point share from recovered data (si * B point)
		// This matches Python's recover_sb which expects (x, Point2D) pairs
		pointShare := &sharing.PointShare{
			X:     big.NewInt(int64(result.X)),
			Point: siB, // This is si*B point returned by server
		}

		// DEBUG: Print what we got from the server
		fmt.Printf("DEBUG: Server %d returned X=%d, siB=(%x, %x)\n", i+1, result.X, siB.X, siB.Y)
		fmt.Printf("DEBUG: Created PointShare with X=%s, Point=(%x, %x)\n", pointShare.X.String(), pointShare.Point.X, pointShare.Point.Y)

		// DEBUG: Convert si*B back to si*U to verify
		// We have si*B, and B = r*U, so si*U = r^-1 * (si*B)
		siBExtended := crypto.Expand(siB)
		siU := crypto.PointMul(rInv, siBExtended)
		siUCompressed := crypto.PointCompress(siU)

		// DEBUG: Also compute what si should be by extracting it from si*B
		// Since si*B = si * (r*U), we need to figure out si from the server response
		// The server should have returned the original si value somehow
		UCompressed := crypto.PointCompress(U)
		fmt.Printf("DEBUG DECRYPT: Share[%d] U = %x\n", i+1, UCompressed)
		fmt.Printf("DEBUG DECRYPT: Share[%d] si*U (RECOVERED) = %x\n", i+1, siUCompressed)

		// TODO: We need to get the actual si value from the server to compare

		recoveredPointShares = append(recoveredPointShares, pointShare)
		fmt.Printf("OpenADP: Recovered share %d from server %d\n", result.X, i+1)
	}

	if len(recoveredPointShares) < threshold {
		return &RecoverEncryptionKeyResult{
			Error: fmt.Sprintf("Could not recover enough shares (got %d, need at least %d)", len(recoveredPointShares), threshold),
		}
	}

	// Step 7: Reconstruct secret using point-based recovery (like Python recover_sb)
	fmt.Printf("OpenADP: Reconstructing secret from %d point shares...\n", len(recoveredPointShares))

	// Use point-based Lagrange interpolation to recover s*B (like Python recover_sb)
	recoveredSB, err := sharing.RecoverPointSecret(recoveredPointShares)
	if err != nil {
		return &RecoverEncryptionKeyResult{
			Error: fmt.Sprintf("Failed to reconstruct point secret: %v", err),
		}
	}

	// Apply r^-1 to get the original secret point: s*U = r^-1 * (s*B)
	// This matches Python: rec_s_point = crypto.point_mul(r_inv, crypto.expand(rec_sb))
	recoveredSB4D := crypto.Expand(recoveredSB)
	originalSU := crypto.PointMul(rInv, recoveredSB4D)

	// Debug: Print the recovered point S during decryption
	recoveredSCompressed := crypto.PointCompress(originalSU)
	fmt.Printf("DEBUG DECRYPT: Point S = %x\n", recoveredSCompressed)

	// Step 8: Derive same encryption key
	encKey := crypto.DeriveEncKey(originalSU)
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
