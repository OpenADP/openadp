// Package auth provides authentication code management for OpenADP clients.
//
// This module provides client-side authentication code generation and management
// for the OpenADP authentication code system.
//
// Key features:
// - Generate secure 128-bit authentication codes
// - Derive server-specific codes using SHA256(auth_code || server_url)
// - Manage authentication codes for multiple servers
// - Provide secure storage recommendations
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// AuthCodeManager manages authentication codes for OpenADP clients.
//
// Provides methods to generate base authentication codes and derive
// server-specific codes for distributed authentication.
type AuthCodeManager struct{}

// NewAuthCodeManager creates a new authentication code manager
func NewAuthCodeManager() *AuthCodeManager {
	return &AuthCodeManager{}
}

// GenerateAuthCode generates a new 128-bit authentication code.
//
// Returns a 32-character hex string representing 128 bits of entropy.
func (m *AuthCodeManager) GenerateAuthCode() (string, error) {
	// Generate 16 random bytes (128 bits)
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Convert to 32-character hex string
	return hex.EncodeToString(randomBytes), nil
}

// DeriveServerCode derives server-specific authentication code.
func (m *AuthCodeManager) DeriveServerCode(baseCode, serverURL string) string {
	combined := fmt.Sprintf("%s:%s", baseCode, serverURL)
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// GetServerCodes gets authentication codes for all servers.
func (m *AuthCodeManager) GetServerCodes(baseCode string, serverURLs []string) map[string]string {
	result := make(map[string]string)
	for _, url := range serverURLs {
		result[url] = m.DeriveServerCode(baseCode, url)
	}
	return result
}

// ValidateBaseCodeFormat validates base authentication code format.
//
// Returns true if format is valid (exactly 32 hex characters), false otherwise.
func (m *AuthCodeManager) ValidateBaseCodeFormat(baseCode string) bool {
	// Must be exactly 32 hex characters (128 bits)
	if len(baseCode) != 32 {
		return false
	}

	// Try to parse as hex
	_, err := hex.DecodeString(baseCode)
	return err == nil
}

// ValidateServerCodeFormat validates server-specific authentication code format.
//
// Returns true if format is valid (exactly 64 hex characters), false otherwise.
func (m *AuthCodeManager) ValidateServerCodeFormat(serverCode string) bool {
	// Must be exactly 64 hex characters (SHA256 hash)
	if len(serverCode) != 64 {
		return false
	}

	// Try to parse as hex
	_, err := hex.DecodeString(serverCode)
	return err == nil
}

// GetStorageRecommendations gets recommendations for secure authentication code storage.
func (m *AuthCodeManager) GetStorageRecommendations() map[string]string {
	return map[string]string{
		"disk_encryption":  "Store authentication code on the encrypted disk itself",
		"password_manager": "Store authentication code in your password manager vault",
		"phone_backup":     "Store authentication code with your phone backup system",
		"multi_device":     "Sync authentication code across devices using secure cloud storage",
		"paper_backup":     "Write authentication code on paper and store in secure location",
		"hardware_token":   "Store authentication code on hardware security key (if supported)",
		"warning":          "Never store authentication codes in plaintext on unencrypted storage",
	}
}

// GenerateAuthCodeFromSeed generates a deterministic auth code from a seed (for testing)
func (m *AuthCodeManager) GenerateAuthCodeFromSeed(seed string) string {
	hash := sha256.Sum256([]byte(seed))
	// Take first 16 bytes for 128-bit auth code
	return hex.EncodeToString(hash[:16])
}

// ParseAuthCodeToInt converts a hex auth code to a big integer
func (m *AuthCodeManager) ParseAuthCodeToInt(authCode string) (*big.Int, error) {
	// Remove any whitespace or formatting
	cleaned := strings.ReplaceAll(authCode, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")

	// Parse as hex
	result := new(big.Int)
	result, ok := result.SetString(cleaned, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex format: %s", authCode)
	}

	return result, nil
}

// FormatAuthCode formats an auth code with optional spacing for readability
func (m *AuthCodeManager) FormatAuthCode(authCode string, addSpacing bool) string {
	if !addSpacing {
		return authCode
	}

	// Add spaces every 8 characters for readability
	var formatted strings.Builder
	for i, char := range authCode {
		if i > 0 && i%8 == 0 {
			formatted.WriteRune(' ')
		}
		formatted.WriteRune(char)
	}

	return formatted.String()
}

// ValidateAuthCodeStrength checks if an auth code has sufficient entropy
func (m *AuthCodeManager) ValidateAuthCodeStrength(authCode string) (bool, string) {
	if !m.ValidateBaseCodeFormat(authCode) {
		return false, "Invalid format: must be 32 hex characters"
	}

	// Convert to integer for analysis
	authInt, err := m.ParseAuthCodeToInt(authCode)
	if err != nil {
		return false, "Failed to parse auth code"
	}

	// Check if it's too small (less than 2^120)
	minValue := new(big.Int).Lsh(big.NewInt(1), 120)
	if authInt.Cmp(minValue) < 0 {
		return false, "Auth code has insufficient entropy (too small)"
	}

	// Check for obvious patterns (all same digit, sequential, etc.)
	if m.hasObviousPattern(authCode) {
		return false, "Auth code contains obvious patterns"
	}

	return true, "Auth code has sufficient strength"
}

// hasObviousPattern checks for simple patterns in the auth code
func (m *AuthCodeManager) hasObviousPattern(authCode string) bool {
	// Check for all same character
	firstChar := authCode[0]
	allSame := true
	for i := 0; i < len(authCode); i++ {
		if authCode[i] != firstChar {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	// Check for simple incrementing pattern
	hasIncrementing := true
	for i := 1; i < len(authCode); i++ {
		curr, _ := strconv.ParseInt(string(authCode[i]), 16, 32)
		prev, _ := strconv.ParseInt(string(authCode[i-1]), 16, 32)
		if (curr-prev+16)%16 != 1 {
			hasIncrementing = false
			break
		}
	}
	if hasIncrementing {
		return true
	}

	return false
}
