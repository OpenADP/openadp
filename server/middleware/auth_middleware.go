// Package middleware provides authentication middleware for OpenADP servers.
//
// This module implements authentication code validation for OpenADP servers,
// replacing the OAuth/DPoP authentication system with a simpler, distributed approach.
//
// Key features:
// - 128-bit authentication code validation
// - Server-specific code derivation using SHA256(auth_code || server_url)
// - Format validation and entropy checking
// - DDoS defense mechanisms
// - No external dependencies (no JWT, no JWKS, no OAuth)
package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Global state for DDoS defense
var (
	failedAttempts    = make(map[string]int)
	attemptTimestamps = make(map[string]time.Time)
	blacklistedCodes  = make(map[string]bool)
	ddosMutex         sync.RWMutex
)

// AuthCodeConfig holds configuration for authentication code middleware
type AuthCodeConfig struct {
	Enabled          bool
	MinEntropyBits   int
	MaxAttemptsPerIP int
	DDosDefense      bool
}

// NewAuthCodeConfig creates configuration from environment variables
func NewAuthCodeConfig() *AuthCodeConfig {
	config := &AuthCodeConfig{
		Enabled:          getEnvBool("OPENADP_AUTH_ENABLED", true),
		MinEntropyBits:   getEnvInt("OPENADP_AUTH_MIN_ENTROPY", 100),
		MaxAttemptsPerIP: getEnvInt("OPENADP_AUTH_MAX_ATTEMPTS_PER_IP", 100),
		DDosDefense:      getEnvBool("OPENADP_AUTH_DDOS_DEFENSE", true),
	}

	log.Printf("Auth code config: enabled=%t, min_entropy=%d, ddos_defense=%t",
		config.Enabled, config.MinEntropyBits, config.DDosDefense)

	return config
}

// getEnvBool gets a boolean environment variable with default
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if value == "1" || strings.ToLower(value) == "true" {
			return true
		}
		return false
	}
	return defaultValue
}

// getEnvInt gets an integer environment variable with default
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// CalculateEntropy calculates the entropy of a hex string in bits
func CalculateEntropy(hexString string) int {
	if hexString == "" {
		return 0
	}

	// Count frequency of each character
	charCounts := make(map[rune]int)
	for _, char := range strings.ToLower(hexString) {
		charCounts[char]++
	}

	// Calculate Shannon entropy
	length := float64(len(hexString))
	entropy := 0.0

	for _, count := range charCounts {
		probability := float64(count) / length
		if probability > 0 {
			entropy -= probability * math.Log2(probability)
		}
	}

	// Convert to bits (multiply by string length)
	return int(entropy * length)
}

// ValidateAuthCodeFormat validates authentication code format
func ValidateAuthCodeFormat(authCode string, config *AuthCodeConfig) bool {
	// Must be exactly 64 hex characters (SHA256 hash)
	hexPattern := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if !hexPattern.MatchString(strings.ToLower(authCode)) {
		return false
	}

	// Check minimum entropy
	if CalculateEntropy(authCode) < config.MinEntropyBits {
		log.Printf("Authentication code has insufficient entropy: %d bits", CalculateEntropy(authCode))
		return false
	}

	// Check blacklist
	ddosMutex.RLock()
	isBlacklisted := blacklistedCodes[strings.ToLower(authCode)]
	ddosMutex.RUnlock()

	if isBlacklisted {
		log.Printf("Authentication code is blacklisted")
		return false
	}

	return true
}

// DeriveServerAuthCode derives server-specific authentication code
func DeriveServerAuthCode(baseCode, serverURL string) string {
	combined := fmt.Sprintf("%s:%s", baseCode, serverURL)
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// CheckDDosDefense checks if DDoS defense should be activated for a client IP
func CheckDDosDefense(clientIP string, config *AuthCodeConfig) bool {
	if !config.DDosDefense {
		return true
	}

	ddosMutex.Lock()
	defer ddosMutex.Unlock()

	currentTime := time.Now()

	// Clean up old timestamps (older than 1 hour)
	cutoffTime := currentTime.Add(-time.Hour)
	for ip, timestamp := range attemptTimestamps {
		if timestamp.Before(cutoffTime) {
			delete(attemptTimestamps, ip)
			delete(failedAttempts, ip)
		}
	}

	// Check attempt count for this IP
	attempts := failedAttempts[clientIP]
	if attempts >= config.MaxAttemptsPerIP {
		log.Printf("DDoS defense activated for IP %s: %d failed attempts", clientIP, attempts)
		return false
	}

	return true
}

// RecordFailedAttempt records a failed authentication attempt for DDoS tracking
func RecordFailedAttempt(clientIP string) {
	ddosMutex.Lock()
	defer ddosMutex.Unlock()

	failedAttempts[clientIP]++
	attemptTimestamps[clientIP] = time.Now()
}

// ValidateAuthCodeRequest validates an authentication code request
func ValidateAuthCodeRequest(authCode, serverURL, clientIP string) (string, error) {
	config := NewAuthCodeConfig()

	// Skip authentication if disabled
	if !config.Enabled {
		log.Printf("Authentication disabled, skipping validation")
		return "", nil
	}

	// Check DDoS defense
	if !CheckDDosDefense(clientIP, config) {
		RecordFailedAttempt(clientIP)
		return "", fmt.Errorf("rate limit exceeded - too many failed attempts")
	}

	// Validate format
	if !ValidateAuthCodeFormat(authCode, config) {
		RecordFailedAttempt(clientIP)
		return "", fmt.Errorf("invalid authentication code format")
	}

	// Derive UUID from authentication code for user identification
	// This creates a consistent user identifier from the auth code
	hash := sha256.Sum256([]byte(authCode))
	derivedUUID := hex.EncodeToString(hash[:])[:16]

	log.Printf("Authentication code validated successfully for derived UUID: %s", derivedUUID)
	return derivedUUID, nil
}

// AuthStats represents authentication middleware statistics
type AuthStats struct {
	FailedAttemptsCount   int                    `json:"failed_attempts_count"`
	BlacklistedCodesCount int                    `json:"blacklisted_codes_count"`
	TotalFailedAttempts   int                    `json:"total_failed_attempts"`
	Config                map[string]interface{} `json:"config"`
}

// GetAuthStats returns authentication middleware statistics for monitoring
func GetAuthStats() *AuthStats {
	ddosMutex.RLock()
	defer ddosMutex.RUnlock()

	config := NewAuthCodeConfig()
	totalAttempts := 0
	for _, count := range failedAttempts {
		totalAttempts += count
	}

	return &AuthStats{
		FailedAttemptsCount:   len(failedAttempts),
		BlacklistedCodesCount: len(blacklistedCodes),
		TotalFailedAttempts:   totalAttempts,
		Config: map[string]interface{}{
			"enabled":          config.Enabled,
			"min_entropy_bits": config.MinEntropyBits,
			"ddos_defense":     config.DDosDefense,
		},
	}
}

// BlacklistAuthCode adds an authentication code to the blacklist
func BlacklistAuthCode(authCode string) {
	ddosMutex.Lock()
	defer ddosMutex.Unlock()

	blacklistedCodes[strings.ToLower(authCode)] = true
	log.Printf("Authentication code blacklisted")
}

// ClearBlacklist clears the authentication code blacklist
func ClearBlacklist() {
	ddosMutex.Lock()
	defer ddosMutex.Unlock()

	blacklistedCodes = make(map[string]bool)
	log.Printf("Authentication code blacklist cleared")
}

// AuthMiddleware is HTTP middleware for authentication code validation
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract client IP
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = strings.Split(forwarded, ",")[0]
		}

		// Extract auth code from header or query parameter
		authCode := r.Header.Get("X-Auth-Code")
		if authCode == "" {
			authCode = r.URL.Query().Get("auth_code")
		}

		if authCode != "" {
			// Validate auth code
			derivedUUID, err := ValidateAuthCodeRequest(authCode, r.Host, clientIP)
			if err != nil {
				http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
				return
			}

			// Add derived UUID to request context for use by handlers
			if derivedUUID != "" {
				r.Header.Set("X-Derived-UUID", derivedUUID)
			}
		}

		// Continue to next handler
		next.ServeHTTP(w, r)
	})
}
