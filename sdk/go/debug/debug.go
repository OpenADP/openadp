// Package debug provides deterministic operations for testing and debugging.
//
// This package implements the same debug mode functionality as the C++ version,
// allowing for deterministic secret generation, polynomial coefficients, and
// ephemeral keys to enable cross-language compatibility testing.
package debug

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
)

// Global debug state
var (
	debugMode            bool
	debugMutex           sync.RWMutex
	deterministicCounter int64
)

// init automatically enables debug mode if OPENADP_DEBUG environment variable is set
func init() {
	if envDebug := os.Getenv("OPENADP_DEBUG"); envDebug == "1" || envDebug == "true" {
		debugMode = true
		log.Println("🐛 Debug mode automatically enabled via OPENADP_DEBUG environment variable")
	}
}

// SetDebugMode enables or disables debug mode for deterministic operations
func SetDebugMode(enabled bool) {
	debugMutex.Lock()
	defer debugMutex.Unlock()

	debugMode = enabled
	deterministicCounter = 0 // Reset counter when enabling/disabling

	if enabled {
		log.Println("🐛 Debug mode enabled - all operations are now deterministic")
	} else {
		log.Println("Debug mode disabled - randomness restored")
	}
}

// IsDebugModeEnabled returns whether debug mode is currently enabled
func IsDebugModeEnabled() bool {
	debugMutex.RLock()
	defer debugMutex.RUnlock()
	return debugMode
}

// DebugLog prints a debug message if debug mode is enabled
func DebugLog(message string) {
	debugMutex.RLock()
	enabled := debugMode
	debugMutex.RUnlock()

	if enabled {
		log.Printf("[DEBUG] %s", message)
	}
}

// GetDeterministicMainSecret returns a large deterministic scalar for the main secret r
// This is a fixed large value that properly exercises the cryptographic operations
func GetDeterministicMainSecret() *big.Int {
	debugMutex.RLock()
	enabled := debugMode
	debugMutex.RUnlock()

	if !enabled {
		panic("GetDeterministicMainSecret called outside debug mode")
	}

	// Use the same large deterministic constant as Python and C++ implementations
	// This is the hex pattern reduced modulo Ed25519 group order q
	// 64 characters (even length) for consistent hex parsing across all SDKs
	deterministicHex := "023456789abcdef0fedcba987654320ffd555c99f7c5421aa6ca577e195e5e23"
	deterministicSecret, _ := new(big.Int).SetString(deterministicHex, 16)

	// Use %064x to ensure leading zero is displayed (64-character hex)
	DebugLog(fmt.Sprintf("Using deterministic main secret r = 0x%064x", deterministicSecret))
	return deterministicSecret
}

// GetDeterministicRandomScalar returns a deterministic scalar for testing
// In debug mode, the main secret r should always be 1
func GetDeterministicRandomScalar() *big.Int {
	debugMutex.RLock()
	enabled := debugMode
	debugMutex.RUnlock()

	if !enabled {
		panic("GetDeterministicRandomScalar called outside debug mode")
	}

	DebugLog("Using deterministic scalar r = 1")
	return big.NewInt(1)
}

// GetDeterministicPolynomialCoefficient returns deterministic polynomial coefficients
// These should be sequential: 1, 2, 3, ... for reproducible Shamir secret sharing
func GetDeterministicPolynomialCoefficient() *big.Int {
	debugMutex.Lock()
	defer debugMutex.Unlock()

	if !debugMode {
		panic("GetDeterministicPolynomialCoefficient called outside debug mode")
	}

	deterministicCounter++
	result := big.NewInt(deterministicCounter)

	DebugLog(fmt.Sprintf("Using deterministic polynomial coefficient: %d", deterministicCounter))
	return result
}

// GetDeterministicRandomBytes returns deterministic bytes for testing
func GetDeterministicRandomBytes(length int) []byte {
	debugMutex.Lock()
	defer debugMutex.Unlock()

	if !debugMode {
		panic("GetDeterministicRandomBytes called outside debug mode")
	}

	deterministicCounter++
	bytes := make([]byte, length)

	for i := 0; i < length; i++ {
		bytes[i] = byte((deterministicCounter + int64(i)) % 256)
	}

	DebugLog(fmt.Sprintf("Generated deterministic bytes (%d bytes)", length))
	return bytes
}

// GetDeterministicEphemeralSecret returns a fixed ephemeral secret for reproducible Noise handshakes
func GetDeterministicEphemeralSecret() []byte {
	debugMutex.RLock()
	enabled := debugMode
	debugMutex.RUnlock()

	if !enabled {
		panic("GetDeterministicEphemeralSecret called outside debug mode")
	}

	DebugLog("Using deterministic ephemeral secret")
	// Fixed ephemeral secret for reproducible Noise handshakes (32 bytes for X25519)
	// This should match the Python implementation
	ephemeralSecret := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
	}

	DebugLog(fmt.Sprintf("Using deterministic ephemeral secret: %064x", ephemeralSecret))
	return ephemeralSecret
}

// SecureRandom provides either deterministic or cryptographically secure random generation
// This is the main function that should be used throughout the codebase for random number generation
func SecureRandom(max *big.Int) (*big.Int, error) {
	debugMutex.RLock()
	enabled := debugMode
	debugMutex.RUnlock()

	if enabled {
		// In debug mode, return deterministic values
		// For the main secret, always return 1
		DebugLog("Using deterministic random value: 1")
		return big.NewInt(1), nil
	}

	// In normal mode, use cryptographically secure random
	return rand.Int(rand.Reader, max)
}

// SecureRandomCoefficient provides deterministic or secure random coefficients for Shamir secret sharing
func SecureRandomCoefficient(max *big.Int) (*big.Int, error) {
	debugMutex.RLock()
	enabled := debugMode
	debugMutex.RUnlock()

	if enabled {
		// In debug mode, return sequential deterministic coefficients
		return GetDeterministicPolynomialCoefficient(), nil
	}

	// In normal mode, use cryptographically secure random
	return rand.Int(rand.Reader, max)
}

// GetDeterministicBaseAuthCode returns a fixed base auth code for deterministic testing
func GetDeterministicBaseAuthCode() string {
	debugMutex.RLock()
	enabled := debugMode
	debugMutex.RUnlock()

	if !enabled {
		panic("GetDeterministicBaseAuthCode called outside debug mode")
	}

	// Use the same deterministic base auth code as Python implementation
	baseAuthCode := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	DebugLog(fmt.Sprintf("Using deterministic base auth code: %s", baseAuthCode))
	return baseAuthCode
}

// GetDeterministicSecret returns the same value as the main secret for consistency
func GetDeterministicSecret() *big.Int {
	debugMutex.RLock()
	enabled := debugMode
	debugMutex.RUnlock()

	if !enabled {
		panic("GetDeterministicSecret called outside debug mode")
	}

	// Use the same value as the main secret (64 characters, even length)
	deterministicHex := "023456789abcdef0fedcba987654320ffd555c99f7c5421aa6ca577e195e5e23"
	deterministicSecret, _ := new(big.Int).SetString(deterministicHex, 16)

	// Use %064x to ensure leading zero is displayed (64-character hex)
	DebugLog(fmt.Sprintf("Using deterministic secret: 0x%064x", deterministicSecret))
	return deterministicSecret
}
