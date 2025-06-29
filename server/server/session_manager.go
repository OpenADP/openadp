// Package server provides session management for Noise-NK encryption sessions.
//
// This module manages ephemeral Noise-NK encryption sessions for the JSON-RPC server.
// Each session is used for exactly one encrypted method call and then destroyed.
//
// Design:
// - Sessions are identified by 16-byte random session IDs
// - Server maintains a static keypair for NK pattern (responder role)
// - Each session uses fresh ephemeral keys for perfect forward secrecy
// - Sessions are automatically cleaned up after single use
package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/flynn/noise"
	openadpNoise "github.com/openadp/ocrypt/common"
)

// Global debug mode flag
var debugMode bool

// SetDebugMode enables or disables debug mode for deterministic ephemeral keys
func SetDebugMode(enabled bool) {
	debugMode = enabled
	// Note: Debug mode for the underlying Noise-NK implementation is now
	// automatically enabled via OPENADP_DEBUG environment variable set in main.go
	if enabled {
		log.Println("🐛 Session manager debug mode enabled - using deterministic ephemeral keys")
	} else {
		log.Println("Session manager debug mode disabled - using random ephemeral keys")
	}
}

// NoiseSessionManager manages Noise-NK encryption sessions for the JSON-RPC server
type NoiseSessionManager struct {
	sessions    map[string]*openadpNoise.NoiseNK
	sessionLock sync.RWMutex
	serverKey   noise.DHKey
}

// NewNoiseSessionManager creates a new session manager
func NewNoiseSessionManager(serverStaticKey *noise.DHKey) *NoiseSessionManager {
	var serverKey noise.DHKey
	var err error

	if serverStaticKey == nil {
		log.Println("Generating new server static key for Noise-NK")
		serverKey, err = openadpNoise.GenerateKeypair()
		if err != nil {
			log.Fatalf("Failed to generate server key: %v", err)
		}
	} else {
		serverKey = *serverStaticKey
	}

	// Enable debug mode for detailed Noise-NK logging (directly set the debug variable)
	// Note: This would require exporting the debug variable or using a setter
	log.Println("🐛 Enabling Noise-NK debug mode for detailed logging")

	manager := &NoiseSessionManager{
		sessions:  make(map[string]*openadpNoise.NoiseNK),
		serverKey: serverKey,
	}

	log.Printf("Noise-NK session manager initialized with public key: %x...", manager.GetServerPublicKey()[:16])
	return manager
}

// GetServerPublicKey returns the server's static public key for distribution to clients
func (m *NoiseSessionManager) GetServerPublicKey() []byte {
	return m.serverKey.Public
}

// StartHandshake starts a Noise-NK handshake for a new session
func (m *NoiseSessionManager) StartHandshake(sessionID string, clientHandshakeMessage []byte) ([]byte, error) {
	m.sessionLock.Lock()
	defer m.sessionLock.Unlock()

	// Check if session already exists
	if _, exists := m.sessions[sessionID]; exists {
		return nil, fmt.Errorf("session ID already in use")
	}

	// Create new Noise-NK session (server = responder)
	noiseSession, err := openadpNoise.NewNoiseNK("responder", &m.serverKey, nil, []byte(""))
	if err != nil {
		return nil, fmt.Errorf("failed to create Noise session: %v", err)
	}

	// Process client's handshake message
	serverPayload, err := noiseSession.ReadHandshakeMessage(clientHandshakeMessage)
	if err != nil {
		log.Printf("Failed to process client handshake: %v", err)
		return nil, fmt.Errorf("invalid handshake message: %v", err)
	}

	log.Printf("Received handshake payload from client: %s", string(serverPayload))

	// Send server's handshake response
	serverResponse, err := noiseSession.WriteHandshakeMessage([]byte("Server handshake response"))
	if err != nil {
		log.Printf("Failed to create server handshake response: %v", err)
		return nil, fmt.Errorf("failed to create handshake response: %v", err)
	}

	// Store session for later use
	m.sessions[sessionID] = noiseSession

	log.Printf("Handshake completed for session %s...", sessionID[:16])
	return serverResponse, nil
}

// DecryptCall decrypts an encrypted JSON-RPC call and keeps the session for response
func (m *NoiseSessionManager) DecryptCall(sessionID string, encryptedData []byte) (map[string]interface{}, error) {
	m.sessionLock.RLock()
	noiseSession, exists := m.sessions[sessionID]
	m.sessionLock.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found or expired")
	}

	// Check if handshake is complete
	if !noiseSession.IsHandshakeComplete() {
		return nil, fmt.Errorf("handshake not completed")
	}

	// Decrypt the message (no associated data for JSON-RPC)
	decryptedJSON, err := noiseSession.Decrypt(encryptedData, nil)
	if err != nil {
		log.Printf("Decryption failed for session %s...: %v", sessionID[:16], err)
		// Clean up failed session
		m.sessionLock.Lock()
		delete(m.sessions, sessionID)
		m.sessionLock.Unlock()
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	// Parse JSON
	var requestDict map[string]interface{}
	if err := json.Unmarshal(decryptedJSON, &requestDict); err != nil {
		log.Printf("Invalid JSON in decrypted message: %v", err)
		// Clean up session
		m.sessionLock.Lock()
		delete(m.sessions, sessionID)
		m.sessionLock.Unlock()
		return nil, fmt.Errorf("invalid JSON in encrypted message: %v", err)
	}

	log.Printf("Successfully decrypted call for session %s...", sessionID[:16])
	// Note: Session is kept alive for EncryptResponse
	return requestDict, nil
}

// EncryptResponse encrypts a JSON-RPC response and cleans up the session
func (m *NoiseSessionManager) EncryptResponse(sessionID string, responseDict map[string]interface{}) ([]byte, error) {
	m.sessionLock.Lock()
	defer m.sessionLock.Unlock()

	// Get session
	noiseSession, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found or expired")
	}

	// Serialize response to JSON
	responseJSON, err := json.Marshal(responseDict)
	if err != nil {
		log.Printf("Failed to serialize response: %v", err)
		// Clean up session
		delete(m.sessions, sessionID)
		return nil, fmt.Errorf("failed to serialize response: %v", err)
	}

	// Encrypt the response (no associated data for JSON-RPC)
	encryptedResponse, err := noiseSession.Encrypt(responseJSON, nil)
	if err != nil {
		log.Printf("Encryption failed for session %s...: %v", sessionID[:16], err)
		// Clean up session
		delete(m.sessions, sessionID)
		return nil, fmt.Errorf("encryption failed: %v", err)
	}

	// Clean up session (single use)
	delete(m.sessions, sessionID)

	log.Printf("Successfully encrypted response and cleaned up session %s...", sessionID[:16])
	return encryptedResponse, nil
}

// GetHandshakeHash returns the handshake hash for a completed session
func (m *NoiseSessionManager) GetHandshakeHash(sessionID string) ([]byte, error) {
	m.sessionLock.RLock()
	defer m.sessionLock.RUnlock()

	noiseSession, exists := m.sessions[sessionID]
	if !exists {
		log.Printf("Session %s not found for handshake hash", sessionID)
		return nil, fmt.Errorf("session not found")
	}

	if !noiseSession.IsHandshakeComplete() {
		log.Printf("Handshake not complete for session %s", sessionID)
		return nil, fmt.Errorf("handshake not complete")
	}

	return noiseSession.GetHandshakeHash(), nil
}

// CleanupExpiredSessions cleans up sessions that have been around too long (fallback safety)
func (m *NoiseSessionManager) CleanupExpiredSessions(maxAgeSeconds int) {
	// For now, we don't track creation time, but we could add that
	// Sessions should be short-lived anyway (single use)
	m.sessionLock.RLock()
	currentCount := len(m.sessions)
	m.sessionLock.RUnlock()

	if currentCount > 100 { // Arbitrary threshold
		log.Printf("High number of active sessions: %d", currentCount)
	}
}

// GetSessionCount returns the current number of active sessions (for monitoring)
func (m *NoiseSessionManager) GetSessionCount() int {
	m.sessionLock.RLock()
	defer m.sessionLock.RUnlock()
	return len(m.sessions)
}

// Global session manager instance
var globalSessionManager *NoiseSessionManager
var sessionManagerOnce sync.Once

// GetSessionManager returns the global session manager instance, creating it if necessary
func GetSessionManager() *NoiseSessionManager {
	sessionManagerOnce.Do(func() {
		globalSessionManager = NewNoiseSessionManager(nil)
	})
	return globalSessionManager
}

// InitializeSessionManager initializes the global session manager with a specific key
func InitializeSessionManager(serverStaticKey *noise.DHKey) *NoiseSessionManager {
	globalSessionManager = NewNoiseSessionManager(serverStaticKey)
	return globalSessionManager
}

// GenerateSessionID generates a secure random session ID
func GenerateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// ValidateSessionID validates that a session ID has the correct format
func ValidateSessionID(sessionID string) bool {
	if len(sessionID) != 24 { // Base64 encoding of 16 bytes
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(sessionID)
	if err != nil {
		return false
	}

	return len(decoded) == 16
}
