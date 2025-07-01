// Package noise provides Noise-NK protocol implementation for OpenADP.
package common

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/flynn/noise"
)

// Global debug mode flag and state for noise operations
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

// SetDebugMode enables or disables debug mode for Noise-NK operations
func SetDebugMode(enabled bool) {
	debugMutex.Lock()
	defer debugMutex.Unlock()

	debugMode = enabled
	deterministicCounter = 0 // Reset counter when enabling/disabling

	if enabled {
		log.Println("🐛 Debug mode enabled - using deterministic ephemeral keys")
	} else {
		log.Println("Debug mode disabled - using random ephemeral keys")
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

// NoiseNK represents a Noise-NK protocol handler
type NoiseNK struct {
	role              string
	isInitiator       bool
	prologue          []byte
	handshakeComplete bool
	localStaticKey    noise.DHKey
	remoteStaticKey   []byte
	handshakeState    *noise.HandshakeState
	sendCipher        *noise.CipherState
	recvCipher        *noise.CipherState
	handshakeHash     []byte
	readMessage       bool
	wroteMessage      bool
}

// DebugRandomReader provides deterministic randomness for debug mode
type DebugRandomReader struct {
	ephemeralSecret []byte
	used            bool
}

// Read implements io.Reader for deterministic randomness
func (dr *DebugRandomReader) Read(p []byte) (int, error) {
	if IsDebugModeEnabled() && !dr.used && len(p) >= 32 {
		// Use deterministic ephemeral secret for the first 32 bytes (X25519 key)
		dr.ephemeralSecret = GetDeterministicEphemeralSecret()
		copy(p[:32], dr.ephemeralSecret)
		dr.used = true

		// Fill the rest with zeros if needed
		for i := 32; i < len(p); i++ {
			p[i] = 0
		}

		return len(p), nil
	}

	// Fall back to secure random for non-debug mode or subsequent reads
	return rand.Read(p)
}

// NewNoiseNK creates a new Noise-NK endpoint
func NewNoiseNK(role string, localStaticKey *noise.DHKey, remoteStaticKey []byte, prologue []byte) (*NoiseNK, error) {
	if role != "initiator" && role != "responder" {
		return nil, errors.New("role must be 'initiator' or 'responder'")
	}

	nk := &NoiseNK{
		role:        role,
		isInitiator: role == "initiator",
		prologue:    prologue,
	}

	// In NK pattern, only responder has a static key
	if nk.isInitiator {
		// Initiator has no static key, only needs responder's public key
		if remoteStaticKey == nil {
			return nil, errors.New("initiator must provide responder's static public key")
		}
		nk.remoteStaticKey = remoteStaticKey
	} else {
		// Responder must have a static key
		if localStaticKey == nil {
			// Generate a new key pair if none provided
			keypair, err := noise.DH25519.GenerateKeypair(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("failed to generate keypair: %v", err)
			}
			nk.localStaticKey = keypair
		} else {
			nk.localStaticKey = *localStaticKey
		}
	}

	// Initialize handshake
	if err := nk.initializeHandshake(); err != nil {
		return nil, err
	}

	return nk, nil
}

// initializeHandshake initializes the handshake state with NK pattern
func (nk *NoiseNK) initializeHandshake() error {
	// Create random reader (deterministic in debug mode)
	var randomReader io.Reader
	if IsDebugModeEnabled() {
		randomReader = &DebugRandomReader{}
	} else {
		randomReader = rand.Reader
	}

	// Create Noise config for NK pattern
	config := noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Random:      randomReader,
		Pattern:     noise.HandshakeNK,
		Initiator:   nk.isInitiator,
		Prologue:    nk.prologue,
	}

	// Set static keys based on role
	if nk.isInitiator {
		// Initiator only has remote static key
		config.PeerStatic = nk.remoteStaticKey
	} else {
		// Responder has local static key
		config.StaticKeypair = nk.localStaticKey
	}

	// Create handshake state
	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return fmt.Errorf("failed to create handshake state: %v", err)
	}

	nk.handshakeState = hs
	return nil
}

// GetPublicKey returns this party's static public key as bytes
func (nk *NoiseNK) GetPublicKey() []byte {
	if nk.isInitiator {
		return nil // Initiator has no static key in NK pattern
	}
	return nk.localStaticKey.Public
}

// SetRemotePublicKey sets the remote party's static public key and reinitializes handshake
func (nk *NoiseNK) SetRemotePublicKey(remotePublicKey []byte) error {
	nk.remoteStaticKey = remotePublicKey
	return nk.initializeHandshake()
}

// WriteHandshakeMessage writes the next handshake message
func (nk *NoiseNK) WriteHandshakeMessage(payload []byte) ([]byte, error) {
	if nk.handshakeComplete {
		return nil, errors.New("handshake is already complete")
	}

	message, cs1, cs2, err := nk.handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to write handshake message: %v", err)
	}

	// Track that we wrote a message
	nk.wroteMessage = true

	// Check if handshake is complete (cipher states returned)
	if cs1 != nil && cs2 != nil {
		nk.finalizeHandshakeWithCiphers(cs1, cs2)
	}

	return message, nil
}

// ReadHandshakeMessage reads and processes a handshake message from the other party
func (nk *NoiseNK) ReadHandshakeMessage(message []byte) ([]byte, error) {
	if nk.handshakeComplete {
		return nil, errors.New("handshake is already complete")
	}

	payload, cs1, cs2, err := nk.handshakeState.ReadMessage(nil, message)
	if err != nil {
		return nil, fmt.Errorf("failed to read handshake message: %v", err)
	}

	// Track that we read a message
	nk.readMessage = true

	// Check if handshake is complete (cipher states returned)
	if cs1 != nil && cs2 != nil {
		nk.finalizeHandshakeWithCiphers(cs1, cs2)
	}

	return payload, nil
}

// finalizeHandshakeWithCiphers finalizes the handshake with provided cipher states
func (nk *NoiseNK) finalizeHandshakeWithCiphers(cs1, cs2 *noise.CipherState) {
	// The cipher pairing depends on role:
	// Initiator: cs1 for sending, cs2 for receiving
	// Responder: cs1 for receiving, cs2 for sending
	if nk.isInitiator {
		nk.sendCipher = cs1
		nk.recvCipher = cs2

		if debugMode {
			log.Printf("🔑 GO INITIATOR: Transport key assignment complete")
			log.Printf("  - sendCipher: cs1 (initiator->responder)")
			log.Printf("  - recvCipher: cs2 (responder->initiator)")
			log.Printf("  - Go uses sendCipher for encrypt, recvCipher for decrypt (initiator)")

			// Log transport key information (what we can access)
			log.Printf("🔑 GO INITIATOR: Transport cipher information")

			// Use UnsafeKey() method to extract actual keys for debugging
			var sendKey, recvKey []byte
			if cs1 != nil {
				sendKeyArray := cs1.UnsafeKey()
				sendKey = sendKeyArray[:]
			}
			if cs2 != nil {
				recvKeyArray := cs2.UnsafeKey()
				recvKey = recvKeyArray[:]
			}

			// Log the actual keys (only if they're real keys, not placeholders)
			if len(sendKey) > 0 && string(sendKey) != "send_key_not_accessible" {
				log.Printf("  - send key: %x", sendKey)
			} else {
				log.Printf("  - send key: not accessible")
			}
			if len(recvKey) > 0 && string(recvKey) != "recv_key_not_accessible" {
				log.Printf("  - recv key: %x", recvKey)
			} else {
				log.Printf("  - recv key: not accessible")
			}
		}
	} else {
		nk.sendCipher = cs2
		nk.recvCipher = cs1

		if debugMode {
			log.Printf("🔑 GO RESPONDER: Transport key assignment complete")
			log.Printf("  - sendCipher: cs2 (responder->initiator)")
			log.Printf("  - recvCipher: cs1 (initiator->responder)")
			log.Printf("  - Go uses sendCipher for encrypt, recvCipher for decrypt (responder)")

			// Log transport key information (what we can access)
			log.Printf("🔑 GO RESPONDER: Transport cipher information")

			// Use UnsafeKey() method to extract actual keys for debugging
			var sendKey, recvKey []byte
			if cs2 != nil {
				sendKeyArray := cs2.UnsafeKey()
				sendKey = sendKeyArray[:]
			}
			if cs1 != nil {
				recvKeyArray := cs1.UnsafeKey()
				recvKey = recvKeyArray[:]
			}

			// Log the actual keys (only if they're real keys, not placeholders)
			if len(sendKey) > 0 && string(sendKey) != "send_key_not_accessible" {
				log.Printf("  - send key: %x", sendKey)
			} else {
				log.Printf("  - send key: not accessible")
			}
			if len(recvKey) > 0 && string(recvKey) != "recv_key_not_accessible" {
				log.Printf("  - recv key: %x", recvKey)
			} else {
				log.Printf("  - recv key: not accessible")
			}
		}
	}

	nk.handshakeComplete = true
	nk.handshakeHash = nk.handshakeState.ChannelBinding()
}

// Encrypt encrypts a message (post-handshake)
func (nk *NoiseNK) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	if !nk.handshakeComplete {
		return nil, errors.New("handshake must be completed before encrypting messages")
	}

	if debugMode {
		log.Printf("🔐 GO TRANSPORT ENCRYPT")
		log.Printf("  - plaintext length: %d", len(plaintext))
		log.Printf("  - plaintext hex: %x", plaintext)
		log.Printf("  - AAD length: %d", len(associatedData))
		log.Printf("  - AAD hex: %x", associatedData)
	}

	encrypted, err := nk.sendCipher.Encrypt(nil, associatedData, plaintext)

	if debugMode {
		if err == nil {
			log.Printf("  - encrypted length: %d", len(encrypted))
			log.Printf("  - encrypted hex: %x", encrypted)
		} else {
			log.Printf("  - encryption failed: %v", err)
		}
	}

	return encrypted, err
}

// Decrypt decrypts a message (post-handshake)
func (nk *NoiseNK) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	if !nk.handshakeComplete {
		return nil, errors.New("handshake must be completed before decrypting messages")
	}

	if debugMode {
		log.Printf("🔓 GO TRANSPORT DECRYPT")
		log.Printf("  - ciphertext length: %d", len(ciphertext))
		log.Printf("  - ciphertext hex: %x", ciphertext)
		log.Printf("  - AAD length: %d", len(associatedData))
		log.Printf("  - AAD hex: %x", associatedData)
	}

	decrypted, err := nk.recvCipher.Decrypt(nil, associatedData, ciphertext)

	if debugMode {
		if err == nil {
			log.Printf("  - decrypted length: %d", len(decrypted))
			log.Printf("  - decrypted hex: %x", decrypted)
		} else {
			log.Printf("  - decryption failed: %v", err)
		}
	}

	return decrypted, err
}

// GetHandshakeHash returns the handshake hash for channel binding
func (nk *NoiseNK) GetHandshakeHash() []byte {
	return nk.handshakeHash
}

// IsHandshakeComplete returns whether the handshake is complete
func (nk *NoiseNK) IsHandshakeComplete() bool {
	return nk.handshakeComplete
}

// GetTransportKeys returns the actual transport keys for debugging
func (nk *NoiseNK) GetTransportKeys() ([]byte, []byte) {
	if !nk.handshakeComplete {
		return []byte("handshake_not_complete"), []byte("handshake_not_complete")
	}

	// Try to extract actual keys from cipher states
	var sendKey, recvKey []byte

	// Use UnsafeKey() method to access the k field from CipherState
	// This is for debugging purposes only
	if nk.sendCipher != nil {
		sendKeyArray := nk.sendCipher.UnsafeKey()
		sendKey = sendKeyArray[:]
	}

	if nk.recvCipher != nil {
		recvKeyArray := nk.recvCipher.UnsafeKey()
		recvKey = recvKeyArray[:]
	}

	// Fallback to placeholder if UnsafeKey() fails
	if len(sendKey) == 0 {
		sendKey = []byte("send_key_not_accessible")
	}
	if len(recvKey) == 0 {
		recvKey = []byte("recv_key_not_accessible")
	}

	return sendKey, recvKey
}

// GenerateKeypair generates a new X25519 keypair for Noise-NK
func GenerateKeypair() (noise.DHKey, error) {
	return noise.DH25519.GenerateKeypair(rand.Reader)
}

// TestNoiseNK runs a basic test of the Noise-NK implementation
func TestNoiseNK() error {
	// Generate server keypair
	serverKey, err := GenerateKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate server key: %v", err)
	}

	// Create client and server
	client, err := NewNoiseNK("initiator", nil, serverKey.Public, []byte(""))
	if err != nil {
		return fmt.Errorf("failed to create client: %v", err)
	}

	server, err := NewNoiseNK("responder", &serverKey, nil, []byte(""))
	if err != nil {
		return fmt.Errorf("failed to create server: %v", err)
	}

	// Perform handshake
	msg1, err := client.WriteHandshakeMessage([]byte("Hello Server"))
	if err != nil {
		return fmt.Errorf("client handshake write failed: %v", err)
	}

	response1, err := server.ReadHandshakeMessage(msg1)
	if err != nil {
		return fmt.Errorf("server handshake read failed: %v", err)
	}

	msg2, err := server.WriteHandshakeMessage([]byte("Hello Client"))
	if err != nil {
		return fmt.Errorf("server handshake write failed: %v", err)
	}

	response2, err := client.ReadHandshakeMessage(msg2)
	if err != nil {
		return fmt.Errorf("client handshake read failed: %v", err)
	}

	// Verify handshake payloads
	if string(response1) != "Hello Server" {
		return fmt.Errorf("unexpected server response: %s", response1)
	}
	if string(response2) != "Hello Client" {
		return fmt.Errorf("unexpected client response: %s", response2)
	}

	// Test encryption/decryption
	plaintext := []byte("Secret message")
	encrypted, err := client.Encrypt(plaintext, nil)
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	decrypted, err := server.Decrypt(encrypted, nil)
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		return fmt.Errorf("decryption mismatch: expected %s, got %s", plaintext, decrypted)
	}

	return nil
}
