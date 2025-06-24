// Package noise provides Noise-NK protocol implementation for OpenADP.
package common

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/flynn/noise"
)

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
	// Create Noise config for NK pattern
	config := noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Random:      rand.Reader,
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
	} else {
		nk.sendCipher = cs2
		nk.recvCipher = cs1
	}

	nk.handshakeComplete = true
	nk.handshakeHash = nk.handshakeState.ChannelBinding()
}

// Encrypt encrypts a message (post-handshake)
func (nk *NoiseNK) Encrypt(plaintext []byte, associatedData []byte) ([]byte, error) {
	if !nk.handshakeComplete {
		return nil, errors.New("handshake must be completed before encrypting messages")
	}

	return nk.sendCipher.Encrypt(nil, associatedData, plaintext)
}

// Decrypt decrypts a message (post-handshake)
func (nk *NoiseNK) Decrypt(ciphertext []byte, associatedData []byte) ([]byte, error) {
	if !nk.handshakeComplete {
		return nil, errors.New("handshake must be completed before decrypting messages")
	}

	return nk.recvCipher.Decrypt(nil, associatedData, ciphertext)
}

// GetHandshakeHash returns the handshake hash for channel binding
func (nk *NoiseNK) GetHandshakeHash() []byte {
	return nk.handshakeHash
}

// IsHandshakeComplete returns whether the handshake is complete
func (nk *NoiseNK) IsHandshakeComplete() bool {
	return nk.handshakeComplete
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
