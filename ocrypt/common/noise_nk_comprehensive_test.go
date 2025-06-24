package common

import (
	"bytes"
	"testing"
)

// TestNoiseNKInitialization tests NoiseNK initialization with different parameters
func TestNoiseNKInitialization(t *testing.T) {
	// Generate test keypair for responder
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Test initiator
	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	if !initiator.isInitiator {
		t.Error("Initiator should have isInitiator=true")
	}
	if initiator.role != "initiator" {
		t.Errorf("Expected role 'initiator', got %s", initiator.role)
	}
	if initiator.handshakeComplete {
		t.Error("Handshake should not be complete initially")
	}

	// Test responder
	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	if responder.isInitiator {
		t.Error("Responder should have isInitiator=false")
	}
	if responder.role != "responder" {
		t.Errorf("Expected role 'responder', got %s", responder.role)
	}
	if responder.handshakeComplete {
		t.Error("Handshake should not be complete initially")
	}
}

// TestNoiseNKHandshakeCompleteFlow tests complete Noise-NK handshake flow
func TestNoiseNKHandshakeCompleteFlow(t *testing.T) {
	// Generate keypair for responder
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Initialize parties
	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	testMessage := []byte("Hello, secure world!")

	// Step 1: Initiator sends handshake message
	handshakeMsg, err := initiator.WriteHandshakeMessage(testMessage)
	if err != nil {
		t.Fatalf("Initiator failed to write handshake message: %v", err)
	}
	if len(handshakeMsg) <= len(testMessage) {
		t.Error("Handshake message should be larger than payload")
	}

	// Step 2: Responder processes handshake message
	receivedPayload, err := responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Responder failed to read handshake message: %v", err)
	}
	if !bytes.Equal(receivedPayload, testMessage) {
		t.Errorf("Received payload doesn't match sent payload")
	}

	// Step 3: Responder sends response
	responsePayload := []byte("Response payload")
	responseMsg, err := responder.WriteHandshakeMessage(responsePayload)
	if err != nil {
		t.Fatalf("Responder failed to write handshake message: %v", err)
	}

	// Step 4: Initiator processes response
	receivedResponse, err := initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Initiator failed to read handshake message: %v", err)
	}
	if !bytes.Equal(receivedResponse, responsePayload) {
		t.Errorf("Received response doesn't match sent response")
	}

	// Both sides should now have completed handshake
	if !initiator.IsHandshakeComplete() {
		t.Error("Initiator handshake should be complete")
	}
	if !responder.IsHandshakeComplete() {
		t.Error("Responder handshake should be complete")
	}
}

// TestNoiseNKTransportMessages tests transport message encryption/decryption after handshake
func TestNoiseNKTransportMessages(t *testing.T) {
	// Complete handshake first
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Handshake
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte("init"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	responseMsg, err := responder.WriteHandshakeMessage([]byte("resp"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Test transport messages
	testMessages := [][]byte{
		[]byte("First transport message"),
		[]byte(""),                      // Empty message
		bytes.Repeat([]byte("X"), 1000), // Large message
		[]byte{0x00, 0x01, 0x02, 0x03},  // Binary data
	}

	for i, msg := range testMessages {
		t.Run("message_"+string(rune(i+'0')), func(t *testing.T) {
			// Initiator -> Responder
			encrypted, err := initiator.Encrypt(msg, nil)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			if len(msg) > 0 && bytes.Equal(encrypted, msg) {
				t.Error("Encrypted message should be different from plaintext")
			}

			decrypted, err := responder.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}
			if !bytes.Equal(decrypted, msg) {
				t.Error("Decrypted message doesn't match original")
			}

			// Responder -> Initiator
			encryptedResp, err := responder.Encrypt(msg, nil)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			if len(msg) > 0 && bytes.Equal(encryptedResp, msg) {
				t.Error("Encrypted message should be different from plaintext")
			}

			decryptedResp, err := initiator.Decrypt(encryptedResp, nil)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}
			if !bytes.Equal(decryptedResp, msg) {
				t.Error("Decrypted message doesn't match original")
			}
		})
	}
}

// TestNoiseNKHandshakeEdgeCases tests handshake edge cases and error conditions
func TestNoiseNKHandshakeEdgeCases(t *testing.T) {
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Test with empty payload
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte(""))
	if err != nil {
		t.Fatalf("Failed to write handshake message with empty payload: %v", err)
	}
	receivedPayload, err := responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Failed to read handshake message with empty payload: %v", err)
	}
	if !bytes.Equal(receivedPayload, []byte("")) {
		t.Error("Empty payload should be preserved")
	}

	// Test with large payload
	largePayload := bytes.Repeat([]byte("L"), 5000)
	responseMsg, err := responder.WriteHandshakeMessage(largePayload)
	if err != nil {
		t.Fatalf("Failed to write handshake message with large payload: %v", err)
	}
	responsePayload, err := initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Failed to read handshake message with large payload: %v", err)
	}
	if !bytes.Equal(responsePayload, largePayload) {
		t.Error("Large payload should be preserved")
	}
}

// TestNoiseNKInvalidInitialization tests invalid initialization parameters
func TestNoiseNKInvalidInitialization(t *testing.T) {
	// Test invalid role
	_, err := NewNoiseNK("invalid_role", nil, nil, nil)
	if err == nil {
		t.Error("Expected error for invalid role")
	}

	// Test initiator without remote static key
	_, err = NewNoiseNK("initiator", nil, nil, nil)
	if err == nil {
		t.Error("Expected error for initiator without remote static key")
	}
}

// TestNoiseNKTransportBeforeHandshake tests that transport messages fail before handshake completion
func TestNoiseNKTransportBeforeHandshake(t *testing.T) {
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	// Try to encrypt before handshake
	_, err = initiator.Encrypt([]byte("premature message"), nil)
	if err == nil {
		t.Error("Expected error when encrypting before handshake")
	}

	// Try to decrypt before handshake
	_, err = initiator.Decrypt([]byte("fake_ciphertext"), nil)
	if err == nil {
		t.Error("Expected error when decrypting before handshake")
	}
}

// TestNoiseNKKeypairGeneration tests keypair generation
func TestNoiseNKKeypairGeneration(t *testing.T) {
	keypair1, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	if keypair1.Public == nil {
		t.Error("Public key should not be nil")
	}
	if keypair1.Private == nil {
		t.Error("Private key should not be nil")
	}
	if len(keypair1.Public) != 32 {
		t.Errorf("Public key should be 32 bytes, got %d", len(keypair1.Public))
	}

	// Test that generated keys are different
	keypair2, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate second keypair: %v", err)
	}
	if bytes.Equal(keypair1.Public, keypair2.Public) {
		t.Error("Generated keypairs should be different")
	}
}

// TestNoiseNKPublicKeyOperations tests public key operations
func TestNoiseNKPublicKeyOperations(t *testing.T) {
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	publicKey := responder.GetPublicKey()
	if publicKey == nil {
		t.Error("Public key should not be nil")
	}
	if len(publicKey) != 32 {
		t.Errorf("X25519 public keys should be 32 bytes, got %d", len(publicKey))
	}

	// Test initiator (should return nil)
	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}
	initiatorKey := initiator.GetPublicKey()
	if initiatorKey != nil {
		t.Error("Initiator should not have a public key in NK pattern")
	}
}

// TestNoiseNKSetRemotePublicKey tests setting remote public key
func TestNoiseNKSetRemotePublicKey(t *testing.T) {
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Generate another keypair for testing
	testKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate test keypair: %v", err)
	}

	// Set remote public key using bytes
	err = responder.SetRemotePublicKey(testKeypair.Public)
	if err != nil {
		t.Errorf("Failed to set remote public key: %v", err)
	}
}

// TestNoiseNKHandshakeHash tests handshake hash generation
func TestNoiseNKHandshakeHash(t *testing.T) {
	// Complete handshake
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Handshake
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte("init"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	responseMsg, err := responder.WriteHandshakeMessage([]byte("resp"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Get handshake hashes
	initHash := initiator.GetHandshakeHash()
	respHash := responder.GetHandshakeHash()

	// Both parties should have the same handshake hash
	if !bytes.Equal(initHash, respHash) {
		t.Error("Both parties should have the same handshake hash")
	}
	if len(initHash) == 0 {
		t.Error("Handshake hash should not be empty")
	}
}

// TestNoiseNKBidirectionalCommunication tests bidirectional communication after handshake
func TestNoiseNKBidirectionalCommunication(t *testing.T) {
	// Complete handshake
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Handshake
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte("init"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	responseMsg, err := responder.WriteHandshakeMessage([]byte("resp"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Test multiple rounds of bidirectional communication
	for roundNum := 0; roundNum < 5; roundNum++ {
		t.Run("round_"+string(rune(roundNum+'0')), func(t *testing.T) {
			// Initiator -> Responder
			initMsg := []byte("Initiator message " + string(rune(roundNum+'0')))
			encryptedInit, err := initiator.Encrypt(initMsg, nil)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			decryptedInit, err := responder.Decrypt(encryptedInit, nil)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}
			if !bytes.Equal(decryptedInit, initMsg) {
				t.Error("Decrypted message doesn't match original")
			}

			// Responder -> Initiator
			respMsg := []byte("Responder message " + string(rune(roundNum+'0')))
			encryptedResp, err := responder.Encrypt(respMsg, nil)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			decryptedResp, err := initiator.Decrypt(encryptedResp, nil)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}
			if !bytes.Equal(decryptedResp, respMsg) {
				t.Error("Decrypted message doesn't match original")
			}
		})
	}
}

// TestNoiseNKStateIsolation tests that different Noise states are properly isolated
func TestNoiseNKStateIsolation(t *testing.T) {
	// Create multiple initiator-responder pairs
	type noisePair struct {
		initiator *NoiseNK
		responder *NoiseNK
	}

	var pairs []noisePair
	for i := 0; i < 3; i++ {
		respKeypair, err := GenerateKeypair()
		if err != nil {
			t.Fatalf("Failed to generate keypair: %v", err)
		}

		initiator, err := NewNoiseNK("initiator", nil, respKeypair.Public, nil)
		if err != nil {
			t.Fatalf("Failed to create initiator: %v", err)
		}

		responder, err := NewNoiseNK("responder", &respKeypair, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create responder: %v", err)
		}

		pairs = append(pairs, noisePair{initiator, responder})
	}

	// Complete handshakes for all pairs
	for i, pair := range pairs {
		initPayload := []byte("init" + string(rune(i+'0')))
		handshakeMsg, err := pair.initiator.WriteHandshakeMessage(initPayload)
		if err != nil {
			t.Fatalf("Handshake failed for pair %d: %v", i, err)
		}
		_, err = pair.responder.ReadHandshakeMessage(handshakeMsg)
		if err != nil {
			t.Fatalf("Handshake failed for pair %d: %v", i, err)
		}

		respPayload := []byte("resp" + string(rune(i+'0')))
		responseMsg, err := pair.responder.WriteHandshakeMessage(respPayload)
		if err != nil {
			t.Fatalf("Handshake failed for pair %d: %v", i, err)
		}
		_, err = pair.initiator.ReadHandshakeMessage(responseMsg)
		if err != nil {
			t.Fatalf("Handshake failed for pair %d: %v", i, err)
		}
	}

	// Test that messages from one pair can't be decrypted by another
	msg := []byte("secret message")
	encrypted0, err := pairs[0].initiator.Encrypt(msg, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Should decrypt correctly with matching responder
	decryptedCorrect, err := pairs[0].responder.Decrypt(encrypted0, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if !bytes.Equal(decryptedCorrect, msg) {
		t.Error("Decryption with correct responder failed")
	}

	// Should fail with wrong responder
	_, err = pairs[1].responder.Decrypt(encrypted0, nil)
	if err == nil {
		t.Error("Expected decryption to fail with wrong responder")
	}
}

// TestNoiseNKErrorRecovery tests error recovery and state consistency
func TestNoiseNKErrorRecovery(t *testing.T) {
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Complete handshake
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte("init"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	responseMsg, err := responder.WriteHandshakeMessage([]byte("resp"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Send a valid message
	validMsg := []byte("valid message")
	encryptedValid, err := initiator.Encrypt(validMsg, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	decryptedValid, err := responder.Decrypt(encryptedValid, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if !bytes.Equal(decryptedValid, validMsg) {
		t.Error("Valid message decryption failed")
	}

	// Try to decrypt corrupted message
	corruptedMsg := make([]byte, len(encryptedValid))
	copy(corruptedMsg, encryptedValid)
	if len(corruptedMsg) > 0 {
		corruptedMsg[len(corruptedMsg)-1] = 0x00 // Corrupt last byte
	}
	_, err = responder.Decrypt(corruptedMsg, nil)
	if err == nil {
		t.Error("Expected error when decrypting corrupted message")
	}

	// Verify that valid communication can continue after error
	anotherValidMsg := []byte("another valid message")
	encryptedAnother, err := initiator.Encrypt(anotherValidMsg, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	decryptedAnother, err := responder.Decrypt(encryptedAnother, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if !bytes.Equal(decryptedAnother, anotherValidMsg) {
		t.Error("Communication should continue after error")
	}
}

// TestNoiseNKPerformanceCharacteristics tests performance characteristics with various message sizes
func TestNoiseNKPerformanceCharacteristics(t *testing.T) {
	// Complete handshake
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Handshake
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte("init"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	responseMsg, err := responder.WriteHandshakeMessage([]byte("resp"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Test with various message sizes
	sizes := []int{0, 1, 16, 64, 256, 1024, 4096, 16384}

	for _, size := range sizes {
		t.Run("size_"+string(rune(size/1000+'0')), func(t *testing.T) {
			testMsg := bytes.Repeat([]byte("X"), size)
			encrypted, err := initiator.Encrypt(testMsg, nil)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			decrypted, err := responder.Decrypt(encrypted, nil)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}
			if !bytes.Equal(decrypted, testMsg) {
				t.Error("Decrypted message doesn't match original")
			}

			// Check that encryption adds reasonable overhead
			if size > 0 {
				overhead := len(encrypted) - len(testMsg)
				if overhead <= 0 {
					t.Error("Should have some encryption overhead")
				}
				if overhead > 100 {
					t.Errorf("Encryption overhead too large: %d bytes", overhead)
				}
			}
		})
	}
}

// TestNoiseNKPrologueHandling tests prologue handling
func TestNoiseNKPrologueHandling(t *testing.T) {
	prologue := []byte("test prologue data")

	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, prologue)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, prologue)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Should be able to complete handshake with matching prologues
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte("test"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	receivedPayload, err := responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	if !bytes.Equal(receivedPayload, []byte("test")) {
		t.Error("Received payload doesn't match sent payload")
	}
}

// TestNoiseNKHandshakeStateErrors tests handshake state error conditions
func TestNoiseNKHandshakeStateErrors(t *testing.T) {
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Complete handshake
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte("init"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	responseMsg, err := responder.WriteHandshakeMessage([]byte("resp"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Try to write handshake message after completion
	_, err = initiator.WriteHandshakeMessage([]byte("too late"))
	if err == nil {
		t.Error("Expected error when writing handshake message after completion")
	}

	// Try to read handshake message after completion
	_, err = responder.ReadHandshakeMessage([]byte("fake message"))
	if err == nil {
		t.Error("Expected error when reading handshake message after completion")
	}
}

// TestNoiseNKAssociatedDataEncryption tests encryption/decryption with associated data
func TestNoiseNKAssociatedDataEncryption(t *testing.T) {
	// Complete handshake
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Handshake
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte("init"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	responseMsg, err := responder.WriteHandshakeMessage([]byte("resp"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Test encryption with associated data
	plaintext := []byte("Secret message with associated data")
	associatedData := []byte("metadata_header")

	// Encrypt with associated data
	encrypted, err := initiator.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if bytes.Equal(encrypted, plaintext) {
		t.Error("Encrypted message should be different from plaintext")
	}

	// Decrypt with same associated data
	decrypted, err := responder.Decrypt(encrypted, associatedData)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted message doesn't match original")
	}

	// Try to decrypt with wrong associated data (should fail)
	wrongAssociatedData := []byte("wrong_metadata")
	_, err = responder.Decrypt(encrypted, wrongAssociatedData)
	if err == nil {
		t.Error("Expected error when decrypting with wrong associated data")
	}

	// Try to decrypt with no associated data when it was encrypted with some
	_, err = responder.Decrypt(encrypted, []byte(""))
	if err == nil {
		t.Error("Expected error when decrypting with wrong associated data")
	}
}

// TestNoiseNKMultipleMessageExchange tests multiple message exchange patterns
func TestNoiseNKMultipleMessageExchange(t *testing.T) {
	// Complete handshake
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Handshake
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte("init"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	responseMsg, err := responder.WriteHandshakeMessage([]byte("resp"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Test multiple message exchange (similar to the main function)
	messages := []struct {
		msg       []byte
		direction string
	}{
		{[]byte("Message 1"), "Client -> Server"},
		{[]byte("ACK 1"), "Server -> Client"},
		{[]byte("Message 2 with more data"), "Client -> Server"},
		{[]byte("Final ACK"), "Server -> Client"},
	}

	for i, msgInfo := range messages {
		t.Run("message_"+string(rune(i+'0')), func(t *testing.T) {
			var encrypted, decrypted []byte
			var err error

			if msgInfo.direction == "Client -> Server" {
				encrypted, err = initiator.Encrypt(msgInfo.msg, nil)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}
				decrypted, err = responder.Decrypt(encrypted, nil)
				if err != nil {
					t.Fatalf("Decryption failed: %v", err)
				}
			} else {
				encrypted, err = responder.Encrypt(msgInfo.msg, nil)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}
				decrypted, err = initiator.Decrypt(encrypted, nil)
				if err != nil {
					t.Fatalf("Decryption failed: %v", err)
				}
			}

			if !bytes.Equal(decrypted, msgInfo.msg) {
				t.Error("Decrypted message doesn't match original")
			}
		})
	}
}

// TestNoiseNKCipherStateProperties tests properties of cipher states after handshake
func TestNoiseNKCipherStateProperties(t *testing.T) {
	// Complete handshake
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Handshake
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte("init"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	responseMsg, err := responder.WriteHandshakeMessage([]byte("resp"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	_, err = initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	// Verify cipher states exist
	if initiator.sendCipher == nil {
		t.Error("Initiator send cipher should not be nil")
	}
	if initiator.recvCipher == nil {
		t.Error("Initiator recv cipher should not be nil")
	}
	if responder.sendCipher == nil {
		t.Error("Responder send cipher should not be nil")
	}
	if responder.recvCipher == nil {
		t.Error("Responder recv cipher should not be nil")
	}

	// Verify they are different objects
	if initiator.sendCipher == initiator.recvCipher {
		t.Error("Send and recv ciphers should be different")
	}
	if responder.sendCipher == responder.recvCipher {
		t.Error("Send and recv ciphers should be different")
	}
}

// TestNoiseNKHandshakeMessageTracking tests handshake message tracking attributes
func TestNoiseNKHandshakeMessageTracking(t *testing.T) {
	responderKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	initiator, err := NewNoiseNK("initiator", nil, responderKeypair.Public, nil)
	if err != nil {
		t.Fatalf("Failed to create initiator: %v", err)
	}

	responder, err := NewNoiseNK("responder", &responderKeypair, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Initially, message tracking should be false
	if initiator.wroteMessage {
		t.Error("Initiator should not have written message initially")
	}
	if initiator.readMessage {
		t.Error("Initiator should not have read message initially")
	}
	if responder.wroteMessage {
		t.Error("Responder should not have written message initially")
	}
	if responder.readMessage {
		t.Error("Responder should not have read message initially")
	}

	// After initiator writes message
	handshakeMsg, err := initiator.WriteHandshakeMessage([]byte("init"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	if !initiator.wroteMessage {
		t.Error("Initiator should have written message")
	}
	if initiator.readMessage {
		t.Error("Initiator should not have read message yet")
	}

	// After responder reads message
	_, err = responder.ReadHandshakeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	if !responder.readMessage {
		t.Error("Responder should have read message")
	}
	if responder.wroteMessage {
		t.Error("Responder should not have written message yet")
	}

	// After responder writes response
	responseMsg, err := responder.WriteHandshakeMessage([]byte("resp"))
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	if !responder.wroteMessage {
		t.Error("Responder should have written message")
	}
	if !responder.readMessage {
		t.Error("Responder should still have read message")
	}

	// After initiator reads response - handshake should be complete
	_, err = initiator.ReadHandshakeMessage(responseMsg)
	if err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}
	if !initiator.readMessage {
		t.Error("Initiator should have read message")
	}
	if !initiator.wroteMessage {
		t.Error("Initiator should still have written message")
	}
	if !initiator.IsHandshakeComplete() {
		t.Error("Initiator handshake should be complete")
	}
	if !responder.IsHandshakeComplete() {
		t.Error("Responder handshake should be complete")
	}
}
