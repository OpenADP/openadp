package common

import (
	"encoding/hex"
	"io"
	"testing"

	"github.com/flynn/noise"
)

// DeterministicReader implements io.Reader to provide deterministic "random" data
type DeterministicReader struct {
	data []byte
	pos  int
}

func NewDeterministicReader(data []byte) *DeterministicReader {
	return &DeterministicReader{data: data, pos: 0}
}

func (dr *DeterministicReader) Read(p []byte) (n int, err error) {
	if dr.pos >= len(dr.data) {
		return 0, io.EOF
	}

	n = copy(p, dr.data[dr.pos:])
	dr.pos += n
	return n, nil
}

// TestDeterministicNoiseNK tests deterministic Noise-NK handshake message generation
// This test ensures that given the same keys and random data, the handshake messages
// are identical between Go and Python implementations, validating cross-language compatibility.
func TestDeterministicNoiseNK(t *testing.T) {
	t.Log("🔐 Deterministic Noise-NK Handshake Message Test (Go)")
	t.Log("======================================================")

	// Fixed keys for deterministic testing (32 bytes each)
	// These should match the Python implementation exactly
	serverStaticPrivateHex := "7bb864b489efa3b78c2c63e98cb1c0b4c4b0e8e1e1f3e4d4c1b0a9d8c7b6a5b4"
	serverStaticPublicHex := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	clientEphemeralPrivateHex := "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"

	// Server static private key is only shown for reference
	_, err := hex.DecodeString(serverStaticPrivateHex)
	if err != nil {
		t.Fatalf("failed to decode server static private key: %v", err)
	}

	serverStaticPublic, err := hex.DecodeString(serverStaticPublicHex)
	if err != nil {
		t.Fatalf("failed to decode server static public key: %v", err)
	}

	clientEphemeralPrivate, err := hex.DecodeString(clientEphemeralPrivateHex)
	if err != nil {
		t.Fatalf("failed to decode client ephemeral private key: %v", err)
	}

	t.Logf("Server static private: %s", serverStaticPrivateHex)
	t.Logf("Server static public:  %s", serverStaticPublicHex)
	t.Logf("Client ephemeral private: %s", clientEphemeralPrivateHex)

	// Test payload
	clientPayload := []byte("Hello from client")

	// Create Noise config for client (initiator)
	t.Log("🔧 Creating client (initiator)...")

	// Create deterministic reader for ephemeral key generation
	// The flynn/noise library will use this for generating ephemeral keys
	deterministicReader := NewDeterministicReader(clientEphemeralPrivate)

	clientConfig := noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Random:      deterministicReader,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		Prologue:    []byte(""),
		PeerStatic:  serverStaticPublic,
	}

	// Create handshake state
	clientHandshake, err := noise.NewHandshakeState(clientConfig)
	if err != nil {
		t.Fatalf("failed to create client handshake state: %v", err)
	}

	t.Log("✅ Client initialized")

	// Step 1: Client creates handshake message
	t.Log("📤 Step 1: Client creates handshake message...")
	handshakeMsg1, _, _, err := clientHandshake.WriteMessage(nil, clientPayload)
	if err != nil {
		t.Fatalf("failed to write handshake message: %v", err)
	}

	t.Logf("   Client handshake message (%d bytes):", len(handshakeMsg1))
	t.Logf("   %x", handshakeMsg1)
	t.Logf("   Client payload: %s", string(clientPayload))

	// Break down the message structure for analysis
	t.Log("📋 Message Structure Analysis:")
	t.Log("   NK pattern first message: -> e, es")
	t.Log("   Expected: [ephemeral_key(32)] + [encrypted_payload(?)]")

	if len(handshakeMsg1) >= 32 {
		ephemeralKey := handshakeMsg1[:32]
		encryptedPayload := handshakeMsg1[32:]
		t.Logf("   Ephemeral key (32 bytes): %x", ephemeralKey)
		t.Logf("   Encrypted payload (%d bytes): %x", len(encryptedPayload), encryptedPayload)

		// Verify the expected deterministic output
		expectedMessage := "04ca7d443adb3e04a5a498e3a95a0bd0db7cf8b9c948103a0a81b2d7316e9c74dc292a3b9fedcc287a03207e1f936a12c4bcaaaa87551f0f39485ba4afb3dcb014"
		actualMessage := hex.EncodeToString(handshakeMsg1)

		if actualMessage == expectedMessage {
			t.Log("✅ Handshake message matches expected deterministic output")
		} else {
			t.Errorf("❌ Handshake message mismatch!")
			t.Errorf("   Expected: %s", expectedMessage)
			t.Errorf("   Actual:   %s", actualMessage)
		}
	} else {
		t.Errorf("⚠️  Message too short: %d bytes", len(handshakeMsg1))
	}

	t.Log("🎉 Test completed!")
}
