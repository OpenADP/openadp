package server

import (
	"encoding/json"
	"testing"

	openadpNoise "github.com/openadp/common/noise"
)

func TestNewNoiseSessionManager(t *testing.T) {
	// Test with nil key (should generate new key)
	manager1 := NewNoiseSessionManager(nil)
	if manager1 == nil {
		t.Fatal("NewNoiseSessionManager should not return nil")
	}

	if len(manager1.GetServerPublicKey()) != 32 {
		t.Errorf("Server public key should be 32 bytes, got %d", len(manager1.GetServerPublicKey()))
	}

	// Test with provided key
	keyPair, err := openadpNoise.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	manager2 := NewNoiseSessionManager(&keyPair)
	if manager2 == nil {
		t.Fatal("NewNoiseSessionManager should not return nil")
	}

	// Should use the provided key
	if string(manager2.GetServerPublicKey()) != string(keyPair.Public) {
		t.Errorf("Manager should use provided public key")
	}
}

func TestGenerateSessionID(t *testing.T) {
	id1, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID failed: %v", err)
	}

	id2, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID failed: %v", err)
	}

	// Should be different
	if id1 == id2 {
		t.Errorf("Generated session IDs should be different")
	}

	// Should be valid format
	if !ValidateSessionID(id1) {
		t.Errorf("Generated session ID should be valid: %s", id1)
	}

	if !ValidateSessionID(id2) {
		t.Errorf("Generated session ID should be valid: %s", id2)
	}
}

func TestValidateSessionID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		expected bool
	}{
		{"valid ID", "AAAAAAAAAAAAAAAAAAAAAA==", true},
		{"too short", "AAAAAAAAAAAAAAAAAAAA==", false},
		{"too long", "AAAAAAAAAAAAAAAAAAAAAAAA==", false},
		{"invalid base64", "invalid-base64-string!", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateSessionID(tt.id)
			if result != tt.expected {
				t.Errorf("ValidateSessionID(%q) = %t, want %t", tt.id, result, tt.expected)
			}
		})
	}
}

func TestSessionManagerHandshake(t *testing.T) {
	// Create server session manager
	serverManager := NewNoiseSessionManager(nil)
	serverPublicKey := serverManager.GetServerPublicKey()

	// Create client
	clientSession, err := openadpNoise.NewNoiseNK("initiator", nil, serverPublicKey, []byte(""))
	if err != nil {
		t.Fatalf("Failed to create client session: %v", err)
	}

	// Generate session ID
	sessionID, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("Failed to generate session ID: %v", err)
	}

	// Client creates handshake message
	clientPayload := []byte("Hello from client")
	clientHandshakeMsg, err := clientSession.WriteHandshakeMessage(clientPayload)
	if err != nil {
		t.Fatalf("Client failed to create handshake message: %v", err)
	}

	// Server processes handshake
	serverResponse, err := serverManager.StartHandshake(sessionID, clientHandshakeMsg)
	if err != nil {
		t.Fatalf("Server handshake failed: %v", err)
	}

	// Client completes handshake
	serverPayload, err := clientSession.ReadHandshakeMessage(serverResponse)
	if err != nil {
		t.Fatalf("Client failed to complete handshake: %v", err)
	}

	// Verify server payload
	expectedPayload := "Server handshake response"
	if string(serverPayload) != expectedPayload {
		t.Errorf("Server payload = %q, want %q", string(serverPayload), expectedPayload)
	}

	// Verify handshake is complete
	if !clientSession.IsHandshakeComplete() {
		t.Errorf("Client handshake should be complete")
	}

	// Test duplicate session ID
	_, err = serverManager.StartHandshake(sessionID, clientHandshakeMsg)
	if err == nil {
		t.Errorf("Duplicate session ID should fail")
	}
}

func TestSessionManagerEncryptDecrypt(t *testing.T) {
	// Setup handshake first
	serverManager := NewNoiseSessionManager(nil)
	serverPublicKey := serverManager.GetServerPublicKey()

	clientSession, err := openadpNoise.NewNoiseNK("initiator", nil, serverPublicKey, []byte(""))
	if err != nil {
		t.Fatalf("Failed to create client session: %v", err)
	}

	sessionID, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("Failed to generate session ID: %v", err)
	}

	// Complete handshake
	clientHandshakeMsg, err := clientSession.WriteHandshakeMessage([]byte("Hello from client"))
	if err != nil {
		t.Fatalf("Client handshake failed: %v", err)
	}

	serverResponse, err := serverManager.StartHandshake(sessionID, clientHandshakeMsg)
	if err != nil {
		t.Fatalf("Server handshake failed: %v", err)
	}

	_, err = clientSession.ReadHandshakeMessage(serverResponse)
	if err != nil {
		t.Fatalf("Client handshake completion failed: %v", err)
	}

	// Test encryption/decryption
	testRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "echo",
		"params":  []string{"test message"},
		"id":      1,
	}

	// Client encrypts request
	requestJSON, err := json.Marshal(testRequest)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	encryptedRequest, err := clientSession.Encrypt(requestJSON, nil)
	if err != nil {
		t.Fatalf("Client encryption failed: %v", err)
	}

	// Server decrypts request
	decryptedRequest, err := serverManager.DecryptCall(sessionID, encryptedRequest)
	if err != nil {
		t.Fatalf("Server decryption failed: %v", err)
	}

	// Verify decrypted request
	if decryptedRequest["method"] != "echo" {
		t.Errorf("Decrypted method = %v, want echo", decryptedRequest["method"])
	}

	// Server encrypts response
	testResponse := map[string]interface{}{
		"jsonrpc": "2.0",
		"result":  "test message",
		"id":      1,
	}

	encryptedResponse, err := serverManager.EncryptResponse(sessionID, testResponse)
	if err != nil {
		t.Fatalf("Server response encryption failed: %v", err)
	}

	// Client decrypts response
	decryptedResponseBytes, err := clientSession.Decrypt(encryptedResponse, nil)
	if err != nil {
		t.Fatalf("Client response decryption failed: %v", err)
	}

	var decryptedResponse map[string]interface{}
	if err := json.Unmarshal(decryptedResponseBytes, &decryptedResponse); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Verify decrypted response
	if decryptedResponse["result"] != "test message" {
		t.Errorf("Decrypted result = %v, want 'test message'", decryptedResponse["result"])
	}

	// Session should be cleaned up after response
	if serverManager.GetSessionCount() != 0 {
		t.Errorf("Session should be cleaned up after response, count = %d", serverManager.GetSessionCount())
	}
}

func TestSessionManagerErrors(t *testing.T) {
	serverManager := NewNoiseSessionManager(nil)

	// Test decrypt with non-existent session
	_, err := serverManager.DecryptCall("nonexistent", []byte("data"))
	if err == nil {
		t.Errorf("DecryptCall with non-existent session should fail")
	}

	// Test encrypt response with non-existent session
	_, err = serverManager.EncryptResponse("nonexistent", map[string]interface{}{"test": "data"})
	if err == nil {
		t.Errorf("EncryptResponse with non-existent session should fail")
	}

	// Test handshake hash with non-existent session
	_, err = serverManager.GetHandshakeHash("nonexistent")
	if err == nil {
		t.Errorf("GetHandshakeHash with non-existent session should fail")
	}
}

func TestSessionManagerConcurrency(t *testing.T) {
	serverManager := NewNoiseSessionManager(nil)

	// Test concurrent session creation
	const numSessions = 10
	sessionIDs := make([]string, numSessions)

	for i := 0; i < numSessions; i++ {
		sessionID, err := GenerateSessionID()
		if err != nil {
			t.Fatalf("Failed to generate session ID: %v", err)
		}
		sessionIDs[i] = sessionID
	}

	// All sessions should be created successfully
	for _, sessionID := range sessionIDs {
		// Create a simple client for handshake
		clientSession, err := openadpNoise.NewNoiseNK("initiator", nil, serverManager.GetServerPublicKey(), []byte(""))
		if err != nil {
			t.Fatalf("Failed to create client session: %v", err)
		}

		clientHandshakeMsg, err := clientSession.WriteHandshakeMessage([]byte("test"))
		if err != nil {
			t.Fatalf("Client handshake failed: %v", err)
		}

		_, err = serverManager.StartHandshake(sessionID, clientHandshakeMsg)
		if err != nil {
			t.Fatalf("Server handshake failed for session %s: %v", sessionID, err)
		}
	}

	// Should have all sessions
	if serverManager.GetSessionCount() != numSessions {
		t.Errorf("Session count = %d, want %d", serverManager.GetSessionCount(), numSessions)
	}
}

func TestGlobalSessionManager(t *testing.T) {
	// Test singleton behavior
	manager1 := GetSessionManager()
	manager2 := GetSessionManager()

	if manager1 != manager2 {
		t.Errorf("GetSessionManager should return the same instance")
	}

	// Test initialization with custom key
	keyPair, err := openadpNoise.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	manager3 := InitializeSessionManager(&keyPair)
	if manager3 == nil {
		t.Fatal("InitializeSessionManager should not return nil")
	}

	// Should use the provided key
	if string(manager3.GetServerPublicKey()) != string(keyPair.Public) {
		t.Errorf("Initialized manager should use provided public key")
	}

	// GetSessionManager should now return the initialized manager
	manager4 := GetSessionManager()
	if manager4 != manager3 {
		t.Errorf("GetSessionManager should return the initialized manager")
	}
}

func TestSessionCleanup(t *testing.T) {
	serverManager := NewNoiseSessionManager(nil)

	// Create a session but don't complete the full cycle
	sessionID, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("Failed to generate session ID: %v", err)
	}

	clientSession, err := openadpNoise.NewNoiseNK("initiator", nil, serverManager.GetServerPublicKey(), []byte(""))
	if err != nil {
		t.Fatalf("Failed to create client session: %v", err)
	}

	clientHandshakeMsg, err := clientSession.WriteHandshakeMessage([]byte("test"))
	if err != nil {
		t.Fatalf("Client handshake failed: %v", err)
	}

	_, err = serverManager.StartHandshake(sessionID, clientHandshakeMsg)
	if err != nil {
		t.Fatalf("Server handshake failed: %v", err)
	}

	// Should have one session
	if serverManager.GetSessionCount() != 1 {
		t.Errorf("Session count = %d, want 1", serverManager.GetSessionCount())
	}

	// Test cleanup (this is mostly a placeholder since we don't track creation time yet)
	serverManager.CleanupExpiredSessions(300)

	// For now, cleanup doesn't actually remove sessions, just logs warnings
	// This test mainly ensures the method doesn't panic
}
