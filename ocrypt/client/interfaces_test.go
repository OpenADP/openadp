package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openadp/ocrypt/common"
)

// TestOpenADPClientInterface verifies that OpenADPClient implements the standardized interface
func TestOpenADPClientInterface(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":true,"id":1}`))
	}))
	defer server.Close()

	// Create client
	client := NewOpenADPClient(server.URL)

	// Verify it implements the interface
	var _ StandardOpenADPClientInterface = client

	// Test standardized methods
	t.Run("RegisterSecretStandardized", func(t *testing.T) {
		request := &RegisterSecretRequest{
			UID:        "test-uid",
			DID:        "test-did",
			BID:        "test-bid",
			Version:    1,
			X:          42,
			Y:          "dGVzdA==", // "test" in base64
			MaxGuesses: 10,
			Expiration: 0,
		}

		response, err := client.RegisterSecretStandardized(request)
		if err == nil {
			t.Error("RegisterSecretStandardized() expected error for basic client but got none")
		}
		if response != nil {
			t.Errorf("RegisterSecretStandardized() response = %v, want nil for basic client", response)
		}
		expectedError := "RegisterSecret not supported by basic client - use EncryptedOpenADPClient for secure operations"
		if err.Error() != expectedError {
			t.Errorf("RegisterSecretStandardized() error = %v, want %v", err.Error(), expectedError)
		}
	})

	t.Run("TestConnection", func(t *testing.T) {
		// This will fail because mock server doesn't echo properly, but tests the method exists
		err := client.TestConnection()
		if err == nil {
			t.Error("TestConnection() expected error with mock server")
		}
	})

	t.Run("GetServerURL", func(t *testing.T) {
		url := client.GetServerURL()
		if url != server.URL {
			t.Errorf("GetServerURL() = %v, want %v", url, server.URL)
		}
	})

	t.Run("SupportsEncryption", func(t *testing.T) {
		supports := client.SupportsEncryption()
		if supports {
			t.Error("SupportsEncryption() = true, want false for basic client")
		}
	})
}

// TestEncryptedOpenADPClientInterface verifies that EncryptedOpenADPClient implements the standardized interface
func TestEncryptedOpenADPClientInterface(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","result":true,"id":1}`))
	}))
	defer server.Close()

	// Create encrypted client (without public key for simplicity)
	client := NewEncryptedOpenADPClient(server.URL, nil)

	// Verify it implements the interface
	var _ StandardOpenADPClientInterface = client

	// Test standardized methods
	t.Run("RegisterSecretStandardized", func(t *testing.T) {
		request := &RegisterSecretRequest{
			AuthCode:   "test-auth-code",
			UID:        "test-uid",
			DID:        "test-did",
			BID:        "test-bid",
			Version:    1,
			X:          42,
			Y:          "dGVzdA==", // "test" in base64
			MaxGuesses: 10,
			Expiration: 0,
			Encrypted:  false,
		}

		response, err := client.RegisterSecretStandardized(request)
		if err != nil {
			t.Errorf("RegisterSecretStandardized() error = %v", err)
		}
		if !response.Success {
			t.Errorf("RegisterSecretStandardized() success = %v, want true", response.Success)
		}
	})

	t.Run("SupportsEncryption", func(t *testing.T) {
		supports := client.SupportsEncryption()
		if supports {
			t.Error("SupportsEncryption() = true, want false when no public key provided")
		}
	})
}

// TestMultiServerClientInterface verifies that Client implements the MultiServerClientInterface
func TestMultiServerClientInterface(t *testing.T) {
	// Create multiple mock servers that properly echo
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the request to extract the echo message
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)

		// Get the message from params (should be first parameter)
		params, ok := req["params"].([]interface{})
		message := "liveness_test_"
		if ok && len(params) > 0 {
			if msg, ok := params[0].(string); ok {
				message = msg
			}
		}

		w.WriteHeader(http.StatusOK)
		response := fmt.Sprintf(`{"jsonrpc":"2.0","result":"%s","id":1}`, message)
		w.Write([]byte(response))
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the request to extract the echo message
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)

		// Get the message from params (should be first parameter)
		params, ok := req["params"].([]interface{})
		message := "liveness_test_"
		if ok && len(params) > 0 {
			if msg, ok := params[0].(string); ok {
				message = msg
			}
		}

		w.WriteHeader(http.StatusOK)
		response := fmt.Sprintf(`{"jsonrpc":"2.0","result":"%s","id":1}`, message)
		w.Write([]byte(response))
	}))
	defer server2.Close()

	// Create client with test servers
	serverInfos := []ServerInfo{
		{URL: server1.URL, PublicKey: "", Country: "Test"},
		{URL: server2.URL, PublicKey: "", Country: "Test"},
	}
	client := NewClientWithServerInfo(serverInfos, 0, 0)

	// Verify it implements the interface
	var _ StandardMultiServerClientInterface = client

	// Test multi-server methods
	t.Run("GetLiveServerCount", func(t *testing.T) {
		count := client.GetLiveServerCount()
		if count < 1 {
			t.Errorf("GetLiveServerCount() = %d, want at least 1", count)
		}
	})

	t.Run("GetLiveServerURLs", func(t *testing.T) {
		urls := client.GetLiveServerURLs()
		if len(urls) < 1 {
			t.Errorf("GetLiveServerURLs() returned %d URLs, want at least 1", len(urls))
		}
	})

	t.Run("SetServerSelectionStrategy", func(t *testing.T) {
		// Test that method exists and doesn't panic
		client.SetServerSelectionStrategy(RoundRobin)
		client.SetServerSelectionStrategy(Random)
		client.SetServerSelectionStrategy(FirstAvailable)
	})

	t.Run("SupportsEncryption", func(t *testing.T) {
		supports := client.SupportsEncryption()
		if supports {
			t.Error("SupportsEncryption() = true, want false when no public keys provided")
		}
	})
}

// TestStandardizedRequestResponseTypes verifies the standardized types work correctly
func TestStandardizedRequestResponseTypes(t *testing.T) {
	t.Run("RegisterSecretRequest", func(t *testing.T) {
		request := &RegisterSecretRequest{
			AuthCode:   "test-auth-code",
			UID:        "test-uid",
			DID:        "test-did",
			BID:        "test-bid",
			Version:    1,
			X:          42,
			Y:          "dGVzdA==",
			MaxGuesses: 10,
			Expiration: 0,
			Encrypted:  true,
			AuthData:   map[string]interface{}{"key": "value"},
		}

		if request.AuthCode != "test-auth-code" {
			t.Errorf("AuthCode = %v, want test-auth-code", request.AuthCode)
		}
		if request.Encrypted != true {
			t.Errorf("Encrypted = %v, want true", request.Encrypted)
		}
	})

	t.Run("RegisterSecretResponse", func(t *testing.T) {
		response := &RegisterSecretResponse{
			Success: true,
			Message: "Registration successful",
		}

		if !response.Success {
			t.Errorf("Success = %v, want true", response.Success)
		}
		if response.Message != "Registration successful" {
			t.Errorf("Message = %v, want 'Registration successful'", response.Message)
		}
	})

	t.Run("BackupInfo", func(t *testing.T) {
		backup := BackupInfo{
			UID:        "test-uid",
			BID:        "test-bid",
			Version:    1,
			NumGuesses: 5,
			MaxGuesses: 10,
			Expiration: 1234567890,
		}

		if backup.UID != "test-uid" {
			t.Errorf("UID = %v, want test-uid", backup.UID)
		}
		if backup.NumGuesses != 5 {
			t.Errorf("NumGuesses = %v, want 5", backup.NumGuesses)
		}
	})
}

// TestOpenADPError verifies the standardized error type
func TestOpenADPError(t *testing.T) {
	t.Run("ErrorWithDetails", func(t *testing.T) {
		err := &OpenADPError{
			Code:    ErrorCodeAuthenticationFailed,
			Message: "Authentication failed",
			Details: "Invalid auth code",
		}

		expected := "OpenADP Error 1002: Authentication failed (Invalid auth code)"
		if err.Error() != expected {
			t.Errorf("Error() = %v, want %v", err.Error(), expected)
		}
	})

	t.Run("ErrorWithoutDetails", func(t *testing.T) {
		err := &OpenADPError{
			Code:    ErrorCodeNetworkFailure,
			Message: "Network failure",
		}

		expected := "OpenADP Error 1001: Network failure"
		if err.Error() != expected {
			t.Errorf("Error() = %v, want %v", err.Error(), expected)
		}
	})
}

// TestPointDataConversion verifies point data conversion between different formats
func TestPointDataConversion(t *testing.T) {
	t.Run("Point2DToBase64", func(t *testing.T) {
		// Create a test point
		point := &common.Point2D{
			X: big.NewInt(123),
			Y: big.NewInt(456),
		}

		// Convert to bytes and then base64 (simplified conversion)
		xBytes := point.X.Bytes()
		yBytes := point.Y.Bytes()

		// Pad to ensure consistent length
		if len(xBytes) < 16 {
			padding := make([]byte, 16-len(xBytes))
			xBytes = append(padding, xBytes...)
		}
		if len(yBytes) < 16 {
			padding := make([]byte, 16-len(yBytes))
			yBytes = append(padding, yBytes...)
		}

		pointBytes := append(xBytes, yBytes...)
		base64Point := base64.StdEncoding.EncodeToString(pointBytes)

		if base64Point == "" {
			t.Error("Base64 conversion resulted in empty string")
		}

		// Verify we can decode it back
		decoded, err := base64.StdEncoding.DecodeString(base64Point)
		if err != nil {
			t.Errorf("Failed to decode base64 point: %v", err)
		}
		if len(decoded) != 32 {
			t.Errorf("Decoded point length = %d, want 32", len(decoded))
		}
	})
}

// TestServerSelectionStrategy verifies the server selection strategy enum
func TestServerSelectionStrategy(t *testing.T) {
	strategies := []ServerSelectionStrategy{
		FirstAvailable,
		RoundRobin,
		Random,
		LowestLatency,
	}

	for i, strategy := range strategies {
		if int(strategy) != i {
			t.Errorf("Strategy %d has value %d, want %d", i, int(strategy), i)
		}
	}
}
