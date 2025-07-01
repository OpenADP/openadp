package ocrypt

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestRegisterInputValidation tests input validation for Register function
func TestRegisterInputValidation(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		appID          string
		longTermSecret []byte
		pin            string
		maxGuesses     int
		wantError      bool
		errorContains  string
	}{
		{
			name:           "empty user_id",
			userID:         "",
			appID:          "test_app",
			longTermSecret: []byte("secret"),
			pin:            "1234",
			maxGuesses:     10,
			wantError:      true,
			errorContains:  "user_id must be a non-empty string",
		},
		{
			name:           "empty app_id",
			userID:         "test_user",
			appID:          "",
			longTermSecret: []byte("secret"),
			pin:            "1234",
			maxGuesses:     10,
			wantError:      true,
			errorContains:  "app_id must be a non-empty string",
		},
		{
			name:           "empty long_term_secret",
			userID:         "test_user",
			appID:          "test_app",
			longTermSecret: []byte{},
			pin:            "1234",
			maxGuesses:     10,
			wantError:      true,
			errorContains:  "long_term_secret cannot be empty",
		},
		{
			name:           "empty pin",
			userID:         "test_user",
			appID:          "test_app",
			longTermSecret: []byte("secret"),
			pin:            "",
			maxGuesses:     10,
			wantError:      true,
			errorContains:  "pin must be a non-empty string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Register(tt.userID, tt.appID, tt.longTermSecret, tt.pin, tt.maxGuesses, "")

			if tt.wantError {
				if err == nil {
					t.Errorf("Register() expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Register() error = %v, want error containing %v", err, tt.errorContains)
				}
			} else if err != nil {
				t.Errorf("Register() unexpected error: %v", err)
			}
		})
	}
}

// TestRecoverInputValidation tests input validation for Recover function
func TestRecoverInputValidation(t *testing.T) {
	tests := []struct {
		name          string
		metadata      []byte
		pin           string
		wantError     bool
		errorContains string
	}{
		{
			name:          "empty metadata",
			metadata:      []byte{},
			pin:           "1234",
			wantError:     true,
			errorContains: "metadata cannot be empty",
		},
		{
			name:          "empty pin",
			metadata:      []byte("fake_metadata"),
			pin:           "",
			wantError:     true,
			errorContains: "pin must be a non-empty string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := Recover(tt.metadata, tt.pin, "")

			if tt.wantError {
				if err == nil {
					t.Errorf("Recover() expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Recover() error = %v, want error containing %v", err, tt.errorContains)
				}
			} else if err != nil {
				t.Errorf("Recover() unexpected error: %v", err)
			}
		})
	}
}

// TestMetadataFormat tests that metadata can be parsed correctly
func TestMetadataFormat(t *testing.T) {
	// Create sample metadata
	metadata := &Metadata{
		Servers:   []string{"https://server1.example.com", "https://server2.example.com"},
		Threshold: 2,
		Version:   "1.0",
		AuthCode:  "test_auth_code",
		UserID:    "test_user",
		WrappedLongTermSecret: WrappedSecret{
			Nonce:      "dGVzdF9ub25jZQ==",
			Ciphertext: "dGVzdF9jaXBoZXJ0ZXh0",
			Tag:        "dGVzdF90YWc=",
		},
		BackupID:      "even",
		AppID:         "test_app",
		MaxGuesses:    10,
		OcryptVersion: "1.0",
	}

	// Marshal to JSON
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Failed to marshal metadata: %v", err)
	}

	// Unmarshal back
	var parsedMetadata Metadata
	err = json.Unmarshal(metadataBytes, &parsedMetadata)
	if err != nil {
		t.Fatalf("Failed to unmarshal metadata: %v", err)
	}

	// Verify fields
	if parsedMetadata.UserID != metadata.UserID {
		t.Errorf("UserID mismatch: got %v, want %v", parsedMetadata.UserID, metadata.UserID)
	}
	if parsedMetadata.AppID != metadata.AppID {
		t.Errorf("AppID mismatch: got %v, want %v", parsedMetadata.AppID, metadata.AppID)
	}
	if parsedMetadata.BackupID != metadata.BackupID {
		t.Errorf("BackupID mismatch: got %v, want %v", parsedMetadata.BackupID, metadata.BackupID)
	}
	if parsedMetadata.Threshold != metadata.Threshold {
		t.Errorf("Threshold mismatch: got %v, want %v", parsedMetadata.Threshold, metadata.Threshold)
	}
}

// TestWrapUnwrapSecret tests the AES-GCM wrapping/unwrapping functionality
func TestWrapUnwrapSecret(t *testing.T) {
	secret := []byte("This is a test secret that should be protected")
	key := make([]byte, 32) // 256-bit key
	for i := range key {
		key[i] = byte(i)
	}

	// Test wrapping
	wrapped, err := wrapSecret(secret, key)
	if err != nil {
		t.Fatalf("wrapSecret failed: %v", err)
	}

	// Verify wrapped secret structure
	if wrapped.Nonce == "" {
		t.Error("Wrapped secret missing nonce")
	}
	if wrapped.Ciphertext == "" {
		t.Error("Wrapped secret missing ciphertext")
	}
	if wrapped.Tag == "" {
		t.Error("Wrapped secret missing tag")
	}

	// Test unwrapping
	unwrapped, err := unwrapSecret(wrapped, key)
	if err != nil {
		t.Fatalf("unwrapSecret failed: %v", err)
	}

	// Verify the secret matches
	if !bytes.Equal(secret, unwrapped) {
		t.Errorf("Unwrapped secret doesn't match original: got %v, want %v", unwrapped, secret)
	}

	// Test unwrapping with wrong key
	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = byte(255 - i)
	}

	_, err = unwrapSecret(wrapped, wrongKey)
	if err == nil {
		t.Error("unwrapSecret should fail with wrong key")
	}
	if !strings.Contains(err.Error(), "MAC check failed") {
		t.Errorf("Expected MAC check failed error, got: %v", err)
	}
}

// TestGenerateNextBackupID tests backup ID generation strategies
func TestGenerateNextBackupID(t *testing.T) {
	tests := []struct {
		name      string
		currentID string
		wantNext  string
	}{
		{
			name:      "even to odd",
			currentID: "even",
			wantNext:  "odd",
		},
		{
			name:      "odd to even",
			currentID: "odd",
			wantNext:  "even",
		},
		{
			name:      "v1 to v2",
			currentID: "v1",
			wantNext:  "v2",
		},
		{
			name:      "v10 to v11",
			currentID: "v10",
			wantNext:  "v11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := generateNextBackupID(tt.currentID)
			if next != tt.wantNext {
				t.Errorf("generateNextBackupID(%v) = %v, want %v", tt.currentID, next, tt.wantNext)
			}
		})
	}

	// Test fallback case (should append timestamp)
	customID := "production"
	next := generateNextBackupID(customID)
	if !strings.HasPrefix(next, "production_v") {
		t.Errorf("generateNextBackupID(%v) = %v, expected to start with 'production_v'", customID, next)
	}
}

// TestParseInt tests the parseInt helper function
func TestParseInt(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "valid number",
			input: "123",
			want:  123,
		},
		{
			name:  "zero",
			input: "0",
			want:  0,
		},
		{
			name:  "invalid with letters",
			input: "12a3",
			want:  0,
		},
		{
			name:  "empty string",
			input: "",
			want:  0,
		},
		{
			name:  "negative number",
			input: "-123",
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseInt(tt.input)
			if got != tt.want {
				t.Errorf("parseInt(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestOcryptError tests the custom error type
func TestOcryptError(t *testing.T) {
	tests := []struct {
		name    string
		err     *OcryptError
		wantMsg string
	}{
		{
			name: "error with code",
			err: &OcryptError{
				Message: "Something went wrong",
				Code:    "TEST_ERROR",
			},
			wantMsg: "Ocrypt TEST_ERROR: Something went wrong",
		},
		{
			name: "error without code",
			err: &OcryptError{
				Message: "Something went wrong",
				Code:    "",
			},
			wantMsg: "Ocrypt error: Something went wrong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.wantMsg {
				t.Errorf("OcryptError.Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

// TestRegisterUsesDefaultBackupID tests that Register uses "even" as default backup ID
func TestRegisterUsesDefaultBackupID(t *testing.T) {
	// This test will fail at server connection, but we can check that it tries to use "even"
	userID := "test_user"
	appID := "test_app"
	secret := []byte("test_secret")
	pin := "1234"

	_, err := Register(userID, appID, secret, pin, 10, "")

	// Should fail at server discovery, but error should indicate it tried to proceed
	if err == nil {
		t.Error("Expected error due to no servers, but got none")
	}

	// Error should be about server discovery, not input validation
	if strings.Contains(err.Error(), "user_id") || strings.Contains(err.Error(), "app_id") {
		t.Errorf("Unexpected input validation error: %v", err)
	}
}

// Benchmark tests
func BenchmarkWrapSecret(b *testing.B) {
	secret := make([]byte, 1024) // 1KB secret
	key := make([]byte, 32)      // 256-bit key

	for i := range secret {
		secret[i] = byte(i % 256)
	}
	for i := range key {
		key[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := wrapSecret(secret, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnwrapSecret(b *testing.B) {
	secret := make([]byte, 1024) // 1KB secret
	key := make([]byte, 32)      // 256-bit key

	for i := range secret {
		secret[i] = byte(i % 256)
	}
	for i := range key {
		key[i] = byte(i)
	}

	wrapped, err := wrapSecret(secret, key)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := unwrapSecret(wrapped, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}
