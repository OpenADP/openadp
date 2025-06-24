package client

import (
	"testing"

)

// Test individual keygen functions without server dependencies

func TestDeriveIdentifiers(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		userID   string
		hostname string
		wantUID  bool // just check if it's generated
		wantDID  bool // just check if it's generated
		wantBID  bool // just check if it's generated
	}{
		{
			name:     "basic file",
			filename: "test.txt",
			userID:   "user123",
			hostname: "host",
			wantUID:  true,
			wantDID:  true,
			wantBID:  true,
		},
		{
			name:     "empty hostname",
			filename: "test.txt",
			userID:   "user123",
			hostname: "",
			wantUID:  true,
			wantDID:  true,
			wantBID:  true,
		},
		{
			name:     "unicode filename",
			filename: "тест.txt",
			userID:   "пользователь",
			hostname: "host",
			wantUID:  true,
			wantDID:  true,
			wantBID:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uid, did, bid := DeriveIdentifiers(tt.filename, tt.userID, tt.hostname)

			if tt.wantUID && uid == "" {
				t.Errorf("DeriveIdentifiers() uid is empty")
			}
			if tt.wantDID && did == "" {
				t.Errorf("DeriveIdentifiers() did is empty")
			}
			if tt.wantBID && bid == "" {
				t.Errorf("DeriveIdentifiers() bid is empty")
			}

			// Test consistency - same inputs should produce same outputs
			uid2, did2, bid2 := DeriveIdentifiers(tt.filename, tt.userID, tt.hostname)
			if uid != uid2 || did != did2 || bid != bid2 {
				t.Errorf("DeriveIdentifiers() not deterministic: got (%s,%s,%s) then (%s,%s,%s)",
					uid, did, bid, uid2, did2, bid2)
			}
		})
	}
}

func TestPasswordToPin(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantLen  int
	}{
		{
			name:     "simple password",
			password: "test123",
			wantLen:  2, // First 2 bytes of SHA256 hash
		},
		{
			name:     "empty password",
			password: "",
			wantLen:  2,
		},
		{
			name:     "unicode password",
			password: "пароль123",
			wantLen:  2,
		},
		{
			name:     "long password",
			password: "this is a very long password with many characters",
			wantLen:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pin := PasswordToPin(tt.password)
			if len(pin) != tt.wantLen {
				t.Errorf("PasswordToPin() length = %d, want %d", len(pin), tt.wantLen)
			}

			// Test consistency - same password should produce same PIN
			pin2 := PasswordToPin(tt.password)
			if string(pin) != string(pin2) {
				t.Errorf("PasswordToPin() not deterministic")
			}
		})
	}
}

func TestGenerateAuthCodes(t *testing.T) {
	tests := []struct {
		name       string
		serverURLs []string
		wantCount  int
	}{
		{
			name:       "single server",
			serverURLs: []string{"https://server1.com"},
			wantCount:  1,
		},
		{
			name:       "multiple servers",
			serverURLs: []string{"https://server1.com", "https://server2.com", "https://server3.com"},
			wantCount:  3,
		},
		{
			name:       "empty servers",
			serverURLs: []string{},
			wantCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authCodes := GenerateAuthCodes(tt.serverURLs)

			if authCodes == nil {
				t.Errorf("GenerateAuthCodes() returned nil")
				return
			}

			if len(authCodes.ServerAuthCodes) != tt.wantCount {
				t.Errorf("GenerateAuthCodes() server auth codes count = %d, want %d",
					len(authCodes.ServerAuthCodes), tt.wantCount)
			}

			if authCodes.BaseAuthCode == "" && tt.wantCount > 0 {
				t.Errorf("GenerateAuthCodes() base auth code is empty")
			}

			// Test that each server has an auth code
			for _, url := range tt.serverURLs {
				if _, exists := authCodes.ServerAuthCodes[url]; !exists {
					t.Errorf("GenerateAuthCodes() missing auth code for server %s", url)
				}
			}
		})
	}
}

func TestGenerateEncryptionKeyInputValidation(t *testing.T) {
	tests := []struct {
		name       string
		filename   string
		password   string
		userID     string
		maxGuesses int
		expiration int
		serverURLs []string
		wantError  bool
	}{
		{
			name:       "empty filename",
			filename:   "",
			password:   "test",
			userID:     "user",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{"http://server1.com"},
			wantError:  true,
		},
		{
			name:       "empty userID",
			filename:   "test.txt",
			password:   "test",
			userID:     "",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{"http://server1.com"},
			wantError:  true,
		},
		{
			name:       "negative maxGuesses",
			filename:   "test.txt",
			password:   "test",
			userID:     "user",
			maxGuesses: -1,
			expiration: 0,
			serverURLs: []string{"http://server1.com"},
			wantError:  true,
		},
		{
			name:       "no servers",
			filename:   "test.txt",
			password:   "test",
			userID:     "user",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{},
			wantError:  true,
		},
		{
			name:       "valid inputs (will fail at server connection)",
			filename:   "test.txt",
			password:   "test",
			userID:     "user",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{"http://localhost:9999"}, // non-existent server
			wantError:  true,                              // Should fail at connectivity test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateEncryptionKey(tt.filename, tt.password, tt.userID,
				tt.maxGuesses, tt.expiration, ConvertURLsToServerInfo(tt.serverURLs))

			if tt.wantError && result.Error == "" {
				t.Errorf("GenerateEncryptionKey() expected error but got none")
			}
			if !tt.wantError && result.Error != "" {
				t.Errorf("GenerateEncryptionKey() unexpected error: %s", result.Error)
			}
		})
	}
}

func TestRecoverEncryptionKeyInputValidation(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		password    string
		userID      string
		serverInfos []ServerInfo
		threshold   int
		authCodes   *AuthCodes
		wantError   bool
	}{
		{
			name:        "empty filename",
			filename:    "",
			password:    "test",
			userID:      "user",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   1,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "empty userID",
			filename:    "test.txt",
			password:    "test",
			userID:      "",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   1,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "zero threshold",
			filename:    "test.txt",
			password:    "test",
			userID:      "user",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   0,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "negative threshold",
			filename:    "test.txt",
			password:    "test",
			userID:      "user",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   -1,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "no servers",
			filename:    "test.txt",
			password:    "test",
			userID:      "user",
			serverInfos: []ServerInfo{},
			threshold:   1,
			authCodes:   &AuthCodes{},
			wantError:   true,
		},
		{
			name:        "nil auth codes",
			filename:    "test.txt",
			password:    "test",
			userID:      "user",
			serverInfos: []ServerInfo{{URL: "http://server1.com"}},
			threshold:   1,
			authCodes:   nil,
			wantError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RecoverEncryptionKeyWithServerInfo(tt.filename, tt.password, tt.userID,
				tt.serverInfos, tt.threshold, tt.authCodes)

			if tt.wantError && result.Error == "" {
				t.Errorf("RecoverEncryptionKeyWithServerInfo() expected error but got none")
			}
			if !tt.wantError && result.Error != "" {
				t.Errorf("RecoverEncryptionKeyWithServerInfo() unexpected error: %s", result.Error)
			}
		})
	}
}

func TestMaxMin(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int
		wantMax int
		wantMin int
	}{
		{
			name:    "positive numbers",
			a:       5,
			b:       3,
			wantMax: 5,
			wantMin: 3,
		},
		{
			name:    "negative numbers",
			a:       -2,
			b:       -5,
			wantMax: -2,
			wantMin: -5,
		},
		{
			name:    "equal numbers",
			a:       7,
			b:       7,
			wantMax: 7,
			wantMin: 7,
		},
		{
			name:    "zero and positive",
			a:       0,
			b:       10,
			wantMax: 10,
			wantMin: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := max(tt.a, tt.b); got != tt.wantMax {
				t.Errorf("max(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.wantMax)
			}
			if got := min(tt.a, tt.b); got != tt.wantMin {
				t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.wantMin)
			}
		})
	}
}

// Integration test that requires real servers - keep as a separate test that can be skipped
func TestKeygenRoundTrip(t *testing.T) {
	// Skip if running in CI or if servers not available
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test the complete keygen round trip using actual functions
	filename := "test-file.txt"
	password := "test-password-123"
	userID := "test-user-id-fixed"
	maxGuesses := 10
	expiration := 0
	serverURLs := []string{
		"http://localhost:9200",
		"http://localhost:9201",
		"http://localhost:9202",
	}

	// Step 1: Generate encryption key
	t.Log("🔐 Generating encryption key...")
	result := GenerateEncryptionKey(filename, password, userID, maxGuesses, expiration, ConvertURLsToServerInfo(serverURLs))
	if result.Error != "" {
		t.Skipf("Key generation failed (servers not available): %s", result.Error)
	}

	t.Logf("✅ Generated key: %x", result.EncryptionKey[:16])
	t.Logf("✅ Used %d servers with threshold %d", len(result.ServerURLs), result.Threshold)

	// Step 2: Recover encryption key
	t.Log("🔓 Recovering encryption key...")
	serverInfos := ConvertURLsToServerInfo(result.ServerURLs)
	recoveryResult := RecoverEncryptionKeyWithServerInfo(filename, password, userID, serverInfos, result.Threshold, result.AuthCodes)
	if recoveryResult.Error != "" {
		t.Fatalf("Key recovery failed: %s", recoveryResult.Error)
	}

	t.Logf("✅ Recovered key: %x", recoveryResult.EncryptionKey[:16])

	// Step 3: Verify keys match
	if len(result.EncryptionKey) != len(recoveryResult.EncryptionKey) {
		t.Errorf("Key lengths don't match: original=%d, recovered=%d", len(result.EncryptionKey), len(recoveryResult.EncryptionKey))
	}

	for i := 0; i < len(result.EncryptionKey) && i < len(recoveryResult.EncryptionKey); i++ {
		if result.EncryptionKey[i] != recoveryResult.EncryptionKey[i] {
			t.Errorf("Keys don't match at byte %d: original=0x%02x, recovered=0x%02x", i, result.EncryptionKey[i], recoveryResult.EncryptionKey[i])
			t.Errorf("Original key:  %x", result.EncryptionKey)
			t.Errorf("Recovered key: %x", recoveryResult.EncryptionKey)
			return
		}
	}

	t.Log("✅ Keygen round trip test passed - keys match!")
}
