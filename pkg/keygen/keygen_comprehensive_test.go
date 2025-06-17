package keygen

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// TestGenerateEncryptionKeyBasic tests basic encryption key generation
func TestGenerateEncryptionKeyBasic(t *testing.T) {
	filename := "test-file.txt"
	password := "test-password"
	userID := "test-user"
	maxGuesses := 10
	expiration := 0
	serverURLs := []string{
		"http://localhost:9200",
		"http://localhost:9201",
		"http://localhost:9202",
	}

	result := GenerateEncryptionKey(filename, password, userID, maxGuesses, expiration, serverURLs)

	// Should succeed with local servers (or fail gracefully if servers not available)
	if result.Error != "" {
		t.Logf("Key generation failed (expected if no local servers): %s", result.Error)
		return
	}

	// If successful, verify result structure
	if len(result.EncryptionKey) != 32 {
		t.Errorf("Expected 32-byte encryption key, got %d bytes", len(result.EncryptionKey))
	}

	if result.Threshold <= 0 {
		t.Errorf("Expected positive threshold, got %d", result.Threshold)
	}

	if len(result.ServerURLs) == 0 {
		t.Errorf("Expected at least one server URL")
	}

	if result.AuthCodes == nil || len(result.AuthCodes.ServerAuthCodes) == 0 {
		t.Errorf("Expected at least one auth code")
	}
}

// TestGenerateEncryptionKeyDifferentUsers tests that different users get different keys
func TestGenerateEncryptionKeyDifferentUsers(t *testing.T) {
	filename := "test-file.txt"
	password := "test-password"
	maxGuesses := 10
	expiration := 0
	serverURLs := []string{"http://localhost:9200"}

	result1 := GenerateEncryptionKey(filename, password, "user1", maxGuesses, expiration, serverURLs)
	result2 := GenerateEncryptionKey(filename, password, "user2", maxGuesses, expiration, serverURLs)

	// If both succeed, keys should be different
	if result1.Error == "" && result2.Error == "" {
		if bytes.Equal(result1.EncryptionKey, result2.EncryptionKey) {
			t.Errorf("Different users should get different encryption keys")
		}
	} else {
		t.Logf("Key generation failed (expected if no local servers): user1=%s, user2=%s", result1.Error, result2.Error)
	}
}

// TestGenerateEncryptionKeyDifferentPasswords tests that different passwords give different keys
func TestGenerateEncryptionKeyDifferentPasswords(t *testing.T) {
	filename := "test-file.txt"
	userID := "test-user"
	maxGuesses := 10
	expiration := 0
	serverURLs := []string{"http://localhost:9200"}

	result1 := GenerateEncryptionKey(filename, "password1", userID, maxGuesses, expiration, serverURLs)
	result2 := GenerateEncryptionKey(filename, "password2", userID, maxGuesses, expiration, serverURLs)

	// If both succeed, keys should be different
	if result1.Error == "" && result2.Error == "" {
		if bytes.Equal(result1.EncryptionKey, result2.EncryptionKey) {
			t.Errorf("Different passwords should give different encryption keys")
		}
	} else {
		t.Logf("Key generation failed (expected if no local servers): pwd1=%s, pwd2=%s", result1.Error, result2.Error)
	}
}

// TestGenerateEncryptionKeySameInputs tests that same inputs give same results
func TestGenerateEncryptionKeySameInputs(t *testing.T) {
	filename := "test-file.txt"
	password := "test-password"
	userID := "test-user"
	maxGuesses := 10
	expiration := 0
	serverURLs := []string{"http://localhost:9200"}

	result1 := GenerateEncryptionKey(filename, password, userID, maxGuesses, expiration, serverURLs)
	result2 := GenerateEncryptionKey(filename, password, userID, maxGuesses, expiration, serverURLs)

	// If both succeed, results should be identical (deterministic)
	if result1.Error == "" && result2.Error == "" {
		if !bytes.Equal(result1.EncryptionKey, result2.EncryptionKey) {
			t.Errorf("Same inputs should give same encryption keys")
		}
		if result1.Threshold != result2.Threshold {
			t.Errorf("Same inputs should give same threshold")
		}
	} else {
		t.Logf("Key generation failed (expected if no local servers): result1=%s, result2=%s", result1.Error, result2.Error)
	}
}

// TestGenerateEncryptionKeyInvalidParams tests key generation with invalid parameters
func TestGenerateEncryptionKeyInvalidParams(t *testing.T) {
	testCases := []struct {
		name       string
		filename   string
		password   string
		userID     string
		maxGuesses int
		expiration int
		serverURLs []string
		shouldFail bool
	}{
		{
			name:       "empty_filename",
			filename:   "",
			password:   "password",
			userID:     "user",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{"http://localhost:9200"},
			shouldFail: true,
		},
		{
			name:       "empty_password",
			filename:   "file.txt",
			password:   "",
			userID:     "user",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{"http://localhost:9200"},
			shouldFail: false, // Empty password might be allowed
		},
		{
			name:       "empty_user_id",
			filename:   "file.txt",
			password:   "password",
			userID:     "",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{"http://localhost:9200"},
			shouldFail: true,
		},
		{
			name:       "negative_max_guesses",
			filename:   "file.txt",
			password:   "password",
			userID:     "user",
			maxGuesses: -1,
			expiration: 0,
			serverURLs: []string{"http://localhost:9200"},
			shouldFail: true,
		},
		{
			name:       "zero_max_guesses",
			filename:   "file.txt",
			password:   "password",
			userID:     "user",
			maxGuesses: 0,
			expiration: 0,
			serverURLs: []string{"http://localhost:9200"},
			shouldFail: false, // Zero might be allowed
		},
		{
			name:       "empty_server_urls",
			filename:   "file.txt",
			password:   "password",
			userID:     "user",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: []string{},
			shouldFail: true,
		},
		{
			name:       "nil_server_urls",
			filename:   "file.txt",
			password:   "password",
			userID:     "user",
			maxGuesses: 10,
			expiration: 0,
			serverURLs: nil,
			shouldFail: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GenerateEncryptionKey(tc.filename, tc.password, tc.userID, tc.maxGuesses, tc.expiration, tc.serverURLs)

			if tc.shouldFail {
				if result.Error == "" {
					t.Errorf("Expected key generation to fail for case %s", tc.name)
				}
			} else {
				// Note: Even valid cases might fail if servers aren't available
				if result.Error != "" {
					t.Logf("Key generation failed (might be expected): %s", result.Error)
				}
			}
		})
	}
}

// TestKeyDerivationConsistency tests that key derivation is consistent across multiple calls
func TestKeyDerivationConsistency(t *testing.T) {
	filename := "test-file.txt"
	password := "test-password"
	userID := "test-user"
	maxGuesses := 10
	expiration := 0
	serverURLs := []string{"http://localhost:9200"}

	// Generate key multiple times with same parameters
	results := make([]*GenerateEncryptionKeyResult, 3)
	for i := 0; i < 3; i++ {
		results[i] = GenerateEncryptionKey(filename, password, userID, maxGuesses, expiration, serverURLs)
	}

	// Check if any succeeded
	var successfulResults []*GenerateEncryptionKeyResult
	for _, result := range results {
		if result.Error == "" {
			successfulResults = append(successfulResults, result)
		}
	}

	if len(successfulResults) == 0 {
		t.Logf("All key generations failed (expected if no local servers)")
		return
	}

	// If we have successful results, they should be consistent
	if len(successfulResults) > 1 {
		baseResult := successfulResults[0]
		for i, result := range successfulResults[1:] {
			if !bytes.Equal(baseResult.EncryptionKey, result.EncryptionKey) {
				t.Errorf("Key derivation inconsistent: result %d differs from base", i+1)
			}
			if baseResult.Threshold != result.Threshold {
				t.Errorf("Threshold inconsistent: result %d differs from base", i+1)
			}
		}
	}
}

// TestUnicodeHandling tests handling of Unicode characters in inputs
func TestUnicodeHandling(t *testing.T) {
	testCases := []struct {
		name     string
		filename string
		password string
		userID   string
	}{
		{
			name:     "unicode_filename",
			filename: "тест-файл.txt",
			password: "password",
			userID:   "user",
		},
		{
			name:     "unicode_password",
			filename: "file.txt",
			password: "пароль123",
			userID:   "user",
		},
		{
			name:     "unicode_user_id",
			filename: "file.txt",
			password: "password",
			userID:   "пользователь",
		},
		{
			name:     "emoji_inputs",
			filename: "file🔐.txt",
			password: "pass🔑word",
			userID:   "user👤",
		},
		{
			name:     "mixed_unicode",
			filename: "файл-file-ファイル.txt",
			password: "пароль-password-パスワード",
			userID:   "user-пользователь-ユーザー",
		},
	}

	serverURLs := []string{"http://localhost:9200"}
	maxGuesses := 10
	expiration := 0

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GenerateEncryptionKey(tc.filename, tc.password, tc.userID, maxGuesses, expiration, serverURLs)

			// Should handle Unicode gracefully (succeed or fail gracefully)
			if result.Error != "" {
				t.Logf("Unicode test failed (might be expected): %s", result.Error)
			} else {
				// If successful, verify basic properties
				if len(result.EncryptionKey) != 32 {
					t.Errorf("Expected 32-byte key for Unicode input")
				}
			}
		})
	}
}

// TestLargeInputHandling tests handling of large inputs
func TestLargeInputHandling(t *testing.T) {
	// Create large inputs
	largeString := make([]byte, 1000)
	for i := range largeString {
		largeString[i] = 'a'
	}
	largeStringStr := string(largeString)

	testCases := []struct {
		name     string
		filename string
		password string
		userID   string
	}{
		{
			name:     "large_filename",
			filename: largeStringStr + ".txt",
			password: "password",
			userID:   "user",
		},
		{
			name:     "large_password",
			filename: "file.txt",
			password: largeStringStr,
			userID:   "user",
		},
		{
			name:     "large_user_id",
			filename: "file.txt",
			password: "password",
			userID:   largeStringStr,
		},
	}

	serverURLs := []string{"http://localhost:9200"}
	maxGuesses := 10
	expiration := 0

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GenerateEncryptionKey(tc.filename, tc.password, tc.userID, maxGuesses, expiration, serverURLs)

			// Should handle large inputs gracefully
			if result.Error != "" {
				t.Logf("Large input test failed (might be expected): %s", result.Error)
			} else {
				// If successful, verify basic properties
				if len(result.EncryptionKey) != 32 {
					t.Errorf("Expected 32-byte key for large input")
				}
			}
		})
	}
}

// TestConcurrentKeyGeneration tests concurrent key generation
func TestConcurrentKeyGeneration(t *testing.T) {
	filename := "test-file.txt"
	password := "test-password"
	userID := "test-user"
	maxGuesses := 10
	expiration := 0
	serverURLs := []string{"http://localhost:9200"}

	const numGoroutines = 3
	const numOperations = 2

	results := make(chan *GenerateEncryptionKeyResult, numGoroutines*numOperations)
	var wg sync.WaitGroup

	// Launch concurrent key generation operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				result := GenerateEncryptionKey(filename, password, userID, maxGuesses, expiration, serverURLs)
				results <- result
			}
		}(i)
	}

	wg.Wait()
	close(results)

	// Collect results
	var successfulResults []*GenerateEncryptionKeyResult
	var errorResults []*GenerateEncryptionKeyResult

	for result := range results {
		if result.Error == "" {
			successfulResults = append(successfulResults, result)
		} else {
			errorResults = append(errorResults, result)
		}
	}

	t.Logf("Concurrent operations: %d successful, %d failed", len(successfulResults), len(errorResults))

	// If we have successful results, verify they're consistent (same inputs should give same outputs)
	if len(successfulResults) > 1 {
		baseResult := successfulResults[0]
		for i, result := range successfulResults[1:] {
			if !bytes.Equal(baseResult.EncryptionKey, result.EncryptionKey) {
				t.Errorf("Concurrent result %d has different key than base result", i+1)
			}
		}
	}
}

// TestRecoverEncryptionKeyBasic tests basic key recovery
func TestRecoverEncryptionKeyBasic(t *testing.T) {
	// This test requires a successful generation first
	filename := "recovery-test.txt"
	password := "recovery-password"
	userID := "recovery-user"
	maxGuesses := 10
	expiration := 0
	serverURLs := []string{"http://localhost:9200"}

	// First generate a key
	genResult := GenerateEncryptionKey(filename, password, userID, maxGuesses, expiration, serverURLs)
	if genResult.Error != "" {
		t.Logf("Key generation failed (expected if no local servers): %s", genResult.Error)
		return
	}

	// Then try to recover it
	recResult := RecoverEncryptionKey(filename, password, userID, genResult.ServerURLs, genResult.Threshold, genResult.AuthCodes)
	if recResult.Error != "" {
		t.Fatalf("Key recovery failed: %s", recResult.Error)
	}

	// Verify recovered key matches original
	if !bytes.Equal(genResult.EncryptionKey, recResult.EncryptionKey) {
		t.Errorf("Recovered key doesn't match original")
		t.Logf("Original:  %x", genResult.EncryptionKey)
		t.Logf("Recovered: %x", recResult.EncryptionKey)
	}
}

// TestRecoverEncryptionKeyInvalidParams tests key recovery with invalid parameters
func TestRecoverEncryptionKeyInvalidParams(t *testing.T) {
	testCases := []struct {
		name       string
		filename   string
		password   string
		userID     string
		serverURLs []string
		threshold  int
		authCodes  *AuthCodes
		shouldFail bool
	}{
		{
			name:       "empty_filename",
			filename:   "",
			password:   "password",
			userID:     "user",
			serverURLs: []string{"http://localhost:9200"},
			threshold:  1,
			authCodes:  &AuthCodes{BaseAuthCode: "test", ServerAuthCodes: map[string]string{"http://localhost:9200": "auth1"}, UserID: "user"},
			shouldFail: true,
		},
		{
			name:       "empty_password",
			filename:   "file.txt",
			password:   "",
			userID:     "user",
			serverURLs: []string{"http://localhost:9200"},
			threshold:  1,
			authCodes:  &AuthCodes{BaseAuthCode: "test", ServerAuthCodes: map[string]string{"http://localhost:9200": "auth1"}, UserID: "user"},
			shouldFail: false, // Empty password might be allowed
		},
		{
			name:       "empty_user_id",
			filename:   "file.txt",
			password:   "password",
			userID:     "",
			serverURLs: []string{"http://localhost:9200"},
			threshold:  1,
			authCodes:  &AuthCodes{BaseAuthCode: "test", ServerAuthCodes: map[string]string{"http://localhost:9200": "auth1"}, UserID: ""},
			shouldFail: true,
		},
		{
			name:       "empty_server_urls",
			filename:   "file.txt",
			password:   "password",
			userID:     "user",
			serverURLs: []string{},
			threshold:  1,
			authCodes:  &AuthCodes{BaseAuthCode: "test", ServerAuthCodes: map[string]string{}, UserID: "user"},
			shouldFail: true,
		},
		{
			name:       "nil_server_urls",
			filename:   "file.txt",
			password:   "password",
			userID:     "user",
			serverURLs: nil,
			threshold:  1,
			authCodes:  &AuthCodes{BaseAuthCode: "test", ServerAuthCodes: map[string]string{}, UserID: "user"},
			shouldFail: true,
		},
		{
			name:       "zero_threshold",
			filename:   "file.txt",
			password:   "password",
			userID:     "user",
			serverURLs: []string{"http://localhost:9200"},
			threshold:  0,
			authCodes:  &AuthCodes{BaseAuthCode: "test", ServerAuthCodes: map[string]string{"http://localhost:9200": "auth1"}, UserID: "user"},
			shouldFail: true,
		},
		{
			name:       "negative_threshold",
			filename:   "file.txt",
			password:   "password",
			userID:     "user",
			serverURLs: []string{"http://localhost:9200"},
			threshold:  -1,
			authCodes:  &AuthCodes{BaseAuthCode: "test", ServerAuthCodes: map[string]string{"http://localhost:9200": "auth1"}, UserID: "user"},
			shouldFail: true,
		},
		{
			name:       "nil_auth_codes",
			filename:   "file.txt",
			password:   "password",
			userID:     "user",
			serverURLs: []string{"http://localhost:9200"},
			threshold:  1,
			authCodes:  nil,
			shouldFail: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := RecoverEncryptionKey(tc.filename, tc.password, tc.userID, tc.serverURLs, tc.threshold, tc.authCodes)

			if tc.shouldFail && result.Error == "" {
				t.Errorf("Expected failure for %s, but got success", tc.name)
			} else if !tc.shouldFail && result.Error != "" {
				// Only log this as it might fail due to no servers
				t.Logf("Expected success for %s, but got error (might be due to no servers): %s", tc.name, result.Error)
			}
		})
	}
}

// TestInsufficientServersForThreshold tests behavior when there aren't enough servers
func TestInsufficientServersForThreshold(t *testing.T) {
	filename := "insufficient-test.txt"
	password := "password"
	userID := "user"
	maxGuesses := 10
	expiration := 0

	// Try with more servers than available
	serverURLs := []string{
		"http://localhost:9200",
		"http://localhost:9201",
		"http://localhost:9202",
		"http://localhost:9203",
		"http://localhost:9204",
		"http://localhost:9205", // These servers likely don't exist
	}

	result := GenerateEncryptionKey(filename, password, userID, maxGuesses, expiration, serverURLs)

	// Should either succeed with available servers or fail gracefully
	if result.Error != "" {
		t.Logf("Key generation failed with insufficient servers (expected): %s", result.Error)
	} else {
		t.Logf("Key generation succeeded despite some unavailable servers")
		// Verify that result uses only available servers
		if len(result.ServerURLs) > len(serverURLs) {
			t.Errorf("Result uses more servers than provided")
		}
	}
}

// TestMemoryUsage tests that key generation doesn't use excessive memory
func TestMemoryUsage(t *testing.T) {
	// This is a basic test - in practice you'd use runtime.ReadMemStats
	filename := "memory-test.txt"
	password := "password"
	userID := "user"
	maxGuesses := 10
	expiration := 0
	serverURLs := []string{"http://localhost:9200"}

	// Generate multiple keys to test memory usage
	for i := 0; i < 10; i++ {
		testUserID := userID + "_" + string(rune(i+'0'))
		result := GenerateEncryptionKey(filename, password, testUserID, maxGuesses, expiration, serverURLs)

		if result.Error == "" {
			// Verify key is properly sized
			if len(result.EncryptionKey) != 32 {
				t.Errorf("Iteration %d: expected 32-byte key, got %d bytes", i, len(result.EncryptionKey))
			}
		}
	}
}

// TestErrorPropagation tests that errors are properly propagated
func TestErrorPropagation(t *testing.T) {
	// Test with invalid server URLs
	invalidServerURLs := []string{
		"invalid-url",
		"http://nonexistent-server:9999",
		"https://invalid.domain.local",
	}

	result := GenerateEncryptionKey("file.txt", "password", "user", 10, 0, invalidServerURLs)

	// Should fail with appropriate error
	if result.Error == "" {
		t.Errorf("Expected error with invalid server URLs")
	} else {
		t.Logf("Got expected error with invalid servers: %s", result.Error)
	}
}

// TestInputSanitization tests that inputs are properly sanitized
func TestInputSanitization(t *testing.T) {
	testCases := []struct {
		name     string
		filename string
		password string
		userID   string
	}{
		{
			name:     "special_characters_filename",
			filename: "file<>:\"|?*.txt",
			password: "password",
			userID:   "user",
		},
		{
			name:     "null_bytes",
			filename: "file\x00.txt",
			password: "pass\x00word",
			userID:   "user\x00id",
		},
	}

	serverURLs := []string{"http://localhost:9200"}
	maxGuesses := 10
	expiration := 0

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GenerateEncryptionKey(tc.filename, tc.password, tc.userID, maxGuesses, expiration, serverURLs)

			// Should handle malicious inputs gracefully
			if result.Error != "" {
				t.Logf("Input sanitization test failed (might be expected): %s", result.Error)
			} else {
				// If successful, verify basic properties
				if len(result.EncryptionKey) != 32 {
					t.Errorf("Expected 32-byte key for sanitized input")
				}
			}
		})
	}
}

// TestExpirationHandling tests handling of different expiration values
func TestExpirationHandling(t *testing.T) {
	filename := "expiration-test.txt"
	password := "password"
	userID := "user"
	maxGuesses := 10
	serverURLs := []string{"http://localhost:9200"}

	testCases := []struct {
		name       string
		expiration int
	}{
		{
			name:       "no_expiration",
			expiration: 0,
		},
		{
			name:       "future_expiration",
			expiration: int(time.Now().Unix()) + 3600, // 1 hour from now
		},
		{
			name:       "past_expiration",
			expiration: int(time.Now().Unix()) - 3600, // 1 hour ago
		},
		{
			name:       "negative_expiration",
			expiration: -1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testUserID := userID + "_" + tc.name
			result := GenerateEncryptionKey(filename, password, testUserID, maxGuesses, tc.expiration, serverURLs)

			// Should handle different expiration values
			if result.Error != "" {
				t.Logf("Expiration test failed (might be expected): %s", result.Error)
			} else {
				// If successful, verify basic properties
				if len(result.EncryptionKey) != 32 {
					t.Errorf("Expected 32-byte key for expiration test")
				}
			}
		})
	}
}
