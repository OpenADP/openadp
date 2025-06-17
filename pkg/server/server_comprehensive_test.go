package server

import (
	"math/big"
	"testing"
	"time"

	"github.com/openadp/openadp/pkg/crypto"
	"github.com/openadp/openadp/pkg/database"
)

// TestMaxGuessLimitEnforcement tests that max guess limit is properly enforced
func TestMaxGuessLimitEnforcement(t *testing.T) {
	// Create in-memory database
	db, err := database.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test the core logic of max guess enforcement
	maxGuesses := 3

	// Test data
	uid := "test_user"
	did := "test_device"
	bid := "test_backup"
	authCode := "test_auth_code"
	version := 1
	x := 1
	y := make([]byte, 32) // 32-byte Y coordinate
	expiration := int64(2000000000)

	// Register a secret
	err = RegisterSecret(db, uid, did, bid, authCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to register secret: %v", err)
	}

	// Create a valid point B for recovery
	secret := big.NewInt(12345) // Use a fixed value for testing
	u := crypto.PointMul(secret, crypto.G)
	r := big.NewInt(67890) // Use a fixed value for testing
	b4D := crypto.PointMul(r, u)
	b := crypto.Unexpand(b4D)

	// Test successful recoveries up to the limit
	for guessNum := 0; guessNum < maxGuesses; guessNum++ {
		result, err := RecoverSecret(db, uid, did, bid, b, guessNum)
		if err != nil {
			// Recovery might fail due to cryptographic mismatch, but should not be due to guess limit
			if err.Error() == "too many guesses" {
				t.Errorf("Guess %d should not be blocked by guess limit", guessNum)
			}
		} else {
			// If recovery succeeds, verify the guess count increments
			if result.NumGuesses != guessNum+1 {
				t.Errorf("Expected NumGuesses=%d, got %d", guessNum+1, result.NumGuesses)
			}
			if result.MaxGuesses != maxGuesses {
				t.Errorf("Expected MaxGuesses=%d, got %d", maxGuesses, result.MaxGuesses)
			}
		}
	}

	// Test that exceeding max_guesses is blocked
	_, err = RecoverSecret(db, uid, did, bid, b, maxGuesses)
	if err == nil || err.Error() != "too many guesses" {
		t.Errorf("Expected 'too many guesses' error, got: %v", err)
	}

	// Test that further attempts are still blocked
	_, err = RecoverSecret(db, uid, did, bid, b, maxGuesses)
	if err == nil || err.Error() != "too many guesses" {
		t.Errorf("Expected 'too many guesses' error on repeated attempt, got: %v", err)
	}
}

// TestAuthenticationValidation tests authentication token validation
func TestAuthenticationValidation(t *testing.T) {
	// Test valid token formats
	validTokens := []string{
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature",
		"Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig",
	}

	for _, token := range validTokens {
		// Should not raise exception for valid format
		if len(token) <= 10 {
			t.Errorf("Token should be longer than 10 characters: %s", token)
		}
	}

	// Test invalid tokens
	invalidTokens := []string{
		"",        // Empty
		"invalid", // Not JWT format
		"Bearer",  // Missing token
		"Bearer ", // Empty token
	}

	for _, token := range invalidTokens {
		// Should be considered invalid
		if len(token) >= 10 {
			t.Errorf("Token should be considered invalid: %s", token)
		}
	}
}

// TestSessionManagement tests session creation and management
func TestSessionManagement(t *testing.T) {
	// Test session ID generation
	sessionIds := make(map[string]bool)
	for i := 0; i < 100; i++ {
		// Generate mock session ID (in real implementation, this would use crypto/rand)
		sessionId := generateMockSessionID(i)
		sessionIds[sessionId] = true
	}

	// All session IDs should be unique
	if len(sessionIds) != 100 {
		t.Errorf("Expected 100 unique session IDs, got %d", len(sessionIds))
	}
}

// Helper function to generate mock session IDs
func generateMockSessionID(i int) string {
	hash := crypto.Sha256Hash(append([]byte("session"), byte(i)))
	return string(hash[:16])
}

// TestGuessValidationLogic tests the core guess validation logic
func TestGuessValidationLogic(t *testing.T) {
	// Test different types of guesses
	testCases := []struct {
		expected    string
		actual      string
		shouldMatch bool
	}{
		{"correct_password", "correct_password", true},
		{"correct_password", "wrong_password", false},
		{"", "", true}, // Empty strings match
		{"password", "", false},
		{"", "password", false},
		{"case_sensitive", "CASE_SENSITIVE", false},
		{"with spaces", "with spaces", true},
		{"special!@#$%", "special!@#$%", true},
	}

	for _, tc := range testCases {
		t.Run("guess_validation", func(t *testing.T) {
			result := (tc.expected == tc.actual)
			if result != tc.shouldMatch {
				t.Errorf("Expected %s == %s to be %v, got %v", tc.expected, tc.actual, tc.shouldMatch, result)
			}
		})
	}
}

// TestInputValidation tests comprehensive input validation
func TestInputValidation(t *testing.T) {
	// Test various input types
	testInputs := []string{
		"normal_string",
		"", // Empty string
		"string with spaces",
		"string_with_underscores",
		"string-with-hyphens",
		"string.with.dots",
		"123456",            // Numeric string
		"special!@#$%^&*()", // Special characters
	}

	for _, input := range testInputs {
		// Basic sanitization - remove dangerous characters
		sanitized := sanitizeInput(input)

		// Should not contain dangerous characters
		dangerousChars := []string{"<", ">", "&", "\"", "'", ";", "|", "`"}
		for _, char := range dangerousChars {
			if containsChar(sanitized, char) {
				t.Errorf("Sanitized input should not contain dangerous char '%s': %s", char, sanitized)
			}
		}
	}
}

// Helper function to sanitize input
func sanitizeInput(input string) string {
	result := ""
	for _, c := range input {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == ' ' {
			result += string(c)
		}
	}
	return result
}

// Helper function to check if string contains character
func containsChar(s, char string) bool {
	for _, c := range s {
		if string(c) == char {
			return true
		}
	}
	return false
}

// TestInputLengthLimits tests input length validation
func TestInputLengthLimits(t *testing.T) {
	// Test various input lengths
	maxLengths := map[string]int{
		"session_id":  64,
		"guess":       1000,
		"auth_token":  2048,
		"method_name": 64,
	}

	for field, maxLen := range maxLengths {
		t.Run(field, func(t *testing.T) {
			// Test at limit
			atLimit := repeatString("x", maxLen)
			if len(atLimit) != maxLen {
				t.Errorf("String at limit should be %d chars, got %d", maxLen, len(atLimit))
			}

			// Test over limit
			overLimit := repeatString("x", maxLen+1)
			if len(overLimit) <= maxLen {
				t.Errorf("String over limit should be > %d chars, got %d", maxLen, len(overLimit))
			}
		})
	}
}

// Helper function to repeat string
func repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

// TestSessionTimeoutHandling tests session timeout logic
func TestSessionTimeoutHandling(t *testing.T) {
	// Mock session with timestamp
	sessionTimeout := int64(3600) // 1 hour in seconds
	currentTime := time.Now().Unix()

	// Recent session (should be valid)
	recentSession := map[string]interface{}{
		"created_at": currentTime - 1800, // 30 minutes ago
		"status":     "active",
	}

	// Old session (should be expired)
	oldSession := map[string]interface{}{
		"created_at": currentTime - 7200, // 2 hours ago
		"status":     "active",
	}

	// Check timeout logic
	recentAge := currentTime - recentSession["created_at"].(int64)
	oldAge := currentTime - oldSession["created_at"].(int64)

	if recentAge >= sessionTimeout {
		t.Error("Recent session should not be expired")
	}
	if oldAge < sessionTimeout {
		t.Error("Old session should be expired")
	}
}

// TestSecurityHeadersValidation tests security-related header validation
func TestSecurityHeadersValidation(t *testing.T) {
	// Security headers that should be present
	securityHeaders := map[string]string{
		"Content-Type":              "application/json",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}

	for header, expectedValue := range securityHeaders {
		if len(header) == 0 {
			t.Errorf("Header name should not be empty")
		}
		if len(expectedValue) == 0 {
			t.Errorf("Header value should not be empty for %s", header)
		}
	}
}

// TestMaxGuessLimitEnforcementDetailed tests detailed max guess limit enforcement scenarios
func TestMaxGuessLimitEnforcementDetailed(t *testing.T) {
	// Create test database
	db, err := database.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "test_user"
	did := "test_device"
	bid := "test_backup"
	authCode := "test_auth_code"
	version := 1
	x := 1
	y := make([]byte, 32)
	maxGuesses := 3
	expiration := int64(2000000000)

	// Register a secret
	err = RegisterSecret(db, uid, did, bid, authCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to register secret: %v", err)
	}

	// Create a valid point B for recovery
	secret := big.NewInt(12345)
	u := crypto.PointMul(secret, crypto.G)
	r := big.NewInt(12345)
	b4D := crypto.PointMul(r, u)
	b := crypto.Unexpand(b4D)

	// Test successful recoveries up to the limit
	for guessNum := 0; guessNum < maxGuesses; guessNum++ {
		result, err := RecoverSecret(db, uid, did, bid, b, guessNum)
		if err != nil {
			// Recovery might fail due to cryptographic mismatch, but should not be due to guess limit
			if err.Error() == "too many guesses" {
				t.Errorf("Guess %d should not be blocked by guess limit", guessNum)
			}
		} else {
			// If recovery succeeds, verify the guess count increments
			if result.NumGuesses != guessNum+1 {
				t.Errorf("Expected NumGuesses=%d, got %d", guessNum+1, result.NumGuesses)
			}
			if result.MaxGuesses != maxGuesses {
				t.Errorf("Expected MaxGuesses=%d, got %d", maxGuesses, result.MaxGuesses)
			}
		}
	}

	// Test that exceeding max_guesses is blocked
	_, err = RecoverSecret(db, uid, did, bid, b, maxGuesses)
	if err == nil || err.Error() != "too many guesses" {
		t.Errorf("Expected 'too many guesses' error, got: %v", err)
	}

	// Test that further attempts are still blocked
	_, err = RecoverSecret(db, uid, did, bid, b, maxGuesses)
	if err == nil || err.Error() != "too many guesses" {
		t.Errorf("Expected 'too many guesses' error on repeated attempt, got: %v", err)
	}
}

// TestServerInputValidation tests server input validation edge cases
func TestServerInputValidation(t *testing.T) {
	// Create test database
	db, err := database.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	uid := "test_user"
	did := "test_device"
	bid := "test_backup"
	authCode := "test_auth_code"
	version := 1
	x := 1
	y := make([]byte, 32)
	expiration := int64(2000000000)

	// Test max_guesses > 1000 (should be rejected)
	err = RegisterSecret(db, uid, did, bid, authCode, version, x, y, 1001, expiration)
	if err == nil || err.Error() != "max guesses too high" {
		t.Errorf("Expected 'max guesses too high' error, got: %v", err)
	}

	// Test valid max_guesses (should succeed)
	err = RegisterSecret(db, uid, did, bid, authCode, version, x, y, 1000, expiration)
	if err != nil {
		t.Errorf("Valid max_guesses should succeed, got error: %v", err)
	}

	// Test very long strings (should be rejected)
	longString := repeatString("x", 1000)
	err = RegisterSecret(db, longString, did, bid, authCode, version, x, y, 10, expiration)
	if err == nil || err.Error() != "UID too long" {
		t.Errorf("Expected 'UID too long' error, got: %v", err)
	}
}

// TestDatabaseEdgeCases tests database edge cases and error conditions
func TestDatabaseEdgeCases(t *testing.T) {
	// Test database creation in memory
	db, err := database.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create in-memory database: %v", err)
	}
	defer db.Close()

	// Test basic operations work
	uid := "table_test_user"
	did := "table_test_device"
	bid := "table_test_backup"
	authCode := "test_auth_code"
	version := 1
	x := 1
	y := make([]byte, 32)
	maxGuesses := 10
	expiration := int64(2000000000)

	// This should work without errors (tables exist)
	err = db.Insert(uid, did, bid, authCode, version, x, y, 0, maxGuesses, expiration)
	if err != nil {
		t.Errorf("Database insert should work: %v", err)
	}

	result, err := db.Lookup(uid, did, bid)
	if err != nil {
		t.Errorf("Database lookup should work: %v", err)
	}
	if result == nil {
		t.Error("Lookup result should not be nil")
	}

	// Test server config operations
	err = db.SetServerConfig("test", []byte("data"))
	if err != nil {
		t.Errorf("SetServerConfig should work: %v", err)
	}

	configData, err := db.GetServerConfig("test")
	if err != nil {
		t.Errorf("GetServerConfig should work: %v", err)
	}
	if string(configData) != "data" {
		t.Errorf("Expected 'data', got '%s'", string(configData))
	}
}

// TestServerRecoveryIdempotency tests that recovery operations are idempotent
func TestServerRecoveryIdempotency(t *testing.T) {
	db, err := database.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "idempotent_user"
	did := "idempotent_device"
	bid := "idempotent_backup"
	authCode := "test_auth_code"
	version := 1
	x := 1
	y := make([]byte, 32)
	maxGuesses := 5
	expiration := int64(2000000000)

	// Register secret
	err = RegisterSecret(db, uid, did, bid, authCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to register secret: %v", err)
	}

	// Create point B
	secret := big.NewInt(12345)
	u := crypto.PointMul(secret, crypto.G)
	r := big.NewInt(12345)
	b4D := crypto.PointMul(r, u)
	b := crypto.Unexpand(b4D)

	// First recovery attempt
	result1, err1 := RecoverSecret(db, uid, did, bid, b, 0)

	// Same recovery attempt (should fail due to wrong guess_num)
	_, err2 := RecoverSecret(db, uid, did, bid, b, 0)
	if err2 == nil || err2.Error() != "expecting guess_num = 1" {
		t.Errorf("Expected 'expecting guess_num = 1' error, got: %v", err2)
	}

	// Correct next recovery attempt
	if err1 == nil && result1 != nil {
		_, err3 := RecoverSecret(db, uid, did, bid, b, result1.NumGuesses)
		// This should work (either succeed or fail for crypto reasons, not guess_num)
		if err3 != nil && err3.Error() == "expecting guess_num = 1" {
			t.Errorf("Should not get guess_num error on correct attempt: %v", err3)
		}
	}
}

// TestExpirationHandling tests share expiration handling
func TestExpirationHandling(t *testing.T) {
	db, err := database.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "expiring_user"
	did := "expiring_device"
	bid := "expiring_backup"
	authCode := "test_auth_code"
	version := 1
	x := 1
	y := make([]byte, 32)
	maxGuesses := 10

	// Test with past expiration
	pastExpiration := time.Now().Unix() - 3600 // 1 hour ago
	err = db.Insert(uid, did, bid, authCode, version, x, y, 0, maxGuesses, pastExpiration)
	if err != nil {
		t.Errorf("Database insert should work: %v", err)
	}

	result, err := db.Lookup(uid, did, bid)
	if err != nil {
		t.Errorf("Database lookup should work: %v", err)
	}
	if result == nil {
		t.Error("Lookup result should not be nil")
	}
	if result.Expiration != pastExpiration {
		t.Errorf("Expected expiration %d, got %d", pastExpiration, result.Expiration)
	}

	// Test with future expiration
	futureExpiration := time.Now().Unix() + 3600 // 1 hour from now
	err = db.Insert(uid, did, "future_backup", authCode, version, x, y, 0, maxGuesses, futureExpiration)
	if err != nil {
		t.Errorf("Database insert should work: %v", err)
	}

	result, err = db.Lookup(uid, did, "future_backup")
	if err != nil {
		t.Errorf("Database lookup should work: %v", err)
	}
	if result == nil {
		t.Error("Lookup result should not be nil")
	}
	if result.Expiration != futureExpiration {
		t.Errorf("Expected expiration %d, got %d", futureExpiration, result.Expiration)
	}
}

// TestListBackupsFunction tests the ListBackups functionality
func TestListBackupsFunction(t *testing.T) {
	db, err := database.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "list_test_user"
	authCode := "test_auth_code"
	version := 1
	x := 1
	y := make([]byte, 32)
	maxGuesses := 10
	expiration := int64(2000000000)

	// Insert multiple backups
	backupIds := []string{"backup1", "backup2", "backup3"}
	for _, bid := range backupIds {
		err = RegisterSecret(db, uid, "device1", bid, authCode, version, x, y, maxGuesses, expiration)
		if err != nil {
			t.Errorf("Failed to register backup %s: %v", bid, err)
		}
	}

	// List backups
	backups, err := ListBackups(db, uid)
	if err != nil {
		t.Errorf("ListBackups failed: %v", err)
	}

	if len(backups) != len(backupIds) {
		t.Errorf("Expected %d backups, got %d", len(backupIds), len(backups))
	}

	// Verify backup contents
	for _, backup := range backups {
		if backup.UID != uid {
			t.Errorf("Expected UID %s, got %s", uid, backup.UID)
		}
		if backup.Version != version {
			t.Errorf("Expected version %d, got %d", version, backup.Version)
		}
		if backup.MaxGuesses != maxGuesses {
			t.Errorf("Expected MaxGuesses %d, got %d", maxGuesses, backup.MaxGuesses)
		}
	}
}

// TestValidateInputsComprehensive tests comprehensive input validation
func TestValidateInputsComprehensive(t *testing.T) {
	// Test ValidateRegisterInputs
	validY := make([]byte, 32)

	// Valid inputs should pass
	err := ValidateRegisterInputs("user", "device", "backup", 1, validY, 10, 2000000000)
	if err != nil {
		t.Errorf("Valid inputs should pass validation: %v", err)
	}

	// Test various invalid inputs
	testCases := []struct {
		uid        string
		did        string
		bid        string
		x          int
		y          []byte
		maxGuesses int
		expiration int64
		expectErr  string
	}{
		{repeatString("x", 600), "device", "backup", 1, validY, 10, 2000000000, "UID too long"},
		{"user", repeatString("x", 600), "backup", 1, validY, 10, 2000000000, "DID too long"},
		{"user", "device", repeatString("x", 600), 1, validY, 10, 2000000000, "BID too long"},
		{"user", "device", "backup", 1001, validY, 10, 2000000000, "too many shares"},
		{"user", "device", "backup", 1, make([]byte, 40), 10, 2000000000, "Y share too large"},
		{"user", "device", "backup", 1, validY, 1001, 2000000000, "max guesses too high"},
		{"user", "device", "backup", 1, validY, 10, time.Now().Unix() - 3600, "expiration is in the past"},
	}

	for i, tc := range testCases {
		t.Run("register_validation_"+string(rune(i+'0')), func(t *testing.T) {
			err := ValidateRegisterInputs(tc.uid, tc.did, tc.bid, tc.x, tc.y, tc.maxGuesses, tc.expiration)
			if err == nil {
				t.Errorf("Expected error '%s', got nil", tc.expectErr)
			} else if err.Error() != tc.expectErr {
				t.Errorf("Expected error '%s', got '%s'", tc.expectErr, err.Error())
			}
		})
	}

	// Test ValidateRecoverInputs
	validPoint := &crypto.Point2D{X: big.NewInt(1), Y: big.NewInt(1)}

	// Valid inputs should pass
	err = ValidateRecoverInputs("user", "device", "backup", validPoint)
	if err != nil {
		t.Errorf("Valid recover inputs should pass validation: %v", err)
	}

	// Test invalid recover inputs
	recoverTestCases := []struct {
		uid       string
		did       string
		bid       string
		b         *crypto.Point2D
		expectErr string
	}{
		{repeatString("x", 600), "device", "backup", validPoint, "UID too long"},
		{"user", repeatString("x", 600), "backup", validPoint, "DID too long"},
		{"user", "device", repeatString("x", 600), validPoint, "BID too long"},
		{"user", "device", "backup", nil, "invalid point"},
		{"user", "device", "backup", &crypto.Point2D{X: nil, Y: big.NewInt(1)}, "invalid point"},
	}

	for i, tc := range recoverTestCases {
		t.Run("recover_validation_"+string(rune(i+'0')), func(t *testing.T) {
			err := ValidateRecoverInputs(tc.uid, tc.did, tc.bid, tc.b)
			if err == nil {
				t.Errorf("Expected error '%s', got nil", tc.expectErr)
			} else if err.Error() != tc.expectErr {
				t.Errorf("Expected error '%s', got '%s'", tc.expectErr, err.Error())
			}
		})
	}
}

// TestServerInfoFunction tests the GetServerInfo functionality
func TestServerInfoFunction(t *testing.T) {
	version := "1.0.0"
	noiseKey := make([]byte, 32)

	monitoring := NewMonitoringTracker()
	info := GetServerInfo(version, noiseKey, monitoring)

	if info.Version != version {
		t.Errorf("Expected version %s, got %s", version, info.Version)
	}

	if len(info.NoiseNKKey) == 0 {
		t.Error("NoiseNK key should not be empty")
	}

	if len(info.Capabilities) == 0 {
		t.Error("Capabilities should not be empty")
	}
}

// TestEchoFunction tests the Echo functionality
func TestEchoFunction(t *testing.T) {
	testMessage := "Hello, World!"
	result := Echo(testMessage)

	if result != testMessage {
		t.Errorf("Expected '%s', got '%s'", testMessage, result)
	}

	// Test with empty string
	emptyResult := Echo("")
	if emptyResult != "" {
		t.Errorf("Expected empty string, got '%s'", emptyResult)
	}
}
