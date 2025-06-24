package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty string", "", 0},
		{"single char", "a", 0},
		{"repeated chars", "aaaa", 0},
		{"mixed hex", "0123456789abcdef", 64},
		{"high entropy", "a1b2c3d4e5f6789012345678901234567890123456789012345678901234", 222},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateEntropy(tt.input)
			if result != tt.expected {
				t.Errorf("CalculateEntropy(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateAuthCodeFormat(t *testing.T) {
	config := &AuthCodeConfig{
		MinEntropyBits: 100,
	}

	tests := []struct {
		name     string
		authCode string
		expected bool
	}{
		{"valid format", "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678", true},
		{"too short", "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567", false},
		{"too long", "a1b2c3d4e5f678901234567890123456789012345678901234567890123456789", false},
		{"invalid chars", "g1b2c3d4e5f67890123456789012345678901234567890123456789012345678", false},
		{"uppercase", "A1B2C3D4E5F67890123456789012345678901234567890123456789012345678", true},
		{"low entropy", "0000000000000000000000000000000000000000000000000000000000000000", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateAuthCodeFormat(tt.authCode, config)
			if result != tt.expected {
				t.Errorf("ValidateAuthCodeFormat(%q) = %t, want %t", tt.authCode, result, tt.expected)
			}
		})
	}
}

func TestDeriveServerAuthCode(t *testing.T) {
	baseCode := "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
	serverURL := "https://example.com"

	result1 := DeriveServerAuthCode(baseCode, serverURL)
	result2 := DeriveServerAuthCode(baseCode, serverURL)

	// Should be deterministic
	if result1 != result2 {
		t.Errorf("DeriveServerAuthCode should be deterministic")
	}

	// Should be 64 hex characters
	if len(result1) != 64 {
		t.Errorf("DeriveServerAuthCode result length = %d, want 64", len(result1))
	}

	// Different URLs should produce different results
	result3 := DeriveServerAuthCode(baseCode, "https://different.com")
	if result1 == result3 {
		t.Errorf("Different server URLs should produce different auth codes")
	}
}

func TestDDosDefense(t *testing.T) {
	// Clear state
	ddosMutex.Lock()
	failedAttempts = make(map[string]int)
	attemptTimestamps = make(map[string]time.Time)
	ddosMutex.Unlock()

	config := &AuthCodeConfig{
		DDosDefense:      true,
		MaxAttemptsPerIP: 3,
	}

	clientIP := "192.168.1.1"

	// First few attempts should be allowed
	for i := 0; i < 3; i++ {
		if !CheckDDosDefense(clientIP, config) {
			t.Errorf("Attempt %d should be allowed", i+1)
		}
		RecordFailedAttempt(clientIP)
	}

	// Next attempt should be blocked
	if CheckDDosDefense(clientIP, config) {
		t.Errorf("Attempt after limit should be blocked")
	}

	// Different IP should still be allowed
	if !CheckDDosDefense("192.168.1.2", config) {
		t.Errorf("Different IP should be allowed")
	}
}

func TestValidateAuthCodeRequest(t *testing.T) {
	// Set environment for testing
	os.Setenv("OPENADP_AUTH_ENABLED", "1")
	os.Setenv("OPENADP_AUTH_MIN_ENTROPY", "100")
	defer func() {
		os.Unsetenv("OPENADP_AUTH_ENABLED")
		os.Unsetenv("OPENADP_AUTH_MIN_ENTROPY")
	}()

	// Clear state
	ddosMutex.Lock()
	failedAttempts = make(map[string]int)
	attemptTimestamps = make(map[string]time.Time)
	blacklistedCodes = make(map[string]bool)
	ddosMutex.Unlock()

	validCode := "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678"
	serverURL := "https://example.com"
	clientIP := "192.168.1.1"

	// Valid request should succeed
	uuid, err := ValidateAuthCodeRequest(validCode, serverURL, clientIP)
	if err != nil {
		t.Errorf("Valid request should succeed: %v", err)
	}
	if uuid == "" {
		t.Errorf("Valid request should return UUID")
	}

	// Invalid format should fail
	_, err = ValidateAuthCodeRequest("invalid", serverURL, clientIP)
	if err == nil {
		t.Errorf("Invalid format should fail")
	}

	// Blacklisted code should fail
	BlacklistAuthCode(validCode)
	_, err = ValidateAuthCodeRequest(validCode, serverURL, clientIP)
	if err == nil {
		t.Errorf("Blacklisted code should fail")
	}
}

func TestAuthMiddleware(t *testing.T) {
	// Set environment for testing
	os.Setenv("OPENADP_AUTH_ENABLED", "1")
	defer os.Unsetenv("OPENADP_AUTH_ENABLED")

	// Clear state
	ddosMutex.Lock()
	failedAttempts = make(map[string]int)
	attemptTimestamps = make(map[string]time.Time)
	blacklistedCodes = make(map[string]bool)
	ddosMutex.Unlock()

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uuid := r.Header.Get("X-Derived-UUID")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("UUID: " + uuid))
	})

	// Wrap with auth middleware
	handler := AuthMiddleware(testHandler)

	t.Run("no auth code", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request without auth code should succeed, got %d", w.Code)
		}
	})

	t.Run("valid auth code in header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Auth-Code", "a1b2c3d4e5f67890123456789012345678901234567890123456789012345678")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Valid auth code should succeed, got %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "UUID:") {
			t.Errorf("Response should contain UUID")
		}
	})

	t.Run("invalid auth code", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Auth-Code", "invalid")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Invalid auth code should return 401, got %d", w.Code)
		}
	})

	t.Run("auth code in query param", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test?auth_code=a1b2c3d4e5f67890123456789012345678901234567890123456789012345678", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Valid auth code in query should succeed, got %d", w.Code)
		}
	})
}

func TestGetAuthStats(t *testing.T) {
	// Clear state
	ddosMutex.Lock()
	failedAttempts = make(map[string]int)
	attemptTimestamps = make(map[string]time.Time)
	blacklistedCodes = make(map[string]bool)
	ddosMutex.Unlock()

	// Record some failed attempts
	RecordFailedAttempt("192.168.1.1")
	RecordFailedAttempt("192.168.1.1")
	RecordFailedAttempt("192.168.1.2")

	// Blacklist a code
	BlacklistAuthCode("test123")

	stats := GetAuthStats()

	if stats.FailedAttemptsCount != 2 {
		t.Errorf("FailedAttemptsCount = %d, want 2", stats.FailedAttemptsCount)
	}

	if stats.TotalFailedAttempts != 3 {
		t.Errorf("TotalFailedAttempts = %d, want 3", stats.TotalFailedAttempts)
	}

	if stats.BlacklistedCodesCount != 1 {
		t.Errorf("BlacklistedCodesCount = %d, want 1", stats.BlacklistedCodesCount)
	}

	if !stats.Config["enabled"].(bool) {
		t.Errorf("Config should show enabled=true")
	}
}

func TestBlacklistOperations(t *testing.T) {
	// Clear state
	ClearBlacklist()

	testCode := "test123"

	// Should not be blacklisted initially
	ddosMutex.RLock()
	isBlacklisted := blacklistedCodes[testCode]
	ddosMutex.RUnlock()

	if isBlacklisted {
		t.Errorf("Code should not be blacklisted initially")
	}

	// Blacklist the code
	BlacklistAuthCode(testCode)

	// Should now be blacklisted
	ddosMutex.RLock()
	isBlacklisted = blacklistedCodes[testCode]
	ddosMutex.RUnlock()

	if !isBlacklisted {
		t.Errorf("Code should be blacklisted after BlacklistAuthCode")
	}

	// Clear blacklist
	ClearBlacklist()

	// Should not be blacklisted after clear
	ddosMutex.RLock()
	isBlacklisted = blacklistedCodes[testCode]
	ddosMutex.RUnlock()

	if isBlacklisted {
		t.Errorf("Code should not be blacklisted after ClearBlacklist")
	}
}

func TestAuthDisabled(t *testing.T) {
	// Disable auth
	os.Setenv("OPENADP_AUTH_ENABLED", "0")
	defer os.Unsetenv("OPENADP_AUTH_ENABLED")

	// Should skip validation when disabled
	uuid, err := ValidateAuthCodeRequest("invalid", "https://example.com", "192.168.1.1")
	if err != nil {
		t.Errorf("Validation should be skipped when auth is disabled: %v", err)
	}
	if uuid != "" {
		t.Errorf("UUID should be empty when auth is disabled")
	}
}
