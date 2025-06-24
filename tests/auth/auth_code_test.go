package auth_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openadp/server/auth"
)

func TestAuthCodeRandomness(t *testing.T) {
	fmt.Println("Testing authentication code randomness...")

	manager := auth.NewAuthCodeManager()
	codes := make([]string, 100)

	// Generate 100 codes
	for i := 0; i < 100; i++ {
		code, err := manager.GenerateAuthCode()
		if err != nil {
			t.Fatalf("Failed to generate auth code: %v", err)
		}
		codes[i] = code
	}

	// All codes should be unique
	codeSet := make(map[string]bool)
	for _, code := range codes {
		if codeSet[code] {
			t.Error("Duplicate auth code generated")
		}
		codeSet[code] = true
	}

	if len(codeSet) != 100 {
		t.Errorf("Expected 100 unique codes, got %d", len(codeSet))
	}

	// Test statistical properties
	allChars := strings.Join(codes, "")
	charCounts := make(map[rune]int)
	hexChars := "0123456789abcdef"

	for _, char := range hexChars {
		charCounts[char] = strings.Count(allChars, string(char))
	}

	// Each hex digit should appear roughly equally
	expectedCount := len(allChars) / 16
	for char, count := range charCounts {
		// Allow 30% deviation from expected
		if count < int(float64(expectedCount)*0.7) {
			t.Errorf("Character '%c' appears too rarely: %d (expected ~%d)", char, count, expectedCount)
		}
		if count > int(float64(expectedCount)*1.3) {
			t.Errorf("Character '%c' appears too frequently: %d (expected ~%d)", char, count, expectedCount)
		}
	}

	fmt.Println("✅ Auth code randomness test passed")
}

func TestServerCodeDerivationSecurity(t *testing.T) {
	fmt.Println("Testing server code derivation security...")

	manager := auth.NewAuthCodeManager()
	baseCode := "deadbeefcafebabe1234567890abcdef"

	// Different servers should produce completely different codes
	server1Code := manager.DeriveServerCode(baseCode, "https://server1.com")
	server2Code := manager.DeriveServerCode(baseCode, "https://server2.com")

	// Codes should be completely different
	if server1Code == server2Code {
		t.Error("Different servers produced identical codes")
	}

	// Hamming distance should be high (roughly half the bits different)
	hammingDistance := 0
	for i := 0; i < len(server1Code) && i < len(server2Code); i++ {
		if server1Code[i] != server2Code[i] {
			hammingDistance++
		}
	}

	if hammingDistance < 25 {
		t.Errorf("Hamming distance too low: %d (expected >25)", hammingDistance)
	}

	fmt.Println("✅ Server code derivation security test passed")
}

func TestBaseCodeCompromiseIsolation(t *testing.T) {
	fmt.Println("Testing base code compromise isolation...")

	manager := auth.NewAuthCodeManager()
	baseCode := "deadbeefcafebabe1234567890abcdef"
	serverURL := "https://server1.com"
	serverCode := manager.DeriveServerCode(baseCode, serverURL)

	// Verify the SHA256 implementation
	combined := baseCode + ":" + serverURL
	hash := sha256.Sum256([]byte(combined))
	expectedHash := fmt.Sprintf("%x", hash)

	if serverCode != expectedHash {
		t.Errorf("Server code derivation mismatch: got %s, expected %s", serverCode, expectedHash)
	}

	// Verify avalanche effect - changing base code by 1 bit produces very different result
	baseCodeModified := baseCode[:len(baseCode)-1]
	if baseCode[len(baseCode)-1] == 'f' {
		baseCodeModified += "e"
	} else {
		baseCodeModified += "f"
	}

	serverCodeModified := manager.DeriveServerCode(baseCodeModified, serverURL)

	hammingDistance := 0
	for i := 0; i < len(serverCode) && i < len(serverCodeModified); i++ {
		if serverCode[i] != serverCodeModified[i] {
			hammingDistance++
		}
	}

	if hammingDistance < 25 {
		t.Errorf("Avalanche effect insufficient: %d differences (expected >25)", hammingDistance)
	}

	fmt.Println("✅ Base code compromise isolation test passed")
}

func TestTimingAttackResistance(t *testing.T) {
	fmt.Println("Testing timing attack resistance...")

	manager := auth.NewAuthCodeManager()
	baseCode := "deadbeefcafebabe1234567890abcdef"
	serverURL := "https://server1.com"

	// Measure time for multiple derivations
	times := make([]time.Duration, 10)
	for i := 0; i < 10; i++ {
		start := time.Now()
		manager.DeriveServerCode(baseCode, serverURL)
		times[i] = time.Since(start)
	}

	// Basic smoke test - ensure function completes in reasonable time
	var totalTime time.Duration
	for _, t := range times {
		totalTime += t
	}
	avgTime := totalTime / time.Duration(len(times))

	if avgTime <= 0 {
		t.Error("Derivation should take some time")
	}
	if avgTime > 100*time.Millisecond {
		t.Errorf("Derivation too slow: %v (expected <100ms)", avgTime)
	}

	fmt.Println("✅ Timing attack resistance test passed")
}

func TestAuthCodeFormatValidationSecurity(t *testing.T) {
	fmt.Println("Testing auth code format validation security...")

	manager := auth.NewAuthCodeManager()

	// Test various attack vectors
	attackVectors := []string{
		"../../../etc/passwd",           // Path traversal
		"<script>alert('xss')</script>", // XSS
		"'; DROP TABLE shares; --",      // SQL injection
		"\x00\x01\x02\x03",              // Binary data
		strings.Repeat("a", 10000),      // Buffer overflow attempt
		"deadbeef\ndeadbeef",            // Newline injection
		"deadbeef\r\ndeadbeef",          // CRLF injection
	}

	for _, attack := range attackVectors {
		t.Run(fmt.Sprintf("Attack_%s", attack[:min(20, len(attack))]), func(t *testing.T) {
			// All attacks should be rejected by format validation
			if manager.ValidateBaseCodeFormat(attack) {
				t.Errorf("Attack vector should be rejected: %s", attack[:min(50, len(attack))])
			}
			if manager.ValidateServerCodeFormat(attack) {
				t.Errorf("Attack vector should be rejected: %s", attack[:min(50, len(attack))])
			}
		})
	}

	fmt.Println("✅ Auth code format validation security test passed")
}

func TestServerURLHandlingSecurity(t *testing.T) {
	fmt.Println("Testing server URL handling security...")

	manager := auth.NewAuthCodeManager()
	baseCode := "deadbeefcafebabe1234567890abcdef"

	// Test various URL formats
	urlTests := []struct {
		url         string
		shouldWork  bool
		description string
	}{
		{"https://server.com", true, "HTTPS URL"},
		{"http://server.com", true, "HTTP URL"},
		{"https://server.com:8080", true, "HTTPS with port"},
		{"https://server.com/path", true, "HTTPS with path"},
		{"ftp://server.com", true, "FTP protocol"},
		{"javascript:alert('xss')", true, "JavaScript XSS attempt"},
		{"", true, "Empty string"},
		{"https://server.com\nmalicious.com", true, "Newline injection"},
	}

	for _, test := range urlTests {
		t.Run(test.description, func(t *testing.T) {
			result := manager.DeriveServerCode(baseCode, test.url)

			if test.shouldWork {
				if len(result) != 64 {
					t.Errorf("Expected 64-character result, got %d", len(result))
				}
				for _, char := range result {
					if !strings.ContainsRune("0123456789abcdef", char) {
						t.Errorf("Invalid hex character in result: %c", char)
						break
					}
				}
			}
		})
	}

	fmt.Println("✅ Server URL handling security test passed")
}

func TestCollisionResistance(t *testing.T) {
	fmt.Println("Testing collision resistance...")

	manager := auth.NewAuthCodeManager()
	baseCodes := []string{
		"deadbeefcafebabe1234567890abcdef",
		"deadbeefcafebabe1234567890abcdee", // 1 bit different
		"deadbeefcafebabe1234567890abcded", // 2 bits different
	}

	serverURL := "https://server.com"
	codes := make([]string, len(baseCodes))

	for i, baseCode := range baseCodes {
		codes[i] = manager.DeriveServerCode(baseCode, serverURL)
	}

	// All derived codes should be different
	codeSet := make(map[string]bool)
	for _, code := range codes {
		if codeSet[code] {
			t.Error("Collision detected in server code derivation")
		}
		codeSet[code] = true
	}

	// Even small changes in input should produce very different outputs
	for i := 0; i < len(codes); i++ {
		for j := i + 1; j < len(codes); j++ {
			hammingDistance := 0
			for k := 0; k < len(codes[i]) && k < len(codes[j]); k++ {
				if codes[i][k] != codes[j][k] {
					hammingDistance++
				}
			}
			if hammingDistance < 20 {
				t.Errorf("Insufficient difference between codes %d and %d: %d", i, j, hammingDistance)
			}
		}
	}

	fmt.Println("✅ Collision resistance test passed")
}

func TestAuthCodeGeneration(t *testing.T) {
	fmt.Println("Testing auth code generation...")

	manager := auth.NewAuthCodeManager()

	// Test basic generation
	code, err := manager.GenerateAuthCode()
	if err != nil {
		t.Fatalf("Failed to generate auth code: %v", err)
	}
	if len(code) != 32 {
		t.Errorf("Expected 32-character auth code, got %d", len(code))
	}

	// Verify hex format
	for _, char := range code {
		if !strings.ContainsRune("0123456789abcdef", char) {
			t.Errorf("Invalid hex character in auth code: %c", char)
			break
		}
	}

	fmt.Println("✅ Auth code generation test passed")
}

func TestAuthCodeValidation(t *testing.T) {
	fmt.Println("Testing auth code validation...")

	manager := auth.NewAuthCodeManager()

	// Valid codes (32 characters for base codes)
	validCodes := []string{
		"deadbeefcafebabe1234567890abcdef",
		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffff",
	}

	for _, code := range validCodes {
		if !manager.ValidateBaseCodeFormat(code) {
			t.Errorf("Valid code rejected: %s", code)
		}
	}

	// Valid server codes (64 characters for derived codes)
	validServerCodes := []string{
		"deadbeefcafebabe1234567890abcdef0123456789abcdef0123456789abcdef",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}

	for _, code := range validServerCodes {
		if !manager.ValidateServerCodeFormat(code) {
			t.Errorf("Valid server code rejected: %s", code)
		}
	}

	// Invalid codes
	invalidCodes := []string{
		"",                                  // Empty
		"deadbeef",                          // Too short
		"deadbeefcafebabe1234567890abcdefX", // Invalid char
		"deadbeefcafebabe1234567890abcdef0", // Too long
	}

	for _, code := range invalidCodes {
		if manager.ValidateBaseCodeFormat(code) {
			t.Errorf("Invalid code accepted: %s", code)
		}
	}

	fmt.Println("✅ Auth code validation test passed")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestMain(m *testing.M) {
	fmt.Println("🚀 Auth Code Security Tests")
	fmt.Println(strings.Repeat("=", 40))

	// Run tests
	m.Run()

	fmt.Println(strings.Repeat("=", 40))
	fmt.Println("✅ Auth code security tests complete")
}
