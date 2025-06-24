package auth

import (
	"regexp"
	"strings"
	"testing"
)

func TestGenerateAuthCode(t *testing.T) {
	manager := NewAuthCodeManager()

	t.Run("BasicGeneration", func(t *testing.T) {
		code, err := manager.GenerateAuthCode()
		if err != nil {
			t.Fatalf("Failed to generate auth code: %v", err)
		}

		// Should be 32 character hex string (128 bits)
		if len(code) != 32 {
			t.Errorf("Expected code length 32, got %d", len(code))
		}

		// Should be valid hex
		matched, _ := regexp.MatchString("^[0-9a-f]+$", code)
		if !matched {
			t.Errorf("Code should be lowercase hex, got %s", code)
		}
	})

	t.Run("Uniqueness", func(t *testing.T) {
		codes := make(map[string]bool)
		numCodes := 100

		for i := 0; i < numCodes; i++ {
			code, err := manager.GenerateAuthCode()
			if err != nil {
				t.Fatalf("Failed to generate auth code: %v", err)
			}
			if codes[code] {
				t.Errorf("Duplicate code generated: %s", code)
			}
			codes[code] = true
		}

		if len(codes) != numCodes {
			t.Errorf("Expected %d unique codes, got %d", numCodes, len(codes))
		}
	})

	t.Run("Entropy", func(t *testing.T) {
		codes := make([]string, 100)
		for i := 0; i < 100; i++ {
			code, err := manager.GenerateAuthCode()
			if err != nil {
				t.Fatalf("Failed to generate auth code: %v", err)
			}
			codes[i] = code
		}

		allChars := strings.Join(codes, "")
		charCounts := make(map[rune]int)
		for _, char := range allChars {
			charCounts[char]++
		}

		// Each hex digit should appear at least once in 100 codes
		hexChars := "0123456789abcdef"
		for _, char := range hexChars {
			if charCounts[char] == 0 {
				t.Errorf("Character '%c' should appear at least once", char)
			}
		}
	})
}

func TestValidateBaseCodeFormat(t *testing.T) {
	manager := NewAuthCodeManager()

	validCodes := []string{
		"0123456789abcdef0123456789abcdef", // All hex digits
		"ffffffffffffffffffffffffffffffff", // All f's
		"0000000000000000000000000000000a", // Mostly zeros
		"deadbeefcafebabe1234567890abcdef", // Mixed
	}

	for _, code := range validCodes {
		t.Run("Valid_"+code[:8], func(t *testing.T) {
			if !manager.ValidateBaseCodeFormat(code) {
				t.Errorf("Code should be valid: %s", code)
			}
		})
	}

	invalidCodes := []string{
		"",                                  // Empty
		"123",                               // Too short
		"0123456789abcdef0123456789abcdef0", // Too long
		"0123456789abcdef0123456789abcdeg",  // Invalid hex char
		"0123456789abcdef 123456789abcdef",  // Space
	}

	for _, code := range invalidCodes {
		t.Run("Invalid_"+code, func(t *testing.T) {
			if manager.ValidateBaseCodeFormat(code) {
				t.Errorf("Code should be invalid: %s", code)
			}
		})
	}

	t.Run("UppercaseAllowed", func(t *testing.T) {
		uppercaseCode := "0123456789ABCDEF0123456789ABCDEF"
		if !manager.ValidateBaseCodeFormat(uppercaseCode) {
			t.Errorf("Uppercase hex should be allowed: %s", uppercaseCode)
		}
	})
}

func TestDeriveServerCode(t *testing.T) {
	manager := NewAuthCodeManager()
	baseCode := "deadbeefcafebabe1234567890abcdef"
	serverURL := "https://server1.openadp.org"

	t.Run("BasicDerivation", func(t *testing.T) {
		serverCode := manager.DeriveServerCode(baseCode, serverURL)

		// Should be 64 character hex string (256 bits)
		if len(serverCode) != 64 {
			t.Errorf("Expected server code length 64, got %d", len(serverCode))
		}

		// Should be valid hex
		matched, _ := regexp.MatchString("^[0-9a-f]+$", serverCode)
		if !matched {
			t.Errorf("Server code should be lowercase hex, got %s", serverCode)
		}
	})

	t.Run("Deterministic", func(t *testing.T) {
		serverCode1 := manager.DeriveServerCode(baseCode, serverURL)
		serverCode2 := manager.DeriveServerCode(baseCode, serverURL)

		if serverCode1 != serverCode2 {
			t.Errorf("Server code derivation should be deterministic")
		}
	})

	t.Run("DifferentServers", func(t *testing.T) {
		serverURLs := []string{
			"https://server1.openadp.org",
			"https://server2.openadp.org",
			"https://localhost:8080",
		}

		codes := make(map[string]string)
		for _, url := range serverURLs {
			codes[url] = manager.DeriveServerCode(baseCode, url)
		}

		// All codes should be different
		codeValues := make([]string, 0, len(codes))
		for _, code := range codes {
			codeValues = append(codeValues, code)
		}

		for i := 0; i < len(codeValues); i++ {
			for j := i + 1; j < len(codeValues); j++ {
				if codeValues[i] == codeValues[j] {
					t.Errorf("Server codes should be different for different servers")
				}
			}
		}
	})

	t.Run("DifferentBaseCodes", func(t *testing.T) {
		baseCodes := []string{
			"deadbeefcafebabe1234567890abcdef",
			"1234567890abcdefdeadbeefcafebabe",
			"0000000000000000000000000000000a",
		}

		codes := make([]string, len(baseCodes))
		for i, baseCode := range baseCodes {
			codes[i] = manager.DeriveServerCode(baseCode, serverURL)
		}

		// All codes should be different
		for i := 0; i < len(codes); i++ {
			for j := i + 1; j < len(codes); j++ {
				if codes[i] == codes[j] {
					t.Errorf("Server codes should be different for different base codes")
				}
			}
		}
	})
}

func TestGetServerCodes(t *testing.T) {
	manager := NewAuthCodeManager()
	baseCode := "deadbeefcafebabe1234567890abcdef"
	serverURLs := []string{
		"https://server1.openadp.org",
		"https://server2.openadp.org",
		"https://localhost:8080",
	}

	serverCodes := manager.GetServerCodes(baseCode, serverURLs)

	// Should have entry for each server
	if len(serverCodes) != len(serverURLs) {
		t.Errorf("Expected %d server codes, got %d", len(serverURLs), len(serverCodes))
	}

	for _, url := range serverURLs {
		code, exists := serverCodes[url]
		if !exists {
			t.Errorf("Missing server code for URL: %s", url)
		}
		if len(code) != 64 {
			t.Errorf("Server code for %s should be 64 chars, got %d", url, len(code))
		}
	}
}

func TestValidateServerCodeFormat(t *testing.T) {
	manager := NewAuthCodeManager()

	validCodes := []string{
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"000000000000000000000000000000000000000000000000000000000000000a",
	}

	for _, code := range validCodes {
		t.Run("Valid_"+code[:8], func(t *testing.T) {
			if !manager.ValidateServerCodeFormat(code) {
				t.Errorf("Server code should be valid: %s", code)
			}
		})
	}

	invalidCodes := []string{
		"",                                 // Empty
		"123",                              // Too short
		"0123456789abcdef0123456789abcdef", // Too short (32 chars)
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", // Too long
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",  // Invalid hex
	}

	for _, code := range invalidCodes {
		t.Run("Invalid_"+code, func(t *testing.T) {
			if manager.ValidateServerCodeFormat(code) {
				t.Errorf("Server code should be invalid: %s", code)
			}
		})
	}
}

func TestSHA256DerivationConsistency(t *testing.T) {
	manager := NewAuthCodeManager()
	baseCode := "deadbeefcafebabe1234567890abcdef"
	serverURL := "https://server1.openadp.org"

	// Test that the derivation is consistent with expected SHA256 behavior
	serverCode1 := manager.DeriveServerCode(baseCode, serverURL)
	serverCode2 := manager.DeriveServerCode(baseCode, serverURL)

	if serverCode1 != serverCode2 {
		t.Errorf("SHA256 derivation should be consistent")
	}

	// Test with different inputs produce different outputs
	differentURL := "https://server2.openadp.org"
	serverCode3 := manager.DeriveServerCode(baseCode, differentURL)

	if serverCode1 == serverCode3 {
		t.Errorf("Different inputs should produce different SHA256 outputs")
	}
}

func TestURLNormalization(t *testing.T) {
	manager := NewAuthCodeManager()
	baseCode := "deadbeefcafebabe1234567890abcdef"

	// Test that URL normalization doesn't affect the derivation
	// (assuming the implementation doesn't normalize URLs)
	urls := []string{
		"https://server1.openadp.org",
		"https://server1.openadp.org/",
		"https://SERVER1.OPENADP.ORG",
	}

	codes := make([]string, len(urls))
	for i, url := range urls {
		codes[i] = manager.DeriveServerCode(baseCode, url)
	}

	// Different URL formats should produce different codes
	// (unless normalization is implemented)
	for i := 0; i < len(codes); i++ {
		for j := i + 1; j < len(codes); j++ {
			if codes[i] == codes[j] {
				t.Logf("URLs %s and %s produce same code (URL normalization may be implemented)", urls[i], urls[j])
			}
		}
	}
}

// Benchmark tests
func BenchmarkGenerateAuthCode(b *testing.B) {
	manager := NewAuthCodeManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.GenerateAuthCode()
	}
}

func BenchmarkDeriveServerCode(b *testing.B) {
	manager := NewAuthCodeManager()
	baseCode := "deadbeefcafebabe1234567890abcdef"
	serverURL := "https://server1.openadp.org"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.DeriveServerCode(baseCode, serverURL)
	}
}

func BenchmarkValidateBaseCodeFormat(b *testing.B) {
	manager := NewAuthCodeManager()
	code := "deadbeefcafebabe1234567890abcdef"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.ValidateBaseCodeFormat(code)
	}
}
