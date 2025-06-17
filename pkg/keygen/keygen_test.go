package keygen

import (
	"testing"
)

func TestKeygenRoundTrip(t *testing.T) {
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
	result := GenerateEncryptionKey(filename, password, userID, maxGuesses, expiration, serverURLs)
	if result.Error != "" {
		t.Fatalf("Key generation failed: %s", result.Error)
	}

	t.Logf("✅ Generated key: %x", result.EncryptionKey[:16])
	t.Logf("✅ Used %d servers with threshold %d", len(result.ServerURLs), result.Threshold)

	// Step 2: Recover encryption key
	t.Log("🔓 Recovering encryption key...")
	recoveryResult := RecoverEncryptionKey(filename, password, userID, result.ServerURLs, result.Threshold, result.AuthCodes)
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
