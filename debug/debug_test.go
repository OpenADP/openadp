package debug

import (
	"math/big"
	"testing"
)

func TestDebugMode(t *testing.T) {
	// Test that debug mode starts disabled
	if IsDebugModeEnabled() {
		t.Error("Debug mode should start disabled")
	}

	// Enable debug mode
	SetDebugMode(true)
	if !IsDebugModeEnabled() {
		t.Error("Debug mode should be enabled")
	}

	// Test deterministic scalar
	scalar := GetDeterministicRandomScalar()
	expected := big.NewInt(1)
	if scalar.Cmp(expected) != 0 {
		t.Errorf("Expected deterministic scalar to be 1, got %s", scalar.String())
	}

	// Test deterministic coefficients are sequential
	coeff1 := GetDeterministicPolynomialCoefficient()
	coeff2 := GetDeterministicPolynomialCoefficient()

	if coeff1.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Expected first coefficient to be 1, got %s", coeff1.String())
	}

	if coeff2.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("Expected second coefficient to be 2, got %s", coeff2.String())
	}

	// Test SecureRandom in debug mode
	random, err := SecureRandom(big.NewInt(100))
	if err != nil {
		t.Errorf("SecureRandom failed: %v", err)
	}
	if random.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Expected SecureRandom to return 1 in debug mode, got %s", random.String())
	}

	// Disable debug mode
	SetDebugMode(false)
	if IsDebugModeEnabled() {
		t.Error("Debug mode should be disabled")
	}

	// Test that SecureRandom works in normal mode
	random, err = SecureRandom(big.NewInt(100))
	if err != nil {
		t.Errorf("SecureRandom failed in normal mode: %v", err)
	}
	// In normal mode, we can't predict the value, just check it's valid
	if random.Cmp(big.NewInt(0)) < 0 || random.Cmp(big.NewInt(100)) >= 0 {
		t.Errorf("SecureRandom returned invalid value: %s", random.String())
	}
}

func TestDeterministicBytes(t *testing.T) {
	SetDebugMode(true)
	defer SetDebugMode(false)

	bytes := GetDeterministicRandomBytes(10)
	if len(bytes) != 10 {
		t.Errorf("Expected 10 bytes, got %d", len(bytes))
	}

	// Test that bytes are deterministic
	bytes2 := GetDeterministicRandomBytes(10)
	if len(bytes2) != 10 {
		t.Errorf("Expected 10 bytes, got %d", len(bytes2))
	}

	// The bytes should be different because the counter increments
	// but both should be deterministic
}

func TestEphemeralSecret(t *testing.T) {
	SetDebugMode(true)
	defer SetDebugMode(false)

	secret := GetDeterministicEphemeralSecret()
	if len(secret) != 32 {
		t.Errorf("Expected 32 bytes for ephemeral secret, got %d", len(secret))
	}

	// Test that the secret is the expected fixed value
	expected := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
	}

	for i, b := range secret {
		if b != expected[i] {
			t.Errorf("Ephemeral secret byte %d: expected %02x, got %02x", i, expected[i], b)
		}
	}
}
