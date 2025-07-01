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

	// Disable debug mode
	SetDebugMode(false)
	if IsDebugModeEnabled() {
		t.Error("Debug mode should be disabled")
	}
}
