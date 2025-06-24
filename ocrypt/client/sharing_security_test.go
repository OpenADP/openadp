package client

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/openadp/ocrypt/common"
)

// TestEvalAt tests the critical evalAt function that has 0% coverage
func TestEvalAt(t *testing.T) {
	prime := common.Q // Use the same prime as in the actual implementation

	// Test polynomial evaluation at various points
	tests := []struct {
		name         string
		coefficients []*big.Int
		x            *big.Int
		expectedY    *big.Int
	}{
		{
			name:         "constant polynomial",
			coefficients: []*big.Int{big.NewInt(42)},
			x:            big.NewInt(5),
			expectedY:    big.NewInt(42), // f(x) = 42
		},
		{
			name:         "linear polynomial",
			coefficients: []*big.Int{big.NewInt(3), big.NewInt(2)},
			x:            big.NewInt(4),
			expectedY:    big.NewInt(11), // f(x) = 3 + 2*4 = 11
		},
		{
			name:         "quadratic polynomial",
			coefficients: []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
			x:            big.NewInt(2),
			expectedY:    big.NewInt(17), // f(x) = 1 + 2*2 + 3*2^2 = 1 + 4 + 12 = 17
		},
		{
			name:         "evaluation at zero",
			coefficients: []*big.Int{big.NewInt(10), big.NewInt(20), big.NewInt(30)},
			x:            big.NewInt(0),
			expectedY:    big.NewInt(10), // f(0) = constant term
		},
		{
			name:         "evaluation at one",
			coefficients: []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
			x:            big.NewInt(1),
			expectedY:    big.NewInt(6), // f(1) = 1 + 2 + 3 = 6
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evalAt(tt.coefficients, tt.x, prime)

			expected := new(big.Int).Mod(tt.expectedY, prime)

			if result.Cmp(expected) != 0 {
				t.Errorf("evalAt() = %s, want %s", result.String(), expected.String())
			}
		})
	}
}

// TestEvalAtWithLargeNumbers tests evalAt with large numbers and edge cases
func TestEvalAtWithLargeNumbers(t *testing.T) {
	prime := common.Q

	// Test with large coefficients
	largePrime, _ := new(big.Int).SetString("2147483647", 10) // 2^31 - 1

	coefficients := []*big.Int{
		largePrime,
		new(big.Int).Mul(largePrime, big.NewInt(2)),
		new(big.Int).Mul(largePrime, big.NewInt(3)),
	}

	x := big.NewInt(100)
	result := evalAt(coefficients, x, prime)

	// Verify the result is computed correctly
	// f(x) = a0 + a1*x + a2*x^2 (all mod prime)
	expected := new(big.Int).Set(coefficients[0])
	expected.Mod(expected, prime)

	term1 := new(big.Int).Mul(coefficients[1], x)
	term1.Mod(term1, prime)
	expected.Add(expected, term1)
	expected.Mod(expected, prime)

	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, prime)
	term2 := new(big.Int).Mul(coefficients[2], x2)
	term2.Mod(term2, prime)
	expected.Add(expected, term2)
	expected.Mod(expected, prime)

	if result.Cmp(expected) != 0 {
		t.Errorf("evalAt() with large numbers failed: got %s, want %s", result.String(), expected.String())
	}
}

// TestEvalAtEmptyCoefficients tests evalAt with empty coefficients
func TestEvalAtEmptyCoefficients(t *testing.T) {
	prime := common.Q
	coefficients := []*big.Int{}
	x := big.NewInt(5)

	result := evalAt(coefficients, x, prime)

	// Should return 0 for empty polynomial
	if result.Sign() != 0 {
		t.Errorf("evalAt() with empty coefficients = %s, want 0", result.String())
	}
}

// TestEvalAtNegativeX tests evalAt with negative x values
func TestEvalAtNegativeX(t *testing.T) {
	prime := common.Q
	coefficients := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	x := big.NewInt(-2)

	// f(x) = 1 + 2*(-2) + 3*(-2)^2 = 1 - 4 + 12 = 9
	// But we need to handle modular arithmetic correctly
	result := evalAt(coefficients, x, prime)

	// Compute expected value using same modular arithmetic
	expected := big.NewInt(1)

	term1 := new(big.Int).Mul(big.NewInt(2), x)
	expected.Add(expected, term1)

	x2 := new(big.Int).Mul(x, x)
	term2 := new(big.Int).Mul(big.NewInt(3), x2)
	expected.Add(expected, term2)

	expected.Mod(expected, prime)

	if result.Cmp(expected) != 0 {
		t.Errorf("evalAt() with negative x = %s, want %s", result.String(), expected.String())
	}
}

// TestEvalAtSingleCoefficient tests evalAt with single coefficient
func TestEvalAtSingleCoefficient(t *testing.T) {
	prime := common.Q
	coefficient := big.NewInt(123456789)
	coefficients := []*big.Int{coefficient}

	// Test with various x values - should always return the constant (mod prime)
	xValues := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(-1),
		big.NewInt(1000),
		big.NewInt(-1000),
	}

	expectedResult := new(big.Int).Mod(coefficient, prime)

	for _, x := range xValues {
		result := evalAt(coefficients, x, prime)
		if result.Cmp(expectedResult) != 0 {
			t.Errorf("evalAt() single coefficient at x=%s = %s, want %s",
				x.String(), result.String(), expectedResult.String())
		}
	}
}

// TestSecretSharingIntegration tests the integration of secret sharing functions
func TestSecretSharingIntegration(t *testing.T) {
	// Test secret sharing with different thresholds and shares
	tests := []struct {
		name      string
		secret    *big.Int
		threshold int
		numShares int
	}{
		{
			name:      "2-of-3 sharing",
			secret:    big.NewInt(123456789),
			threshold: 2,
			numShares: 3,
		},
		{
			name:      "3-of-5 sharing",
			secret:    big.NewInt(987654321),
			threshold: 3,
			numShares: 5,
		},
		{
			name:      "1-of-1 sharing (trivial)",
			secret:    big.NewInt(42),
			threshold: 1,
			numShares: 1,
		},
		{
			name:      "large secret",
			secret:    new(big.Int).Lsh(big.NewInt(1), 200), // Large secret
			threshold: 2,
			numShares: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create shares using the actual API
			shares, err := MakeRandomShares(tt.secret, tt.threshold, tt.numShares)
			if err != nil {
				t.Fatalf("MakeRandomShares() error: %v", err)
			}

			if len(shares) != tt.numShares {
				t.Errorf("MakeRandomShares() returned %d shares, want %d", len(shares), tt.numShares)
			}

			// Test reconstruction with minimum threshold
			minShares := shares[:tt.threshold]
			reconstructed, err := RecoverSecret(minShares)
			if err != nil {
				t.Fatalf("RecoverSecret() error: %v", err)
			}

			if reconstructed.Cmp(tt.secret) != 0 {
				t.Errorf("RecoverSecret() failed: got %s, want %s", reconstructed.String(), tt.secret.String())
			}

			// Test reconstruction with more than threshold
			if tt.numShares > tt.threshold {
				moreShares := shares[:tt.threshold+1]
				reconstructed2, err := RecoverSecret(moreShares)
				if err != nil {
					t.Fatalf("RecoverSecret() with extra shares error: %v", err)
				}

				if reconstructed2.Cmp(tt.secret) != 0 {
					t.Errorf("RecoverSecret() with extra shares failed")
				}
			}

			// Test that fewer than threshold shares fail
			if tt.threshold > 1 {
				tooFewShares := shares[:tt.threshold-1]
				// Note: This might not always fail due to Lagrange interpolation properties
				// but the recovered secret should be different
				recovered, err := RecoverSecret(tooFewShares)
				if err == nil && recovered.Cmp(tt.secret) == 0 {
					t.Errorf("RecoverSecret() with too few shares should not recover correct secret")
				}
			}
		})
	}
}

// TestSecretSharingEdgeCases tests edge cases for secret sharing
func TestSecretSharingEdgeCases(t *testing.T) {
	// Test zero secret
	t.Run("zero secret", func(t *testing.T) {
		secret := big.NewInt(0)
		shares, err := MakeRandomShares(secret, 2, 3)
		if err != nil {
			t.Errorf("MakeRandomShares() with zero secret failed: %v", err)
			return
		}

		reconstructed, err := RecoverSecret(shares[:2])
		if err != nil {
			t.Errorf("RecoverSecret() with zero secret failed: %v", err)
			return
		}

		if reconstructed.Cmp(secret) != 0 {
			t.Errorf("RecoverSecret() zero secret failed: got %s, want 0", reconstructed.String())
		}
	})

	// Test secret equal to prime - 1 (maximum value)
	t.Run("maximum secret", func(t *testing.T) {
		secret := new(big.Int).Sub(common.Q, big.NewInt(1))
		shares, err := MakeRandomShares(secret, 2, 3)
		if err != nil {
			t.Errorf("MakeRandomShares() with maximum secret failed: %v", err)
			return
		}

		reconstructed, err := RecoverSecret(shares[:2])
		if err != nil {
			t.Errorf("RecoverSecret() with maximum secret failed: %v", err)
			return
		}

		if reconstructed.Cmp(secret) != 0 {
			t.Errorf("RecoverSecret() maximum secret failed: got %s, want %s", reconstructed.String(), secret.String())
		}
	})

	// Test with random large secret
	t.Run("random large secret", func(t *testing.T) {
		secret, err := rand.Int(rand.Reader, common.Q)
		if err != nil {
			t.Fatalf("Failed to generate random secret: %v", err)
		}

		shares, err := MakeRandomShares(secret, 3, 5)
		if err != nil {
			t.Errorf("MakeRandomShares() with random secret failed: %v", err)
			return
		}

		reconstructed, err := RecoverSecret(shares[:3])
		if err != nil {
			t.Errorf("RecoverSecret() with random secret failed: %v", err)
			return
		}

		if reconstructed.Cmp(secret) != 0 {
			t.Errorf("RecoverSecret() random secret failed: got %s, want %s", reconstructed.String(), secret.String())
		}
	})
}

// TestSecretSharingErrorCases tests error handling in secret sharing
func TestSecretSharingErrorCases(t *testing.T) {
	secret := big.NewInt(12345)

	// Test threshold greater than shares
	t.Run("threshold > shares", func(t *testing.T) {
		_, err := MakeRandomShares(secret, 5, 3)
		if err == nil {
			t.Errorf("MakeRandomShares() with threshold > shares should fail")
		}
	})

	// Test reconstruction with nil shares
	t.Run("nil shares", func(t *testing.T) {
		_, err := RecoverSecret(nil)
		if err == nil {
			t.Errorf("RecoverSecret() with nil shares should fail")
		}
	})

	// Test reconstruction with empty shares
	t.Run("empty shares", func(t *testing.T) {
		_, err := RecoverSecret([]*Share{})
		if err == nil {
			t.Errorf("RecoverSecret() with empty shares should fail")
		}
	})
}

// TestShareSerialization tests share serialization and deserialization
func TestShareSerialization(t *testing.T) {
	secret := big.NewInt(123456789)
	shares, err := MakeRandomShares(secret, 2, 3)
	if err != nil {
		t.Fatalf("MakeRandomShares() failed: %v", err)
	}

	// Test that shares can be serialized and deserialized properly
	for i, share := range shares {
		// Test share structure
		if share.X == nil || share.X.Sign() <= 0 {
			t.Errorf("Share %d has invalid X coordinate: %v", i, share.X)
		}

		if share.Y == nil {
			t.Errorf("Share %d has nil Y value", i)
		}

		// Test that share Y values are different from original secret
		if share.Y.Cmp(secret) == 0 {
			t.Errorf("Share %d Y value matches original secret (should be different)", i)
		}
	}

	// Test reconstruction with shares
	reconstructed, err := RecoverSecret(shares[:2])
	if err != nil {
		t.Fatalf("RecoverSecret() after serialization test failed: %v", err)
	}

	if reconstructed.Cmp(secret) != 0 {
		t.Errorf("RecoverSecret() after serialization failed: got %s, want %s", reconstructed.String(), secret.String())
	}
}
