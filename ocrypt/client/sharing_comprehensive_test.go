package client

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/openadp/ocrypt/common"
)

// TestMakeRandomSharesBasic tests basic secret sharing functionality
func TestMakeRandomSharesBasic(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 2
	numShares := 3

	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	if len(shares) != numShares {
		t.Errorf("Expected %d shares, got %d", numShares, len(shares))
	}

	// Each share should be a valid Share struct
	for i, share := range shares {
		if share.X == nil || share.Y == nil {
			t.Errorf("Share %d has nil X or Y", i)
		}
		// X coordinates should be 1, 2, 3, ...
		expectedX := int64(i + 1)
		if share.X.Int64() != expectedX {
			t.Errorf("Share %d X coordinate: expected %d, got %d", i, expectedX, share.X.Int64())
		}
	}
}

// TestMakeRandomSharesEdgeCases tests edge cases in MakeRandomShares function
func TestMakeRandomSharesEdgeCases(t *testing.T) {
	// Test minimum = shares (threshold equals total shares)
	secret := big.NewInt(12345)
	minimum := 3
	numShares := 3
	result, err := MakeRandomShares(secret, minimum, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}
	if len(result) != numShares {
		t.Errorf("Expected %d shares, got %d", numShares, len(result))
	}

	// Test minimum = 1 (any single share can recover)
	result, err = MakeRandomShares(secret, 1, 5)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}
	if len(result) != 5 {
		t.Errorf("Expected 5 shares, got %d", len(result))
	}
}

// TestMakeRandomSharesInvalidParams tests secret sharing with invalid parameters
func TestMakeRandomSharesInvalidParams(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)

	// Test threshold > num_shares - should return error
	_, err := MakeRandomShares(secret, 4, 3)
	if err == nil {
		t.Error("Expected error for threshold > num_shares")
	}

	// Test threshold = 0 - should work (creates constant shares)
	shares, err := MakeRandomShares(secret, 0, 3)
	if err != nil {
		t.Fatalf("MakeRandomShares with threshold=0 failed: %v", err)
	}
	if len(shares) != 3 {
		t.Errorf("Expected 3 shares, got %d", len(shares))
	}
	// With threshold 0, all shares should have the same y value (the secret)
	for i, share := range shares {
		if share.Y.Cmp(secret) != 0 {
			t.Errorf("Share %d Y value should equal secret with threshold=0", i)
		}
	}

	// Test num_shares = 0 with threshold > 0 - should return error
	_, err = MakeRandomShares(secret, 1, 0)
	if err == nil {
		t.Error("Expected error for num_shares=0 with threshold>0")
	}

	// Test num_shares = 0 with threshold = 0 - should work
	shares, err = MakeRandomShares(secret, 0, 0)
	if err != nil {
		t.Fatalf("MakeRandomShares with threshold=0, shares=0 failed: %v", err)
	}
	if len(shares) != 0 {
		t.Errorf("Expected 0 shares, got %d", len(shares))
	}
}

// TestPointShareRecoveryBasic tests basic secret recovery using elliptic curve points
func TestPointShareRecoveryBasic(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 3
	numShares := 5

	// Create shares
	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Convert to point shares: (x, y*G) where G is the base point
	pointShares := make([]*PointShare, len(shares))
	for i, share := range shares {
		yPoint := common.PointMul(share.Y, common.G)
		pointShares[i] = &PointShare{
			X:     new(big.Int).Set(share.X),
			Point: common.Unexpand(yPoint),
		}
	}

	// Test recovery with exactly threshold shares
	recoveredPoint, err := RecoverSB(pointShares[:threshold])
	if err != nil {
		t.Fatalf("RecoverSB failed: %v", err)
	}

	// Verify against expected result
	expectedPoint4D := common.PointMul(secret, common.G)
	expectedPoint := common.Unexpand(expectedPoint4D)

	if recoveredPoint.X.Cmp(expectedPoint.X) != 0 || recoveredPoint.Y.Cmp(expectedPoint.Y) != 0 {
		t.Errorf("Recovered point doesn't match expected point")
	}
}

// TestPointShareRecoveryDifferentCombinations tests recovery with different share combinations
func TestPointShareRecoveryDifferentCombinations(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 3
	numShares := 6

	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Convert to point shares
	pointShares := make([]*PointShare, len(shares))
	for i, share := range shares {
		yPoint := common.PointMul(share.Y, common.G)
		pointShares[i] = &PointShare{
			X:     new(big.Int).Set(share.X),
			Point: common.Unexpand(yPoint),
		}
	}

	expectedPoint4D := common.PointMul(secret, common.G)
	expectedPoint := common.Unexpand(expectedPoint4D)

	// Test different combinations of threshold shares
	// Test first 3, middle 3, last 3
	combinations := [][]int{
		{0, 1, 2},
		{1, 2, 3},
		{2, 3, 4},
		{3, 4, 5},
	}

	for _, combo := range combinations {
		testShares := make([]*PointShare, threshold)
		for i, idx := range combo {
			testShares[i] = pointShares[idx]
		}

		recoveredPoint, err := RecoverSB(testShares)
		if err != nil {
			t.Errorf("RecoverSB failed for combination %v: %v", combo, err)
			continue
		}

		if recoveredPoint.X.Cmp(expectedPoint.X) != 0 || recoveredPoint.Y.Cmp(expectedPoint.Y) != 0 {
			t.Errorf("Recovered point doesn't match expected point for combination %v", combo)
		}
	}
}

// TestPointShareRecoveryInsufficientShares tests recovery with insufficient shares
func TestPointShareRecoveryInsufficientShares(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 4
	numShares := 6

	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Convert to point shares
	pointShares := make([]*PointShare, len(shares))
	for i, share := range shares {
		yPoint := common.PointMul(share.Y, common.G)
		pointShares[i] = &PointShare{
			X:     new(big.Int).Set(share.X),
			Point: common.Unexpand(yPoint),
		}
	}

	// With threshold-1 shares, recovery should give wrong result
	insufficientShares := pointShares[:threshold-1]
	if len(insufficientShares) > 0 {
		recoveredPoint, err := RecoverSB(insufficientShares)
		if err != nil {
			t.Fatalf("RecoverSB failed: %v", err)
		}

		// This should NOT equal the expected point (except by extreme coincidence)
		// We just verify the recovery runs without error
		if recoveredPoint == nil {
			t.Error("RecoverSB returned nil point")
		}
		if recoveredPoint.X == nil || recoveredPoint.Y == nil {
			t.Error("RecoverSB returned point with nil coordinates")
		}
	}
}

// TestPointShareRecoveryDuplicateShares tests recovery with duplicate shares
func TestPointShareRecoveryDuplicateShares(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 3
	numShares := 5

	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Convert to point shares
	pointShares := make([]*PointShare, len(shares))
	for i, share := range shares {
		yPoint := common.PointMul(share.Y, common.G)
		pointShares[i] = &PointShare{
			X:     new(big.Int).Set(share.X),
			Point: common.Unexpand(yPoint),
		}
	}

	// Create duplicate shares (same x coordinate)
	duplicateShares := []*PointShare{
		pointShares[0],
		pointShares[1],
		pointShares[0], // Duplicate of first share
	}

	// Recovery with duplicates should complete without crashing
	// (but will give incorrect result due to duplicate x coordinates)
	recoveredPoint, err := RecoverSB(duplicateShares)
	if err != nil {
		// This might fail due to singular matrix, which is expected
		t.Logf("RecoverSB with duplicates failed as expected: %v", err)
		return
	}

	// We just verify that recovery completes without crashing
	if recoveredPoint == nil {
		t.Error("RecoverSB returned nil point")
	}
	if recoveredPoint.X == nil || recoveredPoint.Y == nil {
		t.Error("RecoverSB returned point with nil coordinates")
	}
}

// TestBinaryDataHandling tests handling of binary data by converting to integers
func TestBinaryDataHandling(t *testing.T) {
	testPatterns := [][]byte{
		make([]byte, 32),         // All zeros
		{0xFF, 0xFF, 0xFF, 0xFF}, // Some ones
		{0xAA, 0xAA, 0xAA, 0xAA}, // Alternating pattern
		{0x55, 0x55, 0x55, 0x55}, // Different alternating pattern
	}

	// Add random data
	randomData := make([]byte, 32)
	rand.Read(randomData)
	testPatterns = append(testPatterns, randomData)

	threshold := 3
	numShares := 5

	for i, pattern := range testPatterns {
		t.Run("pattern_"+string(rune(i+'0')), func(t *testing.T) {
			// Convert bytes to integer mod q
			secretInt := new(big.Int).SetBytes(pattern)
			secretInt.Mod(secretInt, common.Q)

			shares, err := MakeRandomShares(secretInt, threshold, numShares)
			if err != nil {
				t.Fatalf("MakeRandomShares failed: %v", err)
			}
			if len(shares) != numShares {
				t.Errorf("Expected %d shares, got %d", numShares, len(shares))
			}

			// Convert to point shares and test recovery
			pointShares := make([]*PointShare, len(shares))
			for j, share := range shares {
				yPoint := common.PointMul(share.Y, common.G)
				pointShares[j] = &PointShare{
					X:     new(big.Int).Set(share.X),
					Point: common.Unexpand(yPoint),
				}
			}

			recoveredPoint, err := RecoverSB(pointShares[:threshold])
			if err != nil {
				t.Fatalf("RecoverSB failed: %v", err)
			}

			expectedPoint4D := common.PointMul(secretInt, common.G)
			expectedPoint := common.Unexpand(expectedPoint4D)

			if recoveredPoint.X.Cmp(expectedPoint.X) != 0 || recoveredPoint.Y.Cmp(expectedPoint.Y) != 0 {
				t.Errorf("Recovered point doesn't match expected point")
			}
		})
	}
}

// TestShareReconstructRoundtripVariousSizes tests share/reconstruct roundtrip with various secret sizes
func TestShareReconstructRoundtripVariousSizes(t *testing.T) {
	testCases := []*big.Int{
		big.NewInt(1), // Minimum
		new(big.Int).Div(common.Q, big.NewInt(2)), // Half of field
		new(big.Int).Sub(common.Q, big.NewInt(1)), // Maximum valid
	}

	// Add random secrets
	for i := 0; i < 2; i++ {
		randomSecret, _ := rand.Int(rand.Reader, common.Q)
		testCases = append(testCases, randomSecret)
	}

	for i, secret := range testCases {
		t.Run("secret_"+string(rune(i+'0')), func(t *testing.T) {
			threshold := 3
			numShares := 5

			shares, err := MakeRandomShares(secret, threshold, numShares)
			if err != nil {
				t.Fatalf("MakeRandomShares failed: %v", err)
			}

			// Convert to point shares
			pointShares := make([]*PointShare, len(shares))
			for j, share := range shares {
				yPoint := common.PointMul(share.Y, common.G)
				pointShares[j] = &PointShare{
					X:     new(big.Int).Set(share.X),
					Point: common.Unexpand(yPoint),
				}
			}

			recoveredPoint, err := RecoverSB(pointShares[:threshold])
			if err != nil {
				t.Fatalf("RecoverSB failed: %v", err)
			}

			expectedPoint4D := common.PointMul(secret, common.G)
			expectedPoint := common.Unexpand(expectedPoint4D)

			if recoveredPoint.X.Cmp(expectedPoint.X) != 0 || recoveredPoint.Y.Cmp(expectedPoint.Y) != 0 {
				t.Errorf("Recovered point doesn't match expected point")
			}
		})
	}
}

// TestShareReconstructVariousThresholds tests with various threshold and share count combinations
func TestShareReconstructVariousThresholds(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)

	testCases := []struct {
		threshold int
		numShares int
	}{
		{1, 1},  // Trivial case
		{1, 5},  // Low threshold, many shares
		{2, 2},  // Threshold equals shares
		{2, 10}, // Low threshold, many shares
		{5, 5},  // Medium threshold equals shares
		{5, 10}, // Medium threshold, more shares
	}

	for _, tc := range testCases {
		t.Run("threshold_"+string(rune(tc.threshold+'0'))+"_shares_"+string(rune(tc.numShares+'0')), func(t *testing.T) {
			shares, err := MakeRandomShares(secret, tc.threshold, tc.numShares)
			if err != nil {
				t.Fatalf("MakeRandomShares failed: %v", err)
			}
			if len(shares) != tc.numShares {
				t.Errorf("Expected %d shares, got %d", tc.numShares, len(shares))
			}

			// Convert to point shares
			pointShares := make([]*PointShare, len(shares))
			for i, share := range shares {
				yPoint := common.PointMul(share.Y, common.G)
				pointShares[i] = &PointShare{
					X:     new(big.Int).Set(share.X),
					Point: common.Unexpand(yPoint),
				}
			}

			recoveredPoint, err := RecoverSB(pointShares[:tc.threshold])
			if err != nil {
				t.Fatalf("RecoverSB failed: %v", err)
			}

			expectedPoint4D := common.PointMul(secret, common.G)
			expectedPoint := common.Unexpand(expectedPoint4D)

			if recoveredPoint.X.Cmp(expectedPoint.X) != 0 || recoveredPoint.Y.Cmp(expectedPoint.Y) != 0 {
				t.Errorf("Recovered point doesn't match expected point")
			}
		})
	}
}

// TestShareIndicesAreCorrect tests that share indices are correctly assigned
func TestShareIndicesAreCorrect(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 2
	numShares := 5

	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Check that x coordinates are sequential starting from 1
	for i, share := range shares {
		expectedX := int64(i + 1)
		if share.X.Int64() != expectedX {
			t.Errorf("Share %d X coordinate: expected %d, got %d", i, expectedX, share.X.Int64())
		}
	}
}

// TestSharesAreDifferent tests that all shares are different
func TestSharesAreDifferent(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 2
	numShares := 10

	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// All y coordinates should be different (x coords are sequential)
	yCoords := make(map[string]bool)
	for _, share := range shares {
		yStr := share.Y.String()
		if yCoords[yStr] {
			t.Errorf("Duplicate Y coordinate found: %s", yStr)
		}
		yCoords[yStr] = true
	}
}

// TestDeterministicBehavior tests that sharing with same secret gives different results (due to randomness)
func TestDeterministicBehavior(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 3
	numShares := 5

	// Generate shares twice
	shares1, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}
	shares2, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Shares should be different due to random polynomial coefficients
	different := false
	for i := 0; i < len(shares1); i++ {
		if shares1[i].Y.Cmp(shares2[i].Y) != 0 {
			different = true
			break
		}
	}

	if !different {
		t.Error("Shares should be different due to randomness")
	}
}

// TestCrossReconstruction tests that shares from different secrets don't cross-reconstruct
func TestCrossReconstruction(t *testing.T) {
	secret1, _ := rand.Int(rand.Reader, common.Q)
	secret2, _ := rand.Int(rand.Reader, common.Q)

	// Ensure secrets are different
	for secret2.Cmp(secret1) == 0 {
		secret2, _ = rand.Int(rand.Reader, common.Q)
	}

	threshold := 3
	numShares := 5

	shares1, err := MakeRandomShares(secret1, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}
	shares2, err := MakeRandomShares(secret2, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Convert to point shares
	pointShares1 := make([]*PointShare, len(shares1))
	for i, share := range shares1 {
		yPoint := common.PointMul(share.Y, common.G)
		pointShares1[i] = &PointShare{
			X:     new(big.Int).Set(share.X),
			Point: common.Unexpand(yPoint),
		}
	}

	pointShares2 := make([]*PointShare, len(shares2))
	for i, share := range shares2 {
		yPoint := common.PointMul(share.Y, common.G)
		pointShares2[i] = &PointShare{
			X:     new(big.Int).Set(share.X),
			Point: common.Unexpand(yPoint),
		}
	}

	// Recover both secrets
	recoveredPoint1, err := RecoverSB(pointShares1[:threshold])
	if err != nil {
		t.Fatalf("RecoverSB failed for secret1: %v", err)
	}
	recoveredPoint2, err := RecoverSB(pointShares2[:threshold])
	if err != nil {
		t.Fatalf("RecoverSB failed for secret2: %v", err)
	}

	// They should be different
	if recoveredPoint1.X.Cmp(recoveredPoint2.X) == 0 && recoveredPoint1.Y.Cmp(recoveredPoint2.Y) == 0 {
		t.Error("Recovered points should be different for different secrets")
	}

	// And should match their respective expected values
	expectedPoint1_4D := common.PointMul(secret1, common.G)
	expectedPoint1 := common.Unexpand(expectedPoint1_4D)
	expectedPoint2_4D := common.PointMul(secret2, common.G)
	expectedPoint2 := common.Unexpand(expectedPoint2_4D)

	if recoveredPoint1.X.Cmp(expectedPoint1.X) != 0 || recoveredPoint1.Y.Cmp(expectedPoint1.Y) != 0 {
		t.Error("Recovered point1 doesn't match expected point1")
	}
	if recoveredPoint2.X.Cmp(expectedPoint2.X) != 0 || recoveredPoint2.Y.Cmp(expectedPoint2.Y) != 0 {
		t.Error("Recovered point2 doesn't match expected point2")
	}
}

// TestLargeThresholdAndShares tests with large threshold and share counts
func TestLargeThresholdAndShares(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 20
	numShares := 50

	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}
	if len(shares) != numShares {
		t.Errorf("Expected %d shares, got %d", numShares, len(shares))
	}

	// Convert to point shares (just first threshold shares to save time)
	pointShares := make([]*PointShare, threshold)
	for i, share := range shares[:threshold] {
		yPoint := common.PointMul(share.Y, common.G)
		pointShares[i] = &PointShare{
			X:     new(big.Int).Set(share.X),
			Point: common.Unexpand(yPoint),
		}
	}

	recoveredPoint, err := RecoverSB(pointShares)
	if err != nil {
		t.Fatalf("RecoverSB failed: %v", err)
	}

	expectedPoint4D := common.PointMul(secret, common.G)
	expectedPoint := common.Unexpand(expectedPoint4D)

	if recoveredPoint.X.Cmp(expectedPoint.X) != 0 || recoveredPoint.Y.Cmp(expectedPoint.Y) != 0 {
		t.Errorf("Recovered point doesn't match expected point")
	}
}

// TestShareStructureConsistency tests that share structure is consistent across different inputs
func TestShareStructureConsistency(t *testing.T) {
	secretsToTest := []*big.Int{
		big.NewInt(1),
		new(big.Int).Div(common.Q, big.NewInt(2)),
		new(big.Int).Sub(common.Q, big.NewInt(1)),
	}

	threshold := 3
	numShares := 5

	for i, secret := range secretsToTest {
		t.Run("secret_"+string(rune(i+'0')), func(t *testing.T) {
			shares, err := MakeRandomShares(secret, threshold, numShares)
			if err != nil {
				t.Fatalf("MakeRandomShares failed: %v", err)
			}

			// All shares should have same structure
			if len(shares) != numShares {
				t.Errorf("Expected %d shares, got %d", numShares, len(shares))
			}
			for j, share := range shares {
				if share.X == nil || share.Y == nil {
					t.Errorf("Share %d has nil X or Y", j)
				}
				if share.X.Int64() != int64(j+1) {
					t.Errorf("Share %d X coordinate should be %d, got %d", j, j+1, share.X.Int64())
				}
			}
		})
	}
}

// TestMakeRandomSharesErrorConditions tests error conditions in MakeRandomShares
func TestMakeRandomSharesErrorConditions(t *testing.T) {
	// Test minimum > shares (should return error)
	_, err := MakeRandomShares(big.NewInt(123), 5, 3) // minimum=5, shares=3
	if err == nil {
		t.Error("Expected error for minimum > shares")
	}
	if err != nil && err.Error() != "pool secret would be irrecoverable" {
		t.Errorf("Expected 'irrecoverable' error, got: %v", err)
	}
}

// TestRecoverSBEdgeCases tests edge cases in RecoverSB function
func TestRecoverSBEdgeCases(t *testing.T) {
	// Test with minimum threshold (2 shares)
	secret := big.NewInt(98765)
	shares, err := MakeRandomShares(secret, 2, 5)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Convert to point shares (use only first 2 shares)
	pointShares := make([]*PointShare, 2)
	for i, share := range shares[:2] {
		yPoint := common.PointMul(share.Y, common.G)
		pointShares[i] = &PointShare{
			X:     new(big.Int).Set(share.X),
			Point: common.Unexpand(yPoint),
		}
	}

	// Recover and verify
	recoveredPoint, err := RecoverSB(pointShares)
	if err != nil {
		t.Fatalf("RecoverSB failed: %v", err)
	}

	expectedPoint4D := common.PointMul(secret, common.G)
	expectedPoint := common.Unexpand(expectedPoint4D)

	if recoveredPoint.X.Cmp(expectedPoint.X) != 0 || recoveredPoint.Y.Cmp(expectedPoint.Y) != 0 {
		t.Errorf("Recovered point doesn't match expected point")
	}
}

// TestSharingWithZeroSecret tests sharing with zero secret
func TestSharingWithZeroSecret(t *testing.T) {
	secret := big.NewInt(0)
	shares, err := MakeRandomShares(secret, 2, 3)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Convert to point shares
	pointShares := make([]*PointShare, 2)
	for i, share := range shares[:2] {
		yPoint := common.PointMul(share.Y, common.G)
		pointShares[i] = &PointShare{
			X:     new(big.Int).Set(share.X),
			Point: common.Unexpand(yPoint),
		}
	}

	// Recover should give zero point (identity element)
	recoveredPoint, err := RecoverSB(pointShares)
	if err != nil {
		t.Fatalf("RecoverSB failed: %v", err)
	}

	expectedPoint4D := common.PointMul(big.NewInt(0), common.G)
	expectedPoint := common.Unexpand(expectedPoint4D)

	if recoveredPoint.X.Cmp(expectedPoint.X) != 0 || recoveredPoint.Y.Cmp(expectedPoint.Y) != 0 {
		t.Errorf("Recovered point doesn't match expected zero point")
	}
}

// TestSharingWithLargeSecret tests sharing with large secret values
func TestSharingWithLargeSecret(t *testing.T) {
	// Test with secret close to prime modulus
	largeSecret := new(big.Int).Sub(common.Q, big.NewInt(1))
	shares, err := MakeRandomShares(largeSecret, 3, 5)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Convert to point shares
	pointShares := make([]*PointShare, 3)
	for i, share := range shares[:3] {
		yPoint := common.PointMul(share.Y, common.G)
		pointShares[i] = &PointShare{
			X:     new(big.Int).Set(share.X),
			Point: common.Unexpand(yPoint),
		}
	}

	// Recover and verify
	recoveredPoint, err := RecoverSB(pointShares)
	if err != nil {
		t.Fatalf("RecoverSB failed: %v", err)
	}

	expectedPoint4D := common.PointMul(largeSecret, common.G)
	expectedPoint := common.Unexpand(expectedPoint4D)

	if recoveredPoint.X.Cmp(expectedPoint.X) != 0 || recoveredPoint.Y.Cmp(expectedPoint.Y) != 0 {
		t.Errorf("Recovered point doesn't match expected point")
	}
}

// TestRecoverSecretBasic tests basic secret recovery functionality
func TestRecoverSecretBasic(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 3
	numShares := 5

	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Test recovery with exactly threshold shares
	recoveredSecret, err := RecoverSecret(shares[:threshold])
	if err != nil {
		t.Fatalf("RecoverSecret failed: %v", err)
	}

	if recoveredSecret.Cmp(secret) != 0 {
		t.Errorf("Recovered secret doesn't match original secret")
	}
}

// TestRecoverSecretDifferentCombinations tests secret recovery with different share combinations
func TestRecoverSecretDifferentCombinations(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 3
	numShares := 6

	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// Test different combinations of threshold shares
	combinations := [][]int{
		{0, 1, 2},
		{1, 2, 3},
		{2, 3, 4},
		{3, 4, 5},
	}

	for _, combo := range combinations {
		testShares := make([]*Share, threshold)
		for i, idx := range combo {
			testShares[i] = shares[idx]
		}

		recoveredSecret, err := RecoverSecret(testShares)
		if err != nil {
			t.Errorf("RecoverSecret failed for combination %v: %v", combo, err)
			continue
		}

		if recoveredSecret.Cmp(secret) != 0 {
			t.Errorf("Recovered secret doesn't match original for combination %v", combo)
		}
	}
}

// TestRecoverSecretInsufficientShares tests secret recovery with insufficient shares
func TestRecoverSecretInsufficientShares(t *testing.T) {
	secret, _ := rand.Int(rand.Reader, common.Q)
	threshold := 4
	numShares := 6

	shares, err := MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		t.Fatalf("MakeRandomShares failed: %v", err)
	}

	// With threshold-1 shares, recovery should give wrong result
	insufficientShares := shares[:threshold-1]
	if len(insufficientShares) > 0 {
		recoveredSecret, err := RecoverSecret(insufficientShares)
		if err != nil {
			t.Fatalf("RecoverSecret failed: %v", err)
		}

		// This should NOT equal the original secret (except by extreme coincidence)
		// We just verify the recovery runs without error
		if recoveredSecret == nil {
			t.Error("RecoverSecret returned nil")
		}
	}
}

// TestPolynomialEvaluationProperties tests mathematical properties of polynomial evaluation
func TestPolynomialEvaluationProperties(t *testing.T) {
	// Test that evalAt correctly implements polynomial evaluation
	// For polynomial a0 + a1*x + a2*x^2, verify manually
	poly := []*big.Int{
		big.NewInt(5), // a0
		big.NewInt(3), // a1
		big.NewInt(2), // a2
	} // 5 + 3x + 2x^2

	// At x=0: should be 5
	result := evalAt(poly, big.NewInt(0), common.Q)
	if result.Int64() != 5 {
		t.Errorf("evalAt(poly, 0) = %d, expected 5", result.Int64())
	}

	// At x=1: should be 5 + 3 + 2 = 10
	result = evalAt(poly, big.NewInt(1), common.Q)
	if result.Int64() != 10 {
		t.Errorf("evalAt(poly, 1) = %d, expected 10", result.Int64())
	}

	// At x=2: should be 5 + 6 + 8 = 19
	result = evalAt(poly, big.NewInt(2), common.Q)
	if result.Int64() != 19 {
		t.Errorf("evalAt(poly, 2) = %d, expected 19", result.Int64())
	}
}

// TestEvalAtEdgeCases tests evalAt function with edge cases
func TestEvalAtEdgeCases(t *testing.T) {
	// Test with empty polynomial (should be 0)
	result := evalAt([]*big.Int{}, big.NewInt(5), common.Q)
	if result.Int64() != 0 {
		t.Errorf("evalAt([], 5) = %d, expected 0", result.Int64())
	}

	// Test with single coefficient (constant polynomial)
	result = evalAt([]*big.Int{big.NewInt(42)}, big.NewInt(100), common.Q)
	if result.Int64() != 42 {
		t.Errorf("evalAt([42], 100) = %d, expected 42", result.Int64())
	}

	// Test with x = 0 (should return constant term)
	poly := []*big.Int{big.NewInt(123), big.NewInt(456), big.NewInt(789)}
	result = evalAt(poly, big.NewInt(0), common.Q)
	if result.Int64() != 123 {
		t.Errorf("evalAt(poly, 0) = %d, expected 123", result.Int64())
	}
}
