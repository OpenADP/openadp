package common

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
)

// TestModpInvBasic tests modular inverse with basic cases
func TestModpInvBasic(t *testing.T) {
	// Test with known values
	inv2 := modpInv(big.NewInt(2))
	expected2 := new(big.Int).Exp(big.NewInt(2), new(big.Int).Sub(P, big.NewInt(2)), P)
	if inv2.Cmp(expected2) != 0 {
		t.Errorf("modpInv(2) failed: got %v, want %v", inv2, expected2)
	}

	inv3 := modpInv(big.NewInt(3))
	expected3 := new(big.Int).Exp(big.NewInt(3), new(big.Int).Sub(P, big.NewInt(2)), P)
	if inv3.Cmp(expected3) != 0 {
		t.Errorf("modpInv(3) failed: got %v, want %v", inv3, expected3)
	}

	// Test that x * modpInv(x) ≡ 1 (mod p)
	testValues := []*big.Int{
		big.NewInt(2), big.NewInt(3), big.NewInt(5), big.NewInt(7),
		big.NewInt(11), big.NewInt(13), big.NewInt(17), big.NewInt(19),
	}

	for _, x := range testValues {
		invX := modpInv(x)
		product := new(big.Int).Mul(x, invX)
		product.Mod(product, P)
		if product.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("x * modpInv(x) != 1 (mod p) for x=%v", x)
		}
	}
}

// TestModpInvEdgeCases tests modular inverse edge cases
func TestModpInvEdgeCases(t *testing.T) {
	// Test with 1 (should be 1)
	inv1 := modpInv(big.NewInt(1))
	if inv1.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("modpInv(1) should be 1, got %v", inv1)
	}

	// Test with p-1 (should be p-1)
	pMinus1 := new(big.Int).Sub(P, big.NewInt(1))
	invPMinus1 := modpInv(pMinus1)
	if invPMinus1.Cmp(pMinus1) != 0 {
		t.Errorf("modpInv(p-1) should be p-1, got %v", invPMinus1)
	}

	// Test with large values
	largeVal := new(big.Int).Div(P, big.NewInt(2))
	invLarge := modpInv(largeVal)
	product := new(big.Int).Mul(largeVal, invLarge)
	product.Mod(product, P)
	if product.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Large value modular inverse failed")
	}
}

// TestExpandBasic tests point expansion from 2D to 4D coordinates
func TestExpandBasic(t *testing.T) {
	// Test with origin-like point
	point2D := &Point2D{X: big.NewInt(0), Y: big.NewInt(1)}
	point4D := Expand(point2D)

	expectedX := big.NewInt(0)
	expectedY := big.NewInt(1)
	expectedZ := big.NewInt(1)
	expectedT := big.NewInt(0) // 0 * 1 = 0

	if point4D.X.Cmp(expectedX) != 0 || point4D.Y.Cmp(expectedY) != 0 ||
		point4D.Z.Cmp(expectedZ) != 0 || point4D.T.Cmp(expectedT) != 0 {
		t.Errorf("Expand(0,1) failed: got (%v,%v,%v,%v), want (%v,%v,%v,%v)",
			point4D.X, point4D.Y, point4D.Z, point4D.T,
			expectedX, expectedY, expectedZ, expectedT)
	}

	// Test with arbitrary point
	point2D = &Point2D{X: big.NewInt(5), Y: big.NewInt(7)}
	point4D = Expand(point2D)

	expectedT = new(big.Int).Mul(big.NewInt(5), big.NewInt(7))
	expectedT.Mod(expectedT, P)

	if point4D.X.Cmp(big.NewInt(5)) != 0 || point4D.Y.Cmp(big.NewInt(7)) != 0 ||
		point4D.Z.Cmp(big.NewInt(1)) != 0 || point4D.T.Cmp(expectedT) != 0 {
		t.Errorf("Expand(5,7) failed")
	}
}

// TestExpandEdgeCases tests point expansion edge cases
func TestExpandEdgeCases(t *testing.T) {
	// Test with large coordinates
	largeX := new(big.Int).Sub(P, big.NewInt(1))
	largeY := new(big.Int).Sub(P, big.NewInt(2))
	point2D := &Point2D{X: largeX, Y: largeY}
	point4D := Expand(point2D)

	expectedT := new(big.Int).Mul(largeX, largeY)
	expectedT.Mod(expectedT, P)

	if point4D.X.Cmp(largeX) != 0 || point4D.Y.Cmp(largeY) != 0 ||
		point4D.Z.Cmp(big.NewInt(1)) != 0 || point4D.T.Cmp(expectedT) != 0 {
		t.Errorf("Expand with large coordinates failed")
	}

	// Test with zero coordinates
	point2D = &Point2D{X: big.NewInt(0), Y: big.NewInt(0)}
	point4D = Expand(point2D)
	if point4D.T.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("Expand(0,0) should have T=0")
	}

	// Test with mixed zero coordinates
	point2D = &Point2D{X: new(big.Int).Sub(P, big.NewInt(1)), Y: big.NewInt(0)}
	point4D = Expand(point2D)
	if point4D.T.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("Expand(p-1,0) should have T=0")
	}
}

// TestPointAddBasic tests point addition basic cases
func TestPointAddBasic(t *testing.T) {
	// Test adding zero point (should be identity)
	result := PointAdd(G, ZeroPoint)

	// Convert both to affine coordinates for comparison
	gAffine := Unexpand(G)
	resultAffine := Unexpand(result)

	if gAffine.X.Cmp(resultAffine.X) != 0 || gAffine.Y.Cmp(resultAffine.Y) != 0 {
		t.Errorf("G + ZeroPoint should equal G in affine coordinates")
	}

	// Test adding point to itself
	doubleG := PointAdd(G, G)
	if len(doubleG.X.Bytes()) == 0 && len(doubleG.Y.Bytes()) == 0 &&
		len(doubleG.Z.Bytes()) == 0 && len(doubleG.T.Bytes()) == 0 {
		t.Errorf("PointAdd(G, G) returned invalid point")
	}

	// Test commutativity: P + Q = Q + P
	p1 := PointAdd(G, ZeroPoint)
	p2 := PointAdd(ZeroPoint, G)
	p1Affine := Unexpand(p1)
	p2Affine := Unexpand(p2)

	if p1Affine.X.Cmp(p2Affine.X) != 0 || p1Affine.Y.Cmp(p2Affine.Y) != 0 {
		t.Errorf("Point addition should be commutative")
	}
}

// TestPointAddAssociativity tests point addition associativity
func TestPointAddAssociativity(t *testing.T) {
	P := G
	Q := PointAdd(G, G) // 2G
	R := PointAdd(Q, G) // 3G

	// (P + Q) + R
	left := PointAdd(PointAdd(P, Q), R)

	// P + (Q + R)
	right := PointAdd(P, PointAdd(Q, R))

	// Compare in affine coordinates
	leftAffine := Unexpand(left)
	rightAffine := Unexpand(right)

	if leftAffine.X.Cmp(rightAffine.X) != 0 || leftAffine.Y.Cmp(rightAffine.Y) != 0 {
		t.Errorf("Point addition should be associative")
	}
}

// TestPointMulBasic tests scalar point multiplication basic cases
func TestPointMulBasic(t *testing.T) {
	// Test multiplication by 0 (should give zero point)
	result := PointMul(big.NewInt(0), G)
	if !PointEqual(result, ZeroPoint) {
		t.Errorf("0 * G should equal ZeroPoint")
	}

	// Test multiplication by 1 (should give same point in affine coordinates)
	result = PointMul(big.NewInt(1), G)
	resultAffine := Unexpand(result)
	gAffine := Unexpand(G)

	if resultAffine.X.Cmp(gAffine.X) != 0 || resultAffine.Y.Cmp(gAffine.Y) != 0 {
		t.Errorf("1 * G should equal G in affine coordinates")
	}

	// Test multiplication by 2
	result = PointMul(big.NewInt(2), G)
	expected := PointAdd(G, G)
	resultAffine = Unexpand(result)
	expectedAffine := Unexpand(expected)

	if resultAffine.X.Cmp(expectedAffine.X) != 0 || resultAffine.Y.Cmp(expectedAffine.Y) != 0 {
		t.Errorf("2 * G should equal G + G")
	}
}

// TestPointMulEdgeCases tests scalar point multiplication edge cases
func TestPointMulEdgeCases(t *testing.T) {
	// Test with large scalar
	largeScalar := new(big.Int).Sub(Q, big.NewInt(1)) // Group order - 1
	result := PointMul(largeScalar, G)

	// Should be a valid point
	if result.X == nil || result.Y == nil || result.Z == nil || result.T == nil {
		t.Errorf("PointMul with large scalar returned invalid point")
	}

	// Test with scalar equal to group order (should give zero point)
	result = PointMul(Q, G)
	if !PointEqual(result, ZeroPoint) {
		t.Errorf("q * G should equal ZeroPoint (where q is group order)")
	}
}

// TestRecoverXBasic tests x-coordinate recovery from y and sign
func TestRecoverXBasic(t *testing.T) {
	// Get the base point coordinates
	gAffine := Unexpand(G)
	gY := gAffine.Y
	gX := gAffine.X

	// Test with sign = 0
	recoveredX := recoverX(gY, 0)
	if recoveredX == nil {
		t.Fatalf("recoverX should not return nil for base point Y")
	}

	// Should recover either gX or p-gX depending on sign bit
	pMinusGX := new(big.Int).Sub(P, gX)
	if recoveredX.Cmp(gX) != 0 && recoveredX.Cmp(pMinusGX) != 0 {
		t.Errorf("recoverX didn't return expected X coordinate")
	}

	// Test with sign = 1
	recoveredX = recoverX(gY, 1)
	if recoveredX == nil {
		t.Fatalf("recoverX should not return nil for base point Y with sign=1")
	}

	if recoveredX.Cmp(gX) != 0 && recoveredX.Cmp(pMinusGX) != 0 {
		t.Errorf("recoverX with sign=1 didn't return expected X coordinate")
	}
}

// TestRecoverXEdgeCases tests x-coordinate recovery edge cases
func TestRecoverXEdgeCases(t *testing.T) {
	// Test with y = 0
	result := recoverX(big.NewInt(0), 0)
	if result != nil {
		if result.Cmp(big.NewInt(0)) < 0 || result.Cmp(P) >= 0 {
			t.Errorf("recoverX(0, 0) returned invalid coordinate: %v", result)
		}
	}

	// Test with y >= p (should return nil)
	result = recoverX(P, 0)
	if result != nil {
		t.Errorf("recoverX(p, 0) should return nil, got %v", result)
	}

	result = recoverX(new(big.Int).Add(P, big.NewInt(1)), 0)
	if result != nil {
		t.Errorf("recoverX(p+1, 0) should return nil, got %v", result)
	}

	// Test with y = p - 1
	result = recoverX(new(big.Int).Sub(P, big.NewInt(1)), 0)
	if result != nil {
		if result.Cmp(big.NewInt(0)) < 0 || result.Cmp(P) >= 0 {
			t.Errorf("recoverX(p-1, 0) returned invalid coordinate: %v", result)
		}
	}
}

// TestPointCompressDecompressRoundtrip tests compression/decompression roundtrip
func TestPointCompressDecompressRoundtrip(t *testing.T) {
	// Test with base point
	compressed := PointCompress(G)
	if len(compressed) != 32 {
		t.Errorf("Compressed point should be 32 bytes, got %d", len(compressed))
	}

	decompressed, err := PointDecompress(compressed)
	if err != nil {
		t.Fatalf("Failed to decompress base point: %v", err)
	}

	if !PointEqual(G, decompressed) {
		t.Errorf("Decompressed base point should equal original")
	}

	// Test with random points
	testScalars := []*big.Int{
		big.NewInt(123), big.NewInt(456), big.NewInt(789),
		big.NewInt(1000000), big.NewInt(999999999),
	}

	for _, scalar := range testScalars {
		point := PointMul(scalar, G)
		compressed := PointCompress(point)
		decompressed, err := PointDecompress(compressed)

		if err != nil {
			t.Errorf("Failed to decompress point for scalar %v: %v", scalar, err)
			continue
		}

		if !PointEqual(point, decompressed) {
			t.Errorf("Roundtrip failed for scalar %v", scalar)
		}
	}
}

// TestPointDecompressInvalidInput tests point decompression with invalid input
func TestPointDecompressInvalidInput(t *testing.T) {
	// Test with wrong length
	invalidLengths := []int{0, 1, 16, 31, 33, 64}

	for _, length := range invalidLengths {
		data := make([]byte, length)
		_, err := PointDecompress(data)
		if err == nil {
			t.Errorf("PointDecompress should fail with length %d", length)
		}
	}

	// Test with invalid point data (all 0xFF)
	invalidData := make([]byte, 32)
	for i := range invalidData {
		invalidData[i] = 0xFF
	}

	_, err := PointDecompress(invalidData)
	// This might or might not fail depending on the curve, but shouldn't crash
	_ = err // Ignore the result, just ensure no panic
}

// TestUnexpand tests conversion from 4D to 2D coordinates
func TestUnexpand(t *testing.T) {
	// Test with base point
	gAffine := Unexpand(G)

	if gAffine.X == nil || gAffine.Y == nil {
		t.Errorf("Unexpand(G) returned nil coordinates")
	}

	// Test roundtrip: expand(unexpand(P)) should equal P in affine coordinates
	expanded := Expand(gAffine)
	unexpandedAgain := Unexpand(expanded)

	if gAffine.X.Cmp(unexpandedAgain.X) != 0 || gAffine.Y.Cmp(unexpandedAgain.Y) != 0 {
		t.Errorf("Expand/Unexpand roundtrip failed")
	}

	// Test with zero point
	zeroAffine := Unexpand(ZeroPoint)
	if zeroAffine.X.Cmp(big.NewInt(0)) != 0 || zeroAffine.Y.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Unexpand(ZeroPoint) should be (0, 1), got (%v, %v)", zeroAffine.X, zeroAffine.Y)
	}
}

// TestHFunctionBasic tests the H function basic cases
func TestHFunctionBasic(t *testing.T) {
	uid := []byte("test-uid")
	did := []byte("test-did")
	bid := []byte("test-bid")
	pin := []byte{0x12, 0x34}

	// Test that H function is deterministic
	point1 := H(uid, did, bid, pin)
	point2 := H(uid, did, bid, pin)

	if !PointEqual(point1, point2) {
		t.Errorf("H function should be deterministic")
	}

	// Test that different inputs give different outputs
	point3 := H([]byte("different-uid"), did, bid, pin)
	if PointEqual(point1, point3) {
		t.Errorf("Different inputs should give different outputs")
	}

	// Test that the result is a valid point
	if !testPointValid(point1) {
		t.Errorf("H function should return a valid point")
	}
}

// TestHFunctionEdgeCases tests H function edge cases
func TestHFunctionEdgeCases(t *testing.T) {
	// Test with empty inputs
	point1 := H([]byte{}, []byte{}, []byte{}, []byte{})
	if !testPointValid(point1) {
		t.Errorf("H function should handle empty inputs")
	}

	// Test with very long inputs
	longInput := make([]byte, 1000)
	for i := range longInput {
		longInput[i] = byte(i % 256)
	}

	point2 := H(longInput, longInput, longInput, longInput[:2])
	if !testPointValid(point2) {
		t.Errorf("H function should handle long inputs")
	}

	// Test with single byte differences
	uid1 := []byte("test-uid")
	uid2 := []byte("test-uie") // Last character different

	point3 := H(uid1, []byte("did"), []byte("bid"), []byte{0x12, 0x34})
	point4 := H(uid2, []byte("did"), []byte("bid"), []byte{0x12, 0x34})

	if PointEqual(point3, point4) {
		t.Errorf("Single byte difference should produce different points")
	}
}

// TestDeriveEncKeyBasic tests encryption key derivation basic cases
func TestDeriveEncKeyBasic(t *testing.T) {
	// Test key derivation from base point
	key1 := DeriveEncKey(G)
	key2 := DeriveEncKey(G)

	if len(key1) != 32 {
		t.Errorf("Derived key should be 32 bytes, got %d", len(key1))
	}

	if !bytes.Equal(key1, key2) {
		t.Errorf("Same point should derive same key")
	}

	// Test that different points give different keys
	point2 := PointMul(big.NewInt(12345), G)
	key3 := DeriveEncKey(point2)

	if bytes.Equal(key1, key3) {
		t.Errorf("Different points should derive different keys")
	}
}

// TestDeriveEncKeyEdgeCases tests encryption key derivation edge cases
func TestDeriveEncKeyEdgeCases(t *testing.T) {
	// Test with zero point
	key1 := DeriveEncKey(ZeroPoint)
	if len(key1) != 32 {
		t.Errorf("Key from zero point should be 32 bytes")
	}

	// Test with large scalar points
	largeScalar := new(big.Int).Sub(Q, big.NewInt(1))
	largePoint := PointMul(largeScalar, G)
	key2 := DeriveEncKey(largePoint)

	if len(key2) != 32 {
		t.Errorf("Key from large point should be 32 bytes")
	}

	if bytes.Equal(key1, key2) {
		t.Errorf("Different points should give different keys")
	}
}

// TestX25519Functions tests X25519 cryptographic functions
func TestX25519Functions(t *testing.T) {
	// Test keypair generation
	private1, public1, err := X25519GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	if len(private1) != 32 {
		t.Errorf("Private key should be 32 bytes, got %d", len(private1))
	}
	if len(public1) != 32 {
		t.Errorf("Public key should be 32 bytes, got %d", len(public1))
	}

	// Test public key derivation
	public1Derived, err := X25519PublicKeyFromPrivate(private1)
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}

	if !bytes.Equal(public1, public1Derived) {
		t.Errorf("Derived public key should match generated public key")
	}

	// Test Diffie-Hellman
	private2, public2, err := X25519GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate second keypair: %v", err)
	}

	shared1, err := X25519DH(private1, public2)
	if err != nil {
		t.Fatalf("Failed to compute DH (1->2): %v", err)
	}

	shared2, err := X25519DH(private2, public1)
	if err != nil {
		t.Fatalf("Failed to compute DH (2->1): %v", err)
	}

	if !bytes.Equal(shared1, shared2) {
		t.Errorf("DH shared secrets should be equal")
	}
}

// TestX25519EdgeCases tests X25519 edge cases
func TestX25519EdgeCases(t *testing.T) {
	// Test with all-zero private key (should be handled gracefully)
	zeroPrivate := make([]byte, 32)
	_, err := X25519PublicKeyFromPrivate(zeroPrivate)
	// This might fail or succeed depending on implementation, but shouldn't crash
	_ = err

	// Test with all-ones private key
	onesPrivate := make([]byte, 32)
	for i := range onesPrivate {
		onesPrivate[i] = 0xFF
	}
	_, err = X25519PublicKeyFromPrivate(onesPrivate)
	_ = err // Shouldn't crash

	// Test DH with same key (should work)
	private, public, err := X25519GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	shared, err := X25519DH(private, public)
	if err != nil {
		t.Fatalf("Failed to compute DH with same key: %v", err)
	}

	if len(shared) != 32 {
		t.Errorf("Shared secret should be 32 bytes, got %d", len(shared))
	}
}

// TestConstantsValidity tests that cryptographic constants are valid
func TestConstantsValidity(t *testing.T) {
	// Test that P is odd (required for modular arithmetic)
	if P.Bit(0) != 1 {
		t.Errorf("Prime P should be odd")
	}

	// Test that Q is the group order
	if Q.Sign() <= 0 {
		t.Errorf("Group order Q should be positive")
	}

	// Test that G is a valid point
	if !testPointValid(G) {
		t.Errorf("Base point G should be valid")
	}

	// Test that ZeroPoint is the identity
	result := PointAdd(G, ZeroPoint)
	if !PointEqual(result, G) {
		t.Errorf("ZeroPoint should be the identity element")
	}

	// Test that Q * G = ZeroPoint
	qG := PointMul(Q, G)
	if !PointEqual(qG, ZeroPoint) {
		t.Errorf("Q * G should equal ZeroPoint")
	}
}

// Helper function to check if a point is valid (test version)
func testPointValid(p *Point4D) bool {
	if p == nil || p.X == nil || p.Y == nil || p.Z == nil || p.T == nil {
		return false
	}

	// Check that coordinates are in valid range
	if p.X.Cmp(P) >= 0 || p.Y.Cmp(P) >= 0 || p.Z.Cmp(P) >= 0 || p.T.Cmp(P) >= 0 {
		return false
	}

	if p.X.Sign() < 0 || p.Y.Sign() < 0 || p.Z.Sign() < 0 || p.T.Sign() < 0 {
		return false
	}

	return true
}

// TestSha256HashComprehensive tests SHA256 hash function comprehensively
func TestSha256HashComprehensive(t *testing.T) {
	// Test with empty input
	hash1 := Sha256Hash([]byte{})
	if len(hash1) != 32 {
		t.Errorf("SHA256 hash should be 32 bytes, got %d", len(hash1))
	}

	// Test with known vectors
	testCases := []struct {
		input    string
		expected string // First 8 hex chars for verification
	}{
		{"", "e3b0c442"},
		{"a", "ca978112"},
		{"abc", "ba7816bf"},
		{"hello", "2cf24dba"},
	}

	for _, tc := range testCases {
		hash := Sha256Hash([]byte(tc.input))
		hashHex := ""
		for i := 0; i < 4; i++ {
			hashHex += fmt.Sprintf("%02x", hash[i])
		}
		if hashHex != tc.expected {
			t.Errorf("SHA256(%q) first 4 bytes: got %s, want %s", tc.input, hashHex, tc.expected)
		}
	}

	// Test that different inputs give different hashes
	hash2 := Sha256Hash([]byte("different"))
	if bytes.Equal(hash1, hash2) {
		t.Errorf("Different inputs should give different hashes")
	}

	// Test with large input
	largeInput := make([]byte, 10000)
	for i := range largeInput {
		largeInput[i] = byte(i % 256)
	}
	hash3 := Sha256Hash(largeInput)
	if len(hash3) != 32 {
		t.Errorf("SHA256 of large input should be 32 bytes")
	}
}

// TestUtilityFunctionsComprehensive tests utility functions comprehensively
func TestUtilityFunctionsComprehensive(t *testing.T) {
	// Test SecretExpand with various inputs
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	expandedSecret, err := SecretExpand(secret)
	if err != nil {
		t.Fatalf("SecretExpand failed: %v", err)
	}

	if expandedSecret.Sign() <= 0 {
		t.Errorf("Expanded secret should be positive")
	}

	// Test SecretToPublic
	publicKey, err := SecretToPublic(secret)
	if err != nil {
		t.Fatalf("SecretToPublic failed: %v", err)
	}

	if len(publicKey) != 32 {
		t.Errorf("Public key should be 32 bytes, got %d", len(publicKey))
	}

	// Test consistency
	publicKey2, err := SecretToPublic(secret)
	if err != nil {
		t.Fatalf("SecretToPublic second call failed: %v", err)
	}

	if !bytes.Equal(publicKey, publicKey2) {
		t.Errorf("SecretToPublic should be deterministic")
	}
}

// TestPointOperationsEdgeCases tests point operations with edge cases
func TestPointOperationsEdgeCases(t *testing.T) {
	// Test point multiplication with zero
	zeroResult := PointMul(big.NewInt(0), G)
	if !PointEqual(zeroResult, ZeroPoint) {
		t.Errorf("0 * G should equal ZeroPoint")
	}

	// Test point multiplication with negative numbers (should handle gracefully)
	negativeResult := PointMul(big.NewInt(-1), G)
	if negativeResult == nil {
		t.Errorf("PointMul with negative scalar shouldn't return nil")
	}

	// Test point addition with same point
	doubleG := PointAdd(G, G)
	doubleGMul := PointMul(big.NewInt(2), G)

	if !PointEqual(doubleG, doubleGMul) {
		t.Errorf("G + G should equal 2 * G")
	}

	// Test point compression/decompression with edge points
	largeScalar := new(big.Int).Sub(Q, big.NewInt(2))
	edgePoint := PointMul(largeScalar, G)

	compressed := PointCompress(edgePoint)
	decompressed, err := PointDecompress(compressed)

	if err != nil {
		t.Errorf("Failed to decompress edge point: %v", err)
	} else if !PointEqual(edgePoint, decompressed) {
		t.Errorf("Edge point compression/decompression failed")
	}
}

// TestCurveEquation tests that points satisfy the curve equation
func TestCurveEquation(t *testing.T) {
	// Helper function to check curve equation for a point
	checkCurveEquation := func(point *Point4D) bool {
		// Convert to affine coordinates
		affine := Unexpand(point)
		x, y := affine.X, affine.Y

		// For Ed25519: -x^2 + y^2 = 1 + d*x^2*y^2
		// Where d = -121665/121666

		x2 := new(big.Int).Mul(x, x)
		x2.Mod(x2, P)

		y2 := new(big.Int).Mul(y, y)
		y2.Mod(y2, P)

		// Left side: -x^2 + y^2
		left := new(big.Int).Sub(y2, x2)
		left.Mod(left, P)

		// Right side: 1 + d*x^2*y^2
		// d = -121665/121666 mod p
		d := big.NewInt(-121665)
		dInv := modpInv(big.NewInt(121666))
		d.Mul(d, dInv)
		d.Mod(d, P)

		x2y2 := new(big.Int).Mul(x2, y2)
		x2y2.Mod(x2y2, P)

		right := new(big.Int).Mul(d, x2y2)
		right.Add(right, big.NewInt(1))
		right.Mod(right, P)

		return left.Cmp(right) == 0
	}

	// Test base point
	if !checkCurveEquation(G) {
		t.Errorf("Base point G doesn't satisfy curve equation")
	}

	// Test zero point
	if !checkCurveEquation(ZeroPoint) {
		t.Errorf("Zero point doesn't satisfy curve equation")
	}

	// Test random points
	testScalars := []*big.Int{
		big.NewInt(2), big.NewInt(3), big.NewInt(17), big.NewInt(12345),
	}

	for _, scalar := range testScalars {
		point := PointMul(scalar, G)
		if !checkCurveEquation(point) {
			t.Errorf("Point %v*G doesn't satisfy curve equation", scalar)
		}
	}
}
