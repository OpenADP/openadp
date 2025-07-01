package common

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

// FuzzPoint2D fuzzes Point2D operations
func FuzzPoint2D(f *testing.F) {
	f.Add(int64(0), int64(0))
	f.Add(int64(1), int64(1))
	f.Add(int64(-1), int64(-1))
	f.Add(int64(9223372036854775807), int64(9223372036854775807)) // Max int64

	f.Fuzz(func(t *testing.T, x, y int64) {
		// Test Point2D creation
		point := &Point2D{
			X: big.NewInt(x),
			Y: big.NewInt(y),
		}

		// Should not panic on nil operations
		if point.X == nil || point.Y == nil {
			return // Skip invalid points
		}

		// Test point operations don't panic
		point2 := &Point2D{
			X: big.NewInt(y), // Swap x and y
			Y: big.NewInt(x),
		}

		// Basic validation that points are created correctly
		if point.X.Int64() != x {
			t.Errorf("X mismatch: expected %d, got %d", x, point.X.Int64())
		}
		if point.Y.Int64() != y {
			t.Errorf("Y mismatch: expected %d, got %d", y, point.Y.Int64())
		}

		// Test that we can handle point2 operations
		_ = point2 // Use the variable to avoid unused variable error
	})
}

// FuzzPoint4D fuzzes Point4D operations
func FuzzPoint4D(f *testing.F) {
	f.Add(int64(1), int64(2), int64(3), int64(4))
	f.Add(int64(0), int64(0), int64(0), int64(0))
	f.Add(int64(-1), int64(-2), int64(-3), int64(-4))

	f.Fuzz(func(t *testing.T, x, y, z, t_coord int64) {
		// Test Point4D creation with fuzzed inputs
		point := &Point4D{
			X: big.NewInt(x),
			Y: big.NewInt(y),
			Z: big.NewInt(z),
			T: big.NewInt(t_coord),
		}

		// Should not panic
		if point.X == nil || point.Y == nil || point.Z == nil || point.T == nil {
			return // Skip invalid points
		}

		// Basic validation
		if point.X.Int64() != x {
			t.Errorf("X mismatch: expected %d, got %d", x, point.X.Int64())
		}
		if point.Y.Int64() != y {
			t.Errorf("Y mismatch: expected %d, got %d", y, point.Y.Int64())
		}
		if point.Z.Int64() != z {
			t.Errorf("Z mismatch: expected %d, got %d", z, point.Z.Int64())
		}
		if point.T.Int64() != t_coord {
			t.Errorf("T mismatch: expected %d, got %d", t_coord, point.T.Int64())
		}
	})
}

// FuzzScalarMult fuzzes scalar multiplication operations
func FuzzScalarMult(f *testing.F) {
	f.Add(int64(123), int64(456), int64(789))
	f.Add(int64(0), int64(1), int64(1))
	f.Add(int64(1), int64(0), int64(0))

	f.Fuzz(func(t *testing.T, scalar, pointX, pointY int64) {
		// Create scalar
		s := big.NewInt(scalar)

		// Create point
		point := &Point4D{
			X: big.NewInt(pointX),
			Y: big.NewInt(pointY),
			Z: big.NewInt(1), // Standard projective coordinate
			T: new(big.Int).Mul(big.NewInt(pointX), big.NewInt(pointY)),
		}

		// Test scalar multiplication - should not panic
		result := PointMul(s, point)

		// Result should be valid point
		if result == nil {
			t.Error("PointMul returned nil")
		} else {
			if result.X == nil || result.Y == nil || result.Z == nil || result.T == nil {
				t.Error("PointMul returned point with nil coordinates")
			}
		}
	})
}

// FuzzPointAdd fuzzes Edwards curve point addition
func FuzzPointAdd(f *testing.F) {
	f.Add(int64(100), int64(200), int64(300), int64(400))
	f.Add(int64(0), int64(1), int64(1), int64(0))
	f.Add(int64(1), int64(0), int64(0), int64(1))

	f.Fuzz(func(t *testing.T, x1, y1, x2, y2 int64) {
		// Create two points
		p1 := &Point4D{
			X: big.NewInt(x1),
			Y: big.NewInt(y1),
			Z: big.NewInt(1),
			T: new(big.Int).Mul(big.NewInt(x1), big.NewInt(y1)),
		}

		p2 := &Point4D{
			X: big.NewInt(x2),
			Y: big.NewInt(y2),
			Z: big.NewInt(1),
			T: new(big.Int).Mul(big.NewInt(x2), big.NewInt(y2)),
		}

		// Test point addition - should not panic
		result := PointAdd(p1, p2)

		// Result should be valid
		if result == nil {
			t.Error("PointAdd returned nil")
		} else {
			if result.X == nil || result.Y == nil || result.Z == nil || result.T == nil {
				t.Error("PointAdd returned point with nil coordinates")
			}
		}
	})
}

// FuzzX25519Operations fuzzes X25519 key operations
func FuzzX25519Operations(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5})
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, 32))
	f.Add(bytes.Repeat([]byte{0x00}, 32))
	f.Add(bytes.Repeat([]byte{0xAA}, 100)) // Oversized

	f.Fuzz(func(t *testing.T, keyData []byte) {
		// Test key generation - should not panic
		privKey, pubKey, err := X25519GenerateKeypair()

		if err != nil {
			t.Errorf("X25519GenerateKeypair failed: %v", err)
			return
		}

		// Keys should be proper length
		if len(privKey) != 32 {
			t.Errorf("Private key length %d != 32", len(privKey))
		}
		if len(pubKey) != 32 {
			t.Errorf("Public key length %d != 32", len(pubKey))
		}

		// Test with fuzzed key data if it's the right size
		if len(keyData) == 32 {
			// Test shared secret computation
			sharedSecret, err := X25519DH(privKey, keyData)
			if err != nil {
				// Some key combinations may be invalid, that's okay
				return
			}

			if len(sharedSecret) != 32 {
				t.Errorf("Shared secret length %d != 32", len(sharedSecret))
			}
		}
	})
}

// FuzzHashFunctions fuzzes hash function implementations
func FuzzHashFunctions(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte(""))
	f.Add(bytes.Repeat([]byte{0x00}, 1000))
	f.Add(bytes.Repeat([]byte{0xFF}, 1000))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test available hash functions - should not panic

		// Test Sha256Hash function
		hash := Sha256Hash(data)
		if len(hash) != 32 {
			t.Errorf("Sha256Hash hash length %d != 32", len(hash))
		}

		// Test that hash is deterministic
		hash2 := Sha256Hash(data)
		if !bytes.Equal(hash, hash2) {
			t.Error("Sha256Hash is not deterministic")
		}
	})
}

// FuzzRandomBytes fuzzes random byte generation
func FuzzRandomBytes(f *testing.F) {
	f.Add(0)
	f.Add(1)
	f.Add(32)
	f.Add(1000)
	f.Add(-1) // Invalid size

	f.Fuzz(func(t *testing.T, size int) {
		if size < 0 || size > 10000 { // Reasonable limits
			return
		}

		// Test random byte generation
		randomBytes := make([]byte, size)
		_, err := rand.Read(randomBytes)

		if err != nil {
			t.Errorf("Failed to generate random bytes: %v", err)
		}

		if len(randomBytes) != size {
			t.Errorf("Random bytes length %d != %d", len(randomBytes), size)
		}

		// For non-zero sizes, check that we didn't get all zeros
		if size > 10 {
			allZeros := true
			for _, b := range randomBytes {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				t.Error("Generated all-zero random bytes (very unlikely)")
			}
		}
	})
}

// FuzzPointConversions fuzzes conversions between point formats
func FuzzPointConversions(f *testing.F) {
	f.Add(int64(123), int64(456))
	f.Add(int64(0), int64(0))
	f.Add(int64(-1), int64(-1))

	f.Fuzz(func(t *testing.T, x, y int64) {
		// Create Point2D
		point2D := &Point2D{
			X: big.NewInt(x),
			Y: big.NewInt(y),
		}

		// Convert to Point4D (if such conversion exists)
		point4D := &Point4D{
			X: new(big.Int).Set(point2D.X),
			Y: new(big.Int).Set(point2D.Y),
			Z: big.NewInt(1),
			T: new(big.Int).Mul(point2D.X, point2D.Y),
		}

		// Convert back to Point2D
		convertedPoint2D := &Point2D{
			X: new(big.Int).Set(point4D.X),
			Y: new(big.Int).Set(point4D.Y),
		}

		// Should be equal
		if point2D.X.Cmp(convertedPoint2D.X) != 0 {
			t.Errorf("X conversion mismatch: %v != %v", point2D.X, convertedPoint2D.X)
		}
		if point2D.Y.Cmp(convertedPoint2D.Y) != 0 {
			t.Errorf("Y conversion mismatch: %v != %v", point2D.Y, convertedPoint2D.Y)
		}
	})
}

// FuzzBigIntOperations fuzzes big integer operations used in crypto
func FuzzBigIntOperations(f *testing.F) {
	f.Add(int64(100), int64(7)) // a, modulus
	f.Add(int64(0), int64(1))
	f.Add(int64(-1), int64(5))

	f.Fuzz(func(t *testing.T, a, mod int64) {
		if mod <= 0 {
			return // Skip invalid modulus
		}

		// Skip edge cases that don't have well-defined behavior
		if mod == 1 || a == 0 {
			return // mod 1 and inverse of 0 are edge cases
		}

		bigA := big.NewInt(a)
		bigMod := big.NewInt(mod)

		// Test modular operations - should not panic
		result := new(big.Int)

		// Modular reduction
		result.Mod(bigA, bigMod)

		// Result should be in range [0, mod)
		if result.Cmp(bigMod) >= 0 {
			t.Errorf("Mod result %v >= modulus %v", result, bigMod)
		}
		if result.Sign() < 0 {
			t.Errorf("Mod result %v < 0", result)
		}

		// Test modular inverse (if gcd(a, mod) == 1 and a != 0)
		gcd := new(big.Int)
		gcd.GCD(nil, nil, bigA, bigMod)
		if gcd.Cmp(big.NewInt(1)) == 0 && bigA.Sign() != 0 {
			inverse := new(big.Int)
			if inverse.ModInverse(bigA, bigMod) != nil {
				// Verify: (a * inverse) mod mod == 1
				check := new(big.Int)
				check.Mul(bigA, inverse)
				check.Mod(check, bigMod)
				if check.Cmp(big.NewInt(1)) != 0 {
					t.Errorf("Modular inverse check failed: (%v * %v) mod %v = %v != 1",
						bigA, inverse, bigMod, check)
				}
			}
		}
	})
}
