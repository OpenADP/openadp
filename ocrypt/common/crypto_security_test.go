package common

import (
	"bytes"
	"math/big"
	"testing"
)

// TestDeriveSecret tests the critical DeriveSecret function - 0% coverage currently
func TestDeriveSecret(t *testing.T) {
	tests := []struct {
		name    string
		uid     []byte
		did     []byte
		bid     []byte
		pin     []byte
		wantNil bool
	}{
		{
			name: "basic derivation",
			uid:  []byte("test-uid"),
			did:  []byte("test-did"),
			bid:  []byte("test-bid"),
			pin:  []byte("test-pin"),
		},
		{
			name: "empty inputs",
			uid:  []byte(""),
			did:  []byte(""),
			bid:  []byte(""),
			pin:  []byte(""),
		},
		{
			name: "large inputs",
			uid:  bytes.Repeat([]byte("A"), 1000),
			did:  bytes.Repeat([]byte("B"), 1000),
			bid:  bytes.Repeat([]byte("C"), 1000),
			pin:  bytes.Repeat([]byte("D"), 1000),
		},
		{
			name: "unicode inputs",
			uid:  []byte("测试用户"),
			did:  []byte("тест-устройство"),
			bid:  []byte("файл.txt"),
			pin:  []byte("пароль"),
		},
		{
			name: "binary inputs",
			uid:  []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
			did:  []byte{0x80, 0x81, 0x82, 0x83, 0x7F, 0x7E, 0x7D},
			bid:  []byte{0x40, 0x41, 0x42, 0x43, 0xBF, 0xBE, 0xBD},
			pin:  []byte{0x20, 0x21, 0x22, 0x23, 0xDF, 0xDE, 0xDD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := DeriveSecret(tt.uid, tt.did, tt.bid, tt.pin)

			if secret == nil {
				t.Errorf("DeriveSecret() returned nil")
				return
			}

			// Secret should never be zero
			if secret.Sign() == 0 {
				t.Errorf("DeriveSecret() returned zero secret")
			}

			// Secret should be less than Q
			if secret.Cmp(Q) >= 0 {
				t.Errorf("DeriveSecret() returned secret >= Q")
			}

			// Same inputs should produce same secret (deterministic)
			secret2 := DeriveSecret(tt.uid, tt.did, tt.bid, tt.pin)
			if secret.Cmp(secret2) != 0 {
				t.Errorf("DeriveSecret() not deterministic: %s != %s", secret.String(), secret2.String())
			}

			// Different inputs should produce different secrets (with high probability)
			if len(tt.uid) > 0 {
				differentUID := make([]byte, len(tt.uid))
				copy(differentUID, tt.uid)
				differentUID[0] ^= 0x01

				secret3 := DeriveSecret(differentUID, tt.did, tt.bid, tt.pin)
				if secret.Cmp(secret3) == 0 {
					t.Errorf("DeriveSecret() collision with different UID")
				}
			}
		})
	}
}

// TestSecretExpand tests the critical SecretExpand function
func TestSecretExpand(t *testing.T) {
	tests := []struct {
		name      string
		secret    []byte
		wantError bool
	}{
		{
			name:      "valid 32-byte secret",
			secret:    make([]byte, 32),
			wantError: false,
		},
		{
			name:      "random 32-byte secret",
			secret:    []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20},
			wantError: false,
		},
		{
			name:      "all-ones secret",
			secret:    bytes.Repeat([]byte{0xFF}, 32),
			wantError: false,
		},
		{
			name:      "empty secret",
			secret:    []byte{},
			wantError: true,
		},
		{
			name:      "too short secret",
			secret:    make([]byte, 31),
			wantError: true,
		},
		{
			name:      "too long secret",
			secret:    make([]byte, 33),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expanded, err := SecretExpand(tt.secret)

			if tt.wantError {
				if err == nil {
					t.Errorf("SecretExpand() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("SecretExpand() unexpected error: %v", err)
				return
			}

			if expanded == nil {
				t.Errorf("SecretExpand() returned nil without error")
				return
			}

			// Check that bit 254 is set (as per Ed25519 spec)
			bit254 := new(big.Int).Lsh(big.NewInt(1), 254)
			if new(big.Int).And(expanded, bit254).Sign() == 0 {
				t.Errorf("SecretExpand() bit 254 not set")
			}

			// Check that lower 3 bits are cleared
			if new(big.Int).And(expanded, big.NewInt(7)).Sign() != 0 {
				t.Errorf("SecretExpand() lower 3 bits not cleared")
			}
		})
	}
}

// TestSecretToPublic tests the SecretToPublic function
func TestSecretToPublic(t *testing.T) {
	tests := []struct {
		name      string
		secret    []byte
		wantError bool
	}{
		{
			name:      "valid secret",
			secret:    make([]byte, 32),
			wantError: false,
		},
		{
			name:      "random valid secret",
			secret:    []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			wantError: false,
		},
		{
			name:      "invalid size",
			secret:    make([]byte, 31),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			public, err := SecretToPublic(tt.secret)

			if tt.wantError {
				if err == nil {
					t.Errorf("SecretToPublic() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("SecretToPublic() unexpected error: %v", err)
				return
			}

			if len(public) != 32 {
				t.Errorf("SecretToPublic() returned %d bytes, want 32", len(public))
			}

			// Same secret should produce same public key
			public2, err := SecretToPublic(tt.secret)
			if err != nil {
				t.Errorf("SecretToPublic() second call failed: %v", err)
				return
			}

			if !bytes.Equal(public, public2) {
				t.Errorf("SecretToPublic() not deterministic")
			}
		})
	}
}

// TestPointValid tests the critical pointValid function
func TestPointValid(t *testing.T) {
	tests := []struct {
		name   string
		point  *Point4D
		wantOK bool
	}{
		{
			name:   "nil point",
			point:  nil,
			wantOK: false,
		},
		{
			name: "point with nil fields",
			point: &Point4D{
				X: nil,
				Y: big.NewInt(1),
				Z: big.NewInt(1),
				T: big.NewInt(1),
			},
			wantOK: false,
		},
		{
			name:   "zero point",
			point:  ZeroPoint,
			wantOK: false,
		},
		{
			name:   "base point G",
			point:  G,
			wantOK: true,
		},
		{
			name:   "valid point derived from scalar multiplication",
			point:  PointMul(big.NewInt(42), G), // 42*G is a valid point
			wantOK: true,
		},
		{
			name: "arbitrary coordinates (not necessarily on curve)",
			point: &Point4D{
				X: big.NewInt(123),
				Y: big.NewInt(456),
				Z: big.NewInt(1),
				T: big.NewInt(789),
			},
			wantOK: true, // Cofactor clearing only checks for small subgroup, not curve membership
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidPoint(tt.point)
			if result != tt.wantOK {
				t.Errorf("IsValidPoint() = %v, want %v", result, tt.wantOK)
			}
		})
	}
}

// TestX25519GenerateKeypair tests the X25519GenerateKeypair function
func TestX25519GenerateKeypair(t *testing.T) {
	// Test key generation
	private1, public1, err := X25519GenerateKeypair()
	if err != nil {
		t.Errorf("X25519GenerateKeypair() error: %v", err)
		return
	}

	if len(private1) != 32 {
		t.Errorf("X25519GenerateKeypair() private key length = %d, want 32", len(private1))
	}

	if len(public1) != 32 {
		t.Errorf("X25519GenerateKeypair() public key length = %d, want 32", len(public1))
	}

	// Test that keys are different each time
	private2, public2, err := X25519GenerateKeypair()
	if err != nil {
		t.Errorf("X25519GenerateKeypair() second call error: %v", err)
		return
	}

	if bytes.Equal(private1, private2) {
		t.Errorf("X25519GenerateKeypair() generated same private key twice")
	}

	if bytes.Equal(public1, public2) {
		t.Errorf("X25519GenerateKeypair() generated same public key twice")
	}

	// Test that public key can be derived from private key
	derivedPublic1, err := X25519PublicKeyFromPrivate(private1)
	if err != nil {
		t.Errorf("X25519PublicKeyFromPrivate() error: %v", err)
		return
	}

	if !bytes.Equal(public1, derivedPublic1) {
		t.Errorf("X25519GenerateKeypair() public key doesn't match derived public key")
	}
}

// TestX25519DH tests the X25519DH function
func TestX25519DH(t *testing.T) {
	// Generate two keypairs
	privateA, publicA, err := X25519GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair A: %v", err)
	}

	privateB, publicB, err := X25519GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair B: %v", err)
	}

	// Perform DH key exchange both ways
	sharedA, err := X25519DH(privateA, publicB)
	if err != nil {
		t.Errorf("X25519DH() A->B error: %v", err)
		return
	}

	sharedB, err := X25519DH(privateB, publicA)
	if err != nil {
		t.Errorf("X25519DH() B->A error: %v", err)
		return
	}

	// Shared secrets should be equal
	if !bytes.Equal(sharedA, sharedB) {
		t.Errorf("X25519DH() shared secrets don't match")
	}

	if len(sharedA) != 32 {
		t.Errorf("X25519DH() shared secret length = %d, want 32", len(sharedA))
	}
}

// TestReverseBytes tests the reverseBytes utility function
func TestReverseBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "empty",
			input:    []byte{},
			expected: []byte{},
		},
		{
			name:     "single byte",
			input:    []byte{0x42},
			expected: []byte{0x42},
		},
		{
			name:     "two bytes",
			input:    []byte{0x12, 0x34},
			expected: []byte{0x34, 0x12},
		},
		{
			name:     "four bytes",
			input:    []byte{0x12, 0x34, 0x56, 0x78},
			expected: []byte{0x78, 0x56, 0x34, 0x12},
		},
		{
			name:     "32 bytes",
			input:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
			expected: []byte{0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reverseBytes(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("reverseBytes() = %x, want %x", result, tt.expected)
			}

			// Test that reversing twice gives original
			if len(tt.input) > 0 {
				twice := reverseBytes(result)
				if !bytes.Equal(twice, tt.input) {
					t.Errorf("reverseBytes() twice = %x, want %x", twice, tt.input)
				}
			}
		})
	}
}

// TestPrefixed tests the prefixed utility function
func TestPrefixed(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantPanic bool
	}{
		{
			name:  "empty",
			input: []byte{},
		},
		{
			name:  "short string",
			input: []byte("hello"),
		},
		{
			name:  "255 bytes",
			input: bytes.Repeat([]byte("A"), 255),
		},
		{
			name:  "256 bytes",
			input: bytes.Repeat([]byte("B"), 256),
		},
		{
			name:  "65535 bytes (max)",
			input: bytes.Repeat([]byte("C"), 65535),
		},
		{
			name:      "65536 bytes (too large)",
			input:     bytes.Repeat([]byte("D"), 65536),
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("prefixed() expected panic but didn't panic")
					}
				}()
			}

			result := prefixed(tt.input)

			if !tt.wantPanic {
				// Check that length prefix is correct
				expectedLen := len(tt.input)
				actualLen := int(result[0]) | (int(result[1]) << 8)

				if actualLen != expectedLen {
					t.Errorf("prefixed() length prefix = %d, want %d", actualLen, expectedLen)
				}

				// Check that data is correctly appended
				if !bytes.Equal(result[2:], tt.input) {
					t.Errorf("prefixed() data doesn't match input")
				}
			}
		})
	}
}

// TestPointMul8 tests the pointMul8 function
func TestPointMul8(t *testing.T) {
	tests := []struct {
		name  string
		point *Point4D
	}{
		{
			name:  "base point G",
			point: G,
		},
		{
			name: "random point",
			point: &Point4D{
				X: big.NewInt(123),
				Y: big.NewInt(456),
				Z: big.NewInt(1),
				T: big.NewInt(789),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pointMul8(tt.point)

			if result == nil {
				t.Errorf("pointMul8() returned nil")
				return
			}

			// Verify that result = 8 * point by computing manually
			expected := PointMul(big.NewInt(8), tt.point)

			if !PointEqual(result, expected) {
				t.Errorf("pointMul8() doesn't match PointMul(8, point)")
			}
		})
	}
}

// TestH tests the critical H function (hash to point)
func TestH(t *testing.T) {
	tests := []struct {
		name string
		uid  []byte
		did  []byte
		bid  []byte
		pin  []byte
	}{
		{
			name: "basic inputs",
			uid:  []byte("test-uid"),
			did:  []byte("test-did"),
			bid:  []byte("test-bid"),
			pin:  []byte("test-pin"),
		},
		{
			name: "empty inputs",
			uid:  []byte(""),
			did:  []byte(""),
			bid:  []byte(""),
			pin:  []byte(""),
		},
		{
			name: "unicode inputs",
			uid:  []byte("用户ID"),
			did:  []byte("设备ID"),
			bid:  []byte("文件.txt"),
			pin:  []byte("密码"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			point := H(tt.uid, tt.did, tt.bid, tt.pin)

			if point == nil {
				t.Errorf("H() returned nil")
				return
			}

			// Point should be valid
			if !IsValidPoint(point) {
				t.Errorf("H() returned invalid point")
			}

			// Same inputs should produce same point (deterministic)
			point2 := H(tt.uid, tt.did, tt.bid, tt.pin)
			if !PointEqual(point, point2) {
				t.Errorf("H() not deterministic")
			}

			// Different inputs should produce different points (with high probability)
			if len(tt.uid) > 0 {
				differentUID := make([]byte, len(tt.uid))
				copy(differentUID, tt.uid)
				differentUID[0] ^= 0x01

				point3 := H(differentUID, tt.did, tt.bid, tt.pin)
				if PointEqual(point, point3) {
					t.Errorf("H() collision with different UID")
				}
			}
		})
	}
}
