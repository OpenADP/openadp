package crypto

import (
	"bytes"
	"math/big"
	"testing"
)

func TestPointOperations(t *testing.T) {
	// Test point addition with zero point
	result := PointAdd(G, ZeroPoint)
	if !PointEqual(result, G) {
		t.Error("G + 0 should equal G")
	}

	// Test point doubling
	doubled := PointAdd(G, G)
	doubled2 := PointMul(big.NewInt(2), G)
	if !PointEqual(doubled, doubled2) {
		t.Error("2*G should equal G+G")
	}

	// Test scalar multiplication
	secret := big.NewInt(12345)
	point1 := PointMul(secret, G)
	point2 := PointMul(secret, G)
	if !PointEqual(point1, point2) {
		t.Error("Same scalar multiplication should give same result")
	}
}

func TestPointCompression(t *testing.T) {
	// Test compression/decompression round trip
	secret := big.NewInt(98765)
	point := PointMul(secret, G)

	compressed := PointCompress(point)
	if len(compressed) != 32 {
		t.Errorf("Compressed point should be 32 bytes, got %d", len(compressed))
	}

	decompressed, err := PointDecompress(compressed)
	if err != nil {
		t.Fatalf("Failed to decompress point: %v", err)
	}

	if !PointEqual(point, decompressed) {
		t.Error("Decompressed point should equal original")
	}
}

func TestSecretOperations(t *testing.T) {
	// Test secret expansion
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	_, err := SecretExpand(secret)
	if err != nil {
		t.Fatalf("Failed to expand secret: %v", err)
	}

	// Test secret to public key conversion
	publicKey, err := SecretToPublic(secret)
	if err != nil {
		t.Fatalf("Failed to convert secret to public: %v", err)
	}

	if len(publicKey) != 32 {
		t.Errorf("Public key should be 32 bytes, got %d", len(publicKey))
	}

	// Test that same secret gives same public key
	publicKey2, err := SecretToPublic(secret)
	if err != nil {
		t.Fatalf("Failed to convert secret to public (second time): %v", err)
	}

	if !bytes.Equal(publicKey, publicKey2) {
		t.Error("Same secret should give same public key")
	}
}

func TestX25519Operations(t *testing.T) {
	// Test keypair generation
	private1, public1, err := X25519GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	private2, public2, err := X25519GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate second keypair: %v", err)
	}

	// Test that different keypairs are different
	if bytes.Equal(private1, private2) {
		t.Error("Different keypairs should have different private keys")
	}
	if bytes.Equal(public1, public2) {
		t.Error("Different keypairs should have different public keys")
	}

	// Test Diffie-Hellman
	shared1, err := X25519DH(private1, public2)
	if err != nil {
		t.Fatalf("Failed to compute DH (1->2): %v", err)
	}

	shared2, err := X25519DH(private2, public1)
	if err != nil {
		t.Fatalf("Failed to compute DH (2->1): %v", err)
	}

	if !bytes.Equal(shared1, shared2) {
		t.Error("DH shared secrets should be equal")
	}
}

func TestHFunction(t *testing.T) {
	uid := []byte("test-uid")
	did := []byte("test-did")
	bid := []byte("test-bid")
	pin := []byte{0x12, 0x34}

	// Test that H function is deterministic
	point1 := H(uid, did, bid, pin)
	point2 := H(uid, did, bid, pin)

	if !PointEqual(point1, point2) {
		t.Error("H function should be deterministic")
	}

	// Test that different inputs give different outputs
	point3 := H([]byte("different-uid"), did, bid, pin)
	if PointEqual(point1, point3) {
		t.Error("Different inputs should give different outputs")
	}
}

func TestKeyDerivation(t *testing.T) {
	// Test key derivation
	secret := big.NewInt(54321)
	point := PointMul(secret, G)

	key1 := DeriveEncKey(point)
	key2 := DeriveEncKey(point)

	if len(key1) != 32 {
		t.Errorf("Derived key should be 32 bytes, got %d", len(key1))
	}

	if !bytes.Equal(key1, key2) {
		t.Error("Same point should derive same key")
	}

	// Test that different points give different keys
	point2 := PointMul(big.NewInt(12345), G)
	key3 := DeriveEncKey(point2)

	if bytes.Equal(key1, key3) {
		t.Error("Different points should derive different keys")
	}
}

func TestSha256Hash(t *testing.T) {
	data := []byte("test data")
	hash1 := Sha256Hash(data)
	hash2 := Sha256Hash(data)

	if len(hash1) != 32 {
		t.Errorf("SHA256 hash should be 32 bytes, got %d", len(hash1))
	}

	if !bytes.Equal(hash1, hash2) {
		t.Error("Same data should give same hash")
	}

	// Test different data gives different hash
	hash3 := Sha256Hash([]byte("different data"))
	if bytes.Equal(hash1, hash3) {
		t.Error("Different data should give different hash")
	}
}

func BenchmarkPointMul(b *testing.B) {
	secret := big.NewInt(12345)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		PointMul(secret, G)
	}
}

func BenchmarkPointCompress(b *testing.B) {
	point := PointMul(big.NewInt(12345), G)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		PointCompress(point)
	}
}

func BenchmarkPointDecompress(b *testing.B) {
	point := PointMul(big.NewInt(12345), G)
	compressed := PointCompress(point)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		PointDecompress(compressed)
	}
}
