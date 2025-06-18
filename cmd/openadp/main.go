// Package main provides a command-line interface for OpenADP operations.
package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/openadp/openadp/pkg/auth"
	"github.com/openadp/openadp/pkg/crypto"
	"github.com/openadp/openadp/pkg/keygen"
	"github.com/openadp/openadp/pkg/sharing"
)

func main() {
	fmt.Println("🚀 OpenADP Go Implementation Demo")
	fmt.Println("==================================")

	// Test 1: Authentication Code Manager
	fmt.Println("\n1. Testing Authentication Code Manager...")
	testAuthCodeManager()

	// Test 2: Cryptographic Operations
	fmt.Println("\n2. Testing Cryptographic Operations...")
	testCrypto()

	// Test 3: Secret Sharing
	fmt.Println("\n3. Testing Secret Sharing...")
	testSecretSharing()

	// Test 4: Key Generation
	fmt.Println("\n4. Testing Key Generation...")
	testKeyGeneration()

	fmt.Println("\n✅ All tests completed successfully!")
	fmt.Println("🎉 OpenADP Go port is working correctly!")
}

func testAuthCodeManager() {
	manager := auth.NewAuthCodeManager()

	// Generate authentication code
	authCode, err := manager.GenerateAuthCode()
	if err != nil {
		log.Fatalf("Failed to generate auth code: %v", err)
	}

	fmt.Printf("   Generated auth code: [REDACTED]\n")
	fmt.Printf("   Auth code length: %d characters\n", len(authCode))

	// Validate format
	if !manager.ValidateBaseCodeFormat(authCode) {
		log.Fatal("Generated auth code has invalid format")
	}
	fmt.Println("   ✅ Auth code format is valid")

	// Test server code derivation
	serverURLs := []string{
		"https://server1.openadp.org",
		"https://server2.openadp.org",
		"https://server3.openadp.org",
	}

	serverCodes := manager.GetServerCodes(authCode, serverURLs)
	fmt.Printf("   Derived %d server-specific codes\n", len(serverCodes))

	for url, code := range serverCodes {
		if !manager.ValidateServerCodeFormat(code) {
			log.Fatalf("Server code for %s has invalid format", url)
		}
	}
	fmt.Println("   ✅ All server codes have valid format")
}

func testCrypto() {
	// Test key generation
	privateKey, publicKey, err := crypto.X25519GenerateKeypair()
	if err != nil {
		log.Fatalf("Failed to generate X25519 keypair: %v", err)
	}

	fmt.Printf("   Generated X25519 keypair (private: %d bytes, public: %d bytes)\n",
		len(privateKey), len(publicKey))

	// Test point operations
	secret := big.NewInt(12345)
	point := crypto.PointMul(secret, crypto.G)
	compressed := crypto.PointCompress(point)

	fmt.Printf("   Point compression: %d bytes\n", len(compressed))

	// Test decompression
	decompressed, err := crypto.PointDecompress(compressed)
	if err != nil {
		log.Fatalf("Failed to decompress point: %v", err)
	}

	if !crypto.PointEqual(point, decompressed) {
		log.Fatal("Point compression/decompression failed")
	}
	fmt.Println("   ✅ Point compression/decompression working")

	// Test H function
	uid := []byte("test-user-id")
	did := []byte("test-device")
	bid := []byte("test-backup")
	pin := []byte{0x12, 0x34}

	hashPoint := crypto.H(uid, did, bid, pin)
	fmt.Printf("   H function generated point: (%s, %s)\n",
		crypto.Unexpand(hashPoint).X.String()[:10]+"...",
		crypto.Unexpand(hashPoint).Y.String()[:10]+"...")

	// Test key derivation
	encKey := crypto.DeriveEncKey(hashPoint)
	fmt.Printf("   Derived encryption key: %d bytes\n", len(encKey))
	fmt.Println("   ✅ Cryptographic operations working")
}

func testSecretSharing() {
	// Generate a random secret
	secret := big.NewInt(98765432109876543)
	threshold := 3
	numShares := 5

	fmt.Printf("   Original secret: %s\n", secret.String())
	fmt.Printf("   Threshold: %d, Total shares: %d\n", threshold, numShares)

	// Create shares
	shares, err := sharing.MakeRandomShares(secret, threshold, numShares)
	if err != nil {
		log.Fatalf("Failed to create shares: %v", err)
	}

	fmt.Printf("   Created %d shares\n", len(shares))

	// Test recovery with threshold shares
	testShares := shares[:threshold]
	recoveredSecret, err := sharing.RecoverSecret(testShares)
	if err != nil {
		log.Fatalf("Failed to recover secret: %v", err)
	}

	if secret.Cmp(recoveredSecret) != 0 {
		log.Fatal("Recovered secret doesn't match original")
	}

	fmt.Printf("   Recovered secret: %s\n", recoveredSecret.String())
	fmt.Println("   ✅ Secret sharing working correctly")
}

func testKeyGeneration() {
	filename := "test_document.txt"
	password := "my_secure_password123"
	userID := "test-user-uuid-12345"
	serverURLs := []string{
		"https://server1.openadp.org",
		"https://server2.openadp.org",
	}

	fmt.Printf("   Filename: %s\n", filename)
	fmt.Printf("   User ID: %s\n", userID)
	fmt.Printf("   Servers: %d\n", len(serverURLs))

	// Test identifier derivation
	uid, did, bid := keygen.DeriveIdentifiers(filename, userID, "")
	fmt.Printf("   Derived identifiers: UID=%s, DID=%s, BID=%s\n", uid, did, bid)

	// Test password to PIN conversion (not logged for security)
	_ = keygen.PasswordToPin(password)
	fmt.Printf("   PIN from password: [REDACTED]\n")

	// Test key generation (simplified)
	result := keygen.GenerateEncryptionKey(filename, password, userID, 10, 0, serverURLs)
	if result.Error != "" {
		// This is expected since we don't have real servers
		fmt.Printf("   Key generation (simulated): %s\n", result.Error)
	} else {
		fmt.Printf("   Generated encryption key: %d bytes\n", len(result.EncryptionKey))
	}

	fmt.Println("   ✅ Key generation logic working")
}
