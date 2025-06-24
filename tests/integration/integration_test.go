// integration_test.go - Comprehensive end-to-end integration test for OpenADP Go implementation
//
// This test demonstrates the complete OpenADP workflow:
// 1. Generate authentication codes and identifiers
// 2. Create secret shares using threshold cryptography
// 3. Start multiple OpenADP servers
// 4. Register shares with servers using JSON-RPC
// 5. Recover shares from servers
// 6. Reconstruct the original secret
// 7. Verify the encryption key derivation
//
// Run with: go test -v integration_test.go

package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/openadp/client/keygen"
	"github.com/openadp/server/auth"
)

func TestOpenADPIntegration(t *testing.T) {
	fmt.Println("🚀 OpenADP Integration Test")
	fmt.Println("===========================")

	// Step 0: Start test servers
	fmt.Println("\n🖥️  Step 0: Starting test servers...")

	serverManager, err := NewTestServerManager()
	if err != nil {
		t.Fatalf("Failed to create server manager: %v", err)
	}
	defer serverManager.Cleanup()

	// Start 3 test servers on ports 18081-18083
	testServers, err := serverManager.StartServers(18081, 3)
	if err != nil {
		t.Fatalf("Failed to start test servers: %v", err)
	}

	serverURLs := serverManager.GetServerURLs()
	fmt.Printf("   Started %d test servers: %v\n", len(testServers), serverURLs)

	// Step 1: Test authentication code generation
	fmt.Println("\n🔐 Step 1: Testing authentication code generation...")

	authManager := auth.NewAuthCodeManager()
	baseCode, err := authManager.GenerateAuthCode()
	if err != nil {
		t.Fatalf("Failed to generate base auth code: %v", err)
	}

	serverCodes := authManager.GetServerCodes(baseCode, serverURLs)
	fmt.Printf("   Base auth code: %s\n", baseCode)
	fmt.Printf("   Generated %d server-specific codes\n", len(serverCodes))

	// Step 2: Test identifier derivation
	fmt.Println("\n🆔 Step 2: Testing identifier derivation...")

	uid := "integration-test@openadp.org"
	did := "test-device-hostname"
	bid := "file://integration-test-backup.tar.gz"

	// Use current API signature: DeriveIdentifiers(filename, userID, hostname string) (string, string, string)
	derivedUID, derivedDID, derivedBID := keygen.DeriveIdentifiers(bid, uid, did)

	fmt.Printf("   Original UID: %s\n", uid)
	fmt.Printf("   Original DID: %s\n", did)
	fmt.Printf("   Original BID: %s\n", bid)
	fmt.Printf("   Derived UID: %s\n", derivedUID)
	fmt.Printf("   Derived DID: %s\n", derivedDID)
	fmt.Printf("   Derived BID: %s\n", derivedBID)

	// Verify identifiers are deterministic
	derivedUID2, derivedDID2, derivedBID2 := keygen.DeriveIdentifiers(bid, uid, did)
	if derivedUID != derivedUID2 || derivedDID != derivedDID2 || derivedBID != derivedBID2 {
		t.Fatalf("Identifier derivation is not deterministic!")
	}
	fmt.Println("   ✅ Identifier derivation is deterministic")

	// Step 3: Test encryption key generation
	fmt.Println("\n🔐 Step 3: Testing encryption key generation...")

	password := "test-password-123"
	// Use absolute timestamp for expiration (current time + 1 hour)
	expiration := int(time.Now().Unix()) + 3600

	// Get ServerInfo with public keys from each test server
	fmt.Println("   Getting server info and public keys from test servers...")
	serverInfos, err := serverManager.GetServerInfos()
	if err != nil {
		t.Fatalf("Failed to get server info from test servers: %v", err)
	}

	for _, serverInfo := range serverInfos {
		if serverInfo.PublicKey != "" {
			fmt.Printf("   ✅ Server %s: Got public key (Noise-NK enabled)\n", serverInfo.URL)
		} else {
			fmt.Printf("   ⚠️  Server %s: No public key (encryption disabled)\n", serverInfo.URL)
		}
	}

	keyResult := keygen.GenerateEncryptionKey(bid, password, uid, 10, expiration, serverInfos)
	if keyResult.Error != "" {
		t.Fatalf("Failed to generate encryption key: %s", keyResult.Error)
	}

	fmt.Printf("   Encryption key: %x\n", keyResult.EncryptionKey[:16])
	fmt.Printf("   Server URLs: %v\n", keyResult.ServerURLs)
	fmt.Printf("   Threshold: %d\n", keyResult.Threshold)
	fmt.Println("   ✅ Key generation completed successfully")

	// Step 4: Test key recovery using the same auth codes
	fmt.Println("\n🔓 Step 4: Testing encryption key recovery...")

	// Use the auth codes from the successful registration
	authCodes := keyResult.AuthCodes
	if authCodes == nil {
		t.Fatalf("No auth codes returned from key generation")
	}

	// Use the same server info with public keys for recovery
	recoveryResult := keygen.RecoverEncryptionKeyWithServerInfo(bid, password, uid, serverInfos, keyResult.Threshold, authCodes)
	if recoveryResult.Error != "" {
		t.Fatalf("Failed to recover encryption key: %s", recoveryResult.Error)
	}

	fmt.Printf("   Original key:  %x\n", keyResult.EncryptionKey[:16])
	fmt.Printf("   Recovered key: %x\n", recoveryResult.EncryptionKey[:16])

	// Verify the recovered key matches the original
	if len(keyResult.EncryptionKey) != len(recoveryResult.EncryptionKey) {
		t.Fatalf("Recovered key length doesn't match original")
	}
	for i := range keyResult.EncryptionKey {
		if keyResult.EncryptionKey[i] != recoveryResult.EncryptionKey[i] {
			t.Fatalf("Recovered key doesn't match original key")
		}
	}
	fmt.Println("   ✅ Key recovery successful - keys match!")

	// Step 5: Test password to PIN conversion
	fmt.Println("\n🔢 Step 5: Testing password to PIN conversion...")

	pin1 := keygen.PasswordToPin(password)
	pin2 := keygen.PasswordToPin(password)

	fmt.Printf("   Password: %s\n", password)
	fmt.Printf("   PIN: %x\n", pin1[:8])

	// Verify PIN conversion is deterministic
	if len(pin1) != len(pin2) {
		t.Fatalf("PIN conversion is not deterministic!")
	}
	for i := range pin1 {
		if pin1[i] != pin2[i] {
			t.Fatalf("PIN conversion is not deterministic!")
		}
	}
	fmt.Println("   ✅ PIN conversion is deterministic")

	fmt.Println("\n🎉 Integration test completed successfully!")
	fmt.Println("=====================================")
	fmt.Println("✅ All components working correctly:")
	fmt.Println("   • Authentication code generation")
	fmt.Println("   • Server-specific code derivation")
	fmt.Println("   • Identifier derivation (deterministic)")
	fmt.Println("   • Password to PIN conversion (deterministic)")
	fmt.Println("   • Encryption key generation")
	fmt.Println("   • Encryption key recovery (simulated)")
	fmt.Println("\n🚀 OpenADP Go core functionality is working!")
}
