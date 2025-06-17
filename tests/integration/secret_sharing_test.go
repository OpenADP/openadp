package integration

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/openadp/openadp/pkg/client"
	"github.com/openadp/openadp/pkg/crypto"
	"github.com/openadp/openadp/pkg/sharing"
)

func TestActualSecretSharing(t *testing.T) {
	fmt.Println("Testing with actual secret sharing values...")

	// Generate the same values as in OpenADP key generation
	secret, err := rand.Int(rand.Reader, crypto.Q)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	shares, err := sharing.MakeRandomShares(secret, 2, 2)
	if err != nil {
		t.Fatalf("Failed to make shares: %v", err)
	}

	fmt.Printf("Secret: %s\n", secret.String())
	fmt.Printf("Shares: %v\n", shares)
	fmt.Println()

	// Test parameters
	uid := "test@example.com"
	did := "test_device"
	bid := "test_actual_shares"
	version := 1
	maxGuesses := 10
	expiration := int64(0)

	// Initialize client with local test servers
	fallbackServers := []string{
		"http://localhost:9200",
		"http://localhost:9201",
		"http://localhost:9202",
	}

	c, err := client.NewClient("", fallbackServers)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Skip("No live servers available - make sure local test servers are running on ports 9200, 9201, 9202")
	}

	fmt.Printf("Using %d live servers\n", liveCount)

	// Try to register each share
	for i, share := range shares {
		fmt.Printf("\n--- Registering Share %d ---\n", i+1)
		fmt.Printf("x: %d\n", share.X)
		fmt.Printf("y: %s\n", share.Y.String())
		fmt.Printf("y bits: %d\n", share.Y.BitLen())
		fmt.Printf("y string length: %d\n", len(share.Y.String()))

		// Test conversion
		yBytes := make([]byte, 32)
		share.Y.FillBytes(yBytes)
		fmt.Printf("✅ Local conversion successful: %d bytes\n", len(yBytes))

		// Try to register with remote servers
		yStr := share.Y.String()
		bidWithIndex := fmt.Sprintf("%s_%d", bid, i)
		success, errMsg := c.RegisterSecret(uid, did, bidWithIndex, version, share.X, yStr, maxGuesses, expiration)

		if success {
			fmt.Println("✅ Registration successful!")
		} else {
			t.Fatalf("Registration failed: %s", errMsg)
		}
	}

	fmt.Println("✅ All registrations successful!")
}

func TestRecoveryWorkflow(t *testing.T) {
	fmt.Println("Testing recovery workflow...")

	// Test parameters
	uid := "waywardgeek@beast"
	did := "beast"
	bid := "file://test_document.txt"

	fmt.Printf("Testing recovery for UID=%s, DID=%s, BID=%s\n", uid, did, bid)

	// Initialize client
	fallbackServers := []string{
		"http://localhost:9200",
		"http://localhost:9201",
		"http://localhost:9202",
	}

	c, err := client.NewClient("", fallbackServers)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	liveCount := c.GetLiveServerCount()
	if liveCount == 0 {
		t.Skip("No live servers available")
	}

	fmt.Printf("Using %d live servers\n", liveCount)

	// Check backups
	fmt.Println("\n--- Listing backups ---")
	backups, errMsg := c.ListBackups(uid)
	if errMsg != "" {
		t.Fatalf("List backups failed: %s", errMsg)
	}

	fmt.Printf("Found %d backups:\n", len(backups))
	for i, backup := range backups {
		fmt.Printf("  Backup %d: %v\n", i, backup)
		if len(backup) >= 4 {
			backupBid := backup[1].(string)
			numGuesses := int(backup[3].(float64))
			fmt.Printf("    BID: %s, num_guesses: %d\n", backupBid, numGuesses)
		}
	}

	// Find our backup
	guessNum := 0
	foundBackup := false
	for _, backup := range backups {
		if len(backup) > 1 {
			backupBid := backup[1].(string)
			if backupBid == bid {
				if len(backup) > 3 {
					guessNum = int(backup[3].(float64))
				}
				foundBackup = true
				fmt.Printf("✅ Found matching backup: %v\n", backup)
				fmt.Printf("    Current guess_num: %d\n", guessNum)
				break
			}
		}
	}

	if !foundBackup {
		t.Skipf("No backup found for BID: %s", bid)
	}

	// Test recovery from one server
	fmt.Println("\n--- Testing recovery from first server ---")

	// Create B point for recovery
	pin := []byte{0x12, 0x34} // Test PIN
	U := crypto.H([]byte(uid), []byte(did), []byte(bid), pin)
	r, err := rand.Int(rand.Reader, new(big.Int).Sub(crypto.Q, big.NewInt(1)))
	if err != nil {
		t.Fatalf("Failed to generate r: %v", err)
	}
	r.Add(r, big.NewInt(1))
	B := crypto.PointMul(r, U)

	BCompressed := crypto.PointCompress(B)
	result, errMsg := c.RecoverSecret(uid, did, bid, BCompressed, guessNum)

	if errMsg != "" {
		fmt.Printf("❌ Recovery failed: %s\n", errMsg)
	} else {
		fmt.Printf("✅ Recovery successful: %v\n", result)
	}
}

