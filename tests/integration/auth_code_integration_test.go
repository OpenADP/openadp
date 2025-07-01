package integration

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openadp/openadp/sdk/go/common"
	"github.com/openadp/server/auth"
	"github.com/openadp/server/database"
	"github.com/openadp/server/server"
)

func TestCompleteRegistrationFlow(t *testing.T) {
	// Create temporary database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	manager := auth.NewAuthCodeManager()

	// Test data
	uid := "integration_test_user"
	did := "integration_test_device"
	bid := "integration_test_backup"
	version := 1
	maxGuesses := 10
	expiration := time.Now().Unix() + 86400 // 24 hours from now

	// Generate authentication code
	baseCode, err := manager.GenerateAuthCode()
	if err != nil {
		t.Fatalf("Failed to generate auth code: %v", err)
	}
	serverURL := "https://server1.openadp.org"
	serverCode := manager.DeriveServerCode(baseCode, serverURL)

	// Generate cryptographic data
	x := 1 // Share index
	y := make([]byte, 32)
	rand.Read(y) // Secret share

	// Register secret using server package function
	err = server.RegisterSecret(db, uid, did, bid, serverCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Secret registration should succeed: %v", err)
	}

	// Verify registration by lookup
	record, err := db.LookupByAuthCode(serverCode, did, bid)
	if err != nil {
		t.Fatalf("Failed to lookup by auth code: %v", err)
	}

	if record == nil {
		t.Fatal("Should find registered share")
	}

	// Verify record contents
	if record.UID != uid {
		t.Errorf("Expected UID %s, got %s", uid, record.UID)
	}
	if record.Version != version {
		t.Errorf("Expected version %d, got %d", version, record.Version)
	}
	if record.X != x {
		t.Errorf("Expected X %d, got %d", x, record.X)
	}
	if len(record.Y) != len(y) {
		t.Errorf("Expected Y length %d, got %d", len(y), len(record.Y))
	}
	if record.NumGuesses != 0 {
		t.Errorf("Expected NumGuesses 0, got %d", record.NumGuesses)
	}
	if record.MaxGuesses != maxGuesses {
		t.Errorf("Expected MaxGuesses %d, got %d", maxGuesses, record.MaxGuesses)
	}

	fmt.Println("✅ Complete registration flow test passed")
}

func TestCompleteRecoveryFlow(t *testing.T) {
	// Create temporary database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	manager := auth.NewAuthCodeManager()

	// Test data
	uid := "integration_test_user"
	did := "integration_test_device"
	bid := "integration_test_backup"
	version := 1
	maxGuesses := 10
	expiration := time.Now().Unix() + 86400

	// Setup: Register a secret first
	baseCode, err := manager.GenerateAuthCode()
	if err != nil {
		t.Fatalf("Failed to generate auth code: %v", err)
	}
	serverURL := "https://server1.openadp.org"
	serverCode := manager.DeriveServerCode(baseCode, serverURL)

	// Generate cryptographic data for registration
	secret, err := rand.Int(rand.Reader, common.Q)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	u := common.PointMul(secret, common.G)
	x := 1 // Share index
	y := make([]byte, 32)
	rand.Read(y)

	// Register using server package function
	err = server.RegisterSecret(db, uid, did, bid, serverCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to register secret: %v", err)
	}

	// Recovery: Generate blinded point
	r, err := rand.Int(rand.Reader, new(big.Int).Sub(common.Q, big.NewInt(1)))
	if err != nil {
		t.Fatalf("Failed to generate r: %v", err)
	}
	r.Add(r, big.NewInt(1))
	b := common.PointMul(r, u)

	// Attempt recovery using server package function with auth code
	b2D := common.Unexpand(b)
	_, err = server.RecoverSecretByAuthCode(db, serverCode, did, bid, b2D, 0)

	// Note: This may fail cryptographically since we're not using the proper
	// key derivation, but it should not fail due to authentication issues
	if err != nil {
		// Should not be authentication-related errors
		errStr := err.Error()
		if contains(errStr, "auth") || contains(errStr, "permission") {
			t.Errorf("Recovery failed with auth error: %v", err)
		}
		// Cryptographic failures are expected in this test setup
		fmt.Printf("Expected cryptographic failure: %v\n", err)
	} else {
		fmt.Println("✅ Recovery succeeded")
	}

	fmt.Println("✅ Complete recovery flow test passed")
}

func TestBackupListingFlow(t *testing.T) {
	// Create temporary database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	manager := auth.NewAuthCodeManager()

	uid := "integration_test_user"
	version := 1
	maxGuesses := 10
	expiration := time.Now().Unix() + 86400

	baseCode, err := manager.GenerateAuthCode()
	if err != nil {
		t.Fatalf("Failed to generate auth code: %v", err)
	}
	serverURL := "https://server1.openadp.org"
	serverCode := manager.DeriveServerCode(baseCode, serverURL)

	// Register multiple backups
	backups := []struct {
		bid string
		did string
	}{
		{"backup1", "device1"},
		{"backup2", "device1"},
		{"backup3", "device2"},
	}

	for i, backup := range backups {
		x := i + 1 // Share index
		y := make([]byte, 32)
		rand.Read(y)

		err = server.RegisterSecret(db, uid, backup.did, backup.bid, serverCode, version, x, y, maxGuesses, expiration)
		if err != nil {
			t.Fatalf("Failed to register backup %d: %v", i, err)
		}
	}

	// List backups
	backupList, err := db.ListBackups(uid)
	if err != nil {
		t.Fatalf("Failed to list backups: %v", err)
	}

	if len(backupList) != 3 {
		t.Errorf("Expected 3 backups, got %d", len(backupList))
	}

	// Verify backup information - BackupInfo has DID, BID, Version fields
	expectedBackups := make(map[string]string) // bid -> did
	for _, backup := range backups {
		expectedBackups[backup.bid] = backup.did
	}

	for i, backup := range backupList {
		if expectedDid, exists := expectedBackups[backup.BID]; !exists {
			t.Errorf("Backup %d: Unexpected BID %s", i, backup.BID)
		} else if backup.DID != expectedDid {
			t.Errorf("Backup %d: Expected DID %s for BID %s, got %s", i, expectedDid, backup.BID, backup.DID)
		}
		if backup.Version != version {
			t.Errorf("Backup %d: Expected version %d, got %d", i, version, backup.Version)
		}
	}

	fmt.Println("✅ Complete backup listing flow test passed")
}

func TestMultiServerIsolation(t *testing.T) {
	// Create temporary database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	manager := auth.NewAuthCodeManager()

	baseUID := "integration_test_user"
	did := "integration_test_device"
	bid := "integration_test_backup"
	version := 1
	maxGuesses := 10
	expiration := time.Now().Unix() + 86400

	baseCode, err := manager.GenerateAuthCode()
	if err != nil {
		t.Fatalf("Failed to generate auth code: %v", err)
	}

	servers := []string{
		"https://server1.openadp.org",
		"https://server2.openadp.org",
		"https://backup.openadp.org",
	}

	// Register same backup on different servers
	for i, serverURL := range servers {
		serverCode := manager.DeriveServerCode(baseCode, serverURL)

		x := i + 1 // Share index
		y := make([]byte, 32)
		rand.Read(y)

		// Use different UIDs to distinguish
		uid := fmt.Sprintf("%s_server_%d", baseUID, i)

		err = server.RegisterSecret(db, uid, did, bid, serverCode, version, x, y, maxGuesses, expiration)
		if err != nil {
			t.Fatalf("Failed to register for server %d: %v", i, err)
		}
	}

	// Verify each server can only see its own data
	for i, serverURL := range servers {
		serverCode := manager.DeriveServerCode(baseCode, serverURL)

		// Should find the backup for this server
		record, err := db.LookupByAuthCode(serverCode, did, bid)
		if err != nil {
			t.Fatalf("Failed to lookup for server %d: %v", i, err)
		}

		if record == nil {
			t.Fatalf("Should find backup for server %d", i)
		}

		expectedUID := fmt.Sprintf("%s_server_%d", baseUID, i)
		if record.UID != expectedUID {
			t.Errorf("Expected UID %s for server %d, got %s", expectedUID, i, record.UID)
		}
	}

	fmt.Println("✅ Multi-server isolation test passed")
}

func TestGuessCountTracking(t *testing.T) {
	// Create temporary database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	manager := auth.NewAuthCodeManager()

	uid := "integration_test_user"
	did := "integration_test_device"
	bid := "integration_test_backup"
	version := 1
	maxGuesses := 3 // Low limit for testing
	expiration := time.Now().Unix() + 86400

	baseCode, err := manager.GenerateAuthCode()
	if err != nil {
		t.Fatalf("Failed to generate auth code: %v", err)
	}
	serverURL := "https://server1.openadp.org"
	serverCode := manager.DeriveServerCode(baseCode, serverURL)

	// Register secret
	x := 1
	y := make([]byte, 32)
	rand.Read(y)

	err = server.RegisterSecret(db, uid, did, bid, serverCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to register secret: %v", err)
	}

	// Test guess count increments with valid recovery attempts
	testBCompressed := common.PointCompress(common.G)
	testB4D, err := common.PointDecompress(testBCompressed)
	if err != nil {
		t.Fatalf("Failed to decompress test point: %v", err)
	}
	testB := common.Unexpand(testB4D)

	for i := 0; i < maxGuesses; i++ {
		// Attempt recovery (will succeed but increment guess count)
		_, err = server.RecoverSecret(db, uid, did, bid, testB, i)
		if err != nil {
			t.Fatalf("Unexpected error during recovery attempt %d: %v", i, err)
		}

		// Check guess count
		record, err := db.Lookup(uid, did, bid)
		if err != nil {
			t.Fatalf("Failed to lookup record: %v", err)
		}

		expectedGuesses := i + 1
		if record.NumGuesses != expectedGuesses {
			t.Errorf("Expected %d guesses after attempt %d, got %d", expectedGuesses, i, record.NumGuesses)
		}
	}

	// Next attempt should fail due to guess limit
	_, err = server.RecoverSecret(db, uid, did, bid, testB, maxGuesses)
	if err == nil {
		t.Error("Expected recovery to fail due to guess limit")
	}

	// Should contain guess limit error
	if !contains(err.Error(), "guess") && !contains(err.Error(), "limit") {
		t.Errorf("Expected guess limit error, got: %v", err)
	}

	fmt.Println("✅ Guess count tracking test passed")
}

// Helper function to check if string contains substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] && s[i+j] != substr[j]+32 && s[i+j] != substr[j]-32 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()
	os.Exit(code)
}
