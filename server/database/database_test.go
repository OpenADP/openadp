package database

import (
	"os"
	"testing"
	"time"
)

func TestNewDatabase(t *testing.T) {
	// Create temporary database file
	dbPath := "test_openadp.db"
	defer os.Remove(dbPath)

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	if db.GetPath() != dbPath {
		t.Errorf("Expected path %s, got %s", dbPath, db.GetPath())
	}
}

func TestInsertAndLookup(t *testing.T) {
	// Create temporary database file
	dbPath := "test_insert_lookup.db"
	defer os.Remove(dbPath)

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "test-user@example.com"
	did := "test-device"
	bid := "test-backup"
	authCode := "AUTH123456789"
	version := 1
	x := 2
	y := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	numGuesses := 0
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600 // 1 hour from now

	// Insert record
	err = db.Insert(uid, did, bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to insert record: %v", err)
	}

	// Lookup record
	record, err := db.Lookup(uid, did, bid)
	if err != nil {
		t.Fatalf("Failed to lookup record: %v", err)
	}

	if record == nil {
		t.Fatal("Record not found")
	}

	// Verify record contents
	if record.UID != uid {
		t.Errorf("Expected UID %s, got %s", uid, record.UID)
	}
	if record.DID != did {
		t.Errorf("Expected DID %s, got %s", did, record.DID)
	}
	if record.BID != bid {
		t.Errorf("Expected BID %s, got %s", bid, record.BID)
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
	for i, b := range y {
		if record.Y[i] != b {
			t.Errorf("Expected Y[%d] = %d, got %d", i, b, record.Y[i])
		}
	}
	if record.NumGuesses != numGuesses {
		t.Errorf("Expected NumGuesses %d, got %d", numGuesses, record.NumGuesses)
	}
	if record.MaxGuesses != maxGuesses {
		t.Errorf("Expected MaxGuesses %d, got %d", maxGuesses, record.MaxGuesses)
	}
	if record.Expiration != expiration {
		t.Errorf("Expected Expiration %d, got %d", expiration, record.Expiration)
	}
}

func TestLookupByAuthCode(t *testing.T) {
	// Create temporary database file
	dbPath := "test_auth_lookup.db"
	defer os.Remove(dbPath)

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "test-user@example.com"
	did := "test-device"
	bid := "test-backup"
	authCode := "AUTH123456789"
	version := 1
	x := 2
	y := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	numGuesses := 0
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600

	// Insert record
	err = db.Insert(uid, did, bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to insert record: %v", err)
	}

	// Lookup by auth code
	record, err := db.LookupByAuthCode(authCode, did, bid)
	if err != nil {
		t.Fatalf("Failed to lookup by auth code: %v", err)
	}

	if record == nil {
		t.Fatal("Record not found by auth code")
	}

	// Verify record contents
	if record.UID != uid {
		t.Errorf("Expected UID %s, got %s", uid, record.UID)
	}
	if record.AuthCode != authCode {
		t.Errorf("Expected AuthCode %s, got %s", authCode, record.AuthCode)
	}
}

func TestUpdateGuessCount(t *testing.T) {
	// Create temporary database file
	dbPath := "test_guess_count.db"
	defer os.Remove(dbPath)

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "test-user@example.com"
	did := "test-device"
	bid := "test-backup"
	authCode := "AUTH123456789"
	version := 1
	x := 2
	y := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	numGuesses := 0
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600

	// Insert record
	err = db.Insert(uid, did, bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to insert record: %v", err)
	}

	// Update guess count
	newGuessCount := 5
	err = db.UpdateGuessCount(uid, did, bid, newGuessCount)
	if err != nil {
		t.Fatalf("Failed to update guess count: %v", err)
	}

	// Verify update
	record, err := db.Lookup(uid, did, bid)
	if err != nil {
		t.Fatalf("Failed to lookup record: %v", err)
	}

	if record.NumGuesses != newGuessCount {
		t.Errorf("Expected NumGuesses %d, got %d", newGuessCount, record.NumGuesses)
	}
}

func TestListBackups(t *testing.T) {
	// Create temporary database file
	dbPath := "test_list_backups.db"
	defer os.Remove(dbPath)

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "test-user@example.com"
	authCode := "AUTH123456789"
	version := 1
	x := 2
	y := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	numGuesses := 0
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600

	// Insert multiple backups
	backups := []struct {
		did string
		bid string
	}{
		{"device1", "backup1"},
		{"device1", "backup2"},
		{"device2", "backup1"},
	}

	for _, backup := range backups {
		err = db.Insert(uid, backup.did, backup.bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
		if err != nil {
			t.Fatalf("Failed to insert backup %s/%s: %v", backup.did, backup.bid, err)
		}
	}

	// List backups
	backupList, err := db.ListBackups(uid)
	if err != nil {
		t.Fatalf("Failed to list backups: %v", err)
	}

	if len(backupList) != len(backups) {
		t.Errorf("Expected %d backups, got %d", len(backups), len(backupList))
	}

	// Verify backup contents
	for i, backup := range backupList {
		expectedBackup := backups[i]
		if backup.DID != expectedBackup.did {
			t.Errorf("Expected DID %s, got %s", expectedBackup.did, backup.DID)
		}
		if backup.BID != expectedBackup.bid {
			t.Errorf("Expected BID %s, got %s", expectedBackup.bid, backup.BID)
		}
	}
}

func TestServerConfig(t *testing.T) {
	// Create temporary database file
	dbPath := "test_server_config.db"
	defer os.Remove(dbPath)

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	key := "test_key"
	value := []byte("test_value_data")

	// Set config
	err = db.SetServerConfig(key, value)
	if err != nil {
		t.Fatalf("Failed to set server config: %v", err)
	}

	// Get config
	retrievedValue, err := db.GetServerConfig(key)
	if err != nil {
		t.Fatalf("Failed to get server config: %v", err)
	}

	if retrievedValue == nil {
		t.Fatal("Retrieved value is nil")
	}

	if len(retrievedValue) != len(value) {
		t.Errorf("Expected value length %d, got %d", len(value), len(retrievedValue))
	}

	for i, b := range value {
		if retrievedValue[i] != b {
			t.Errorf("Expected value[%d] = %d, got %d", i, b, retrievedValue[i])
		}
	}

	// Test non-existent key
	nonExistentValue, err := db.GetServerConfig("non_existent_key")
	if err != nil {
		t.Fatalf("Failed to get non-existent config: %v", err)
	}

	if nonExistentValue != nil {
		t.Error("Expected nil for non-existent key")
	}
}

func TestFindGuessNumber(t *testing.T) {
	// Create temporary database file
	dbPath := "test_find_guess.db"
	defer os.Remove(dbPath)

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "test-user@example.com"
	did := "test-device"
	bid := "test-backup"
	authCode := "AUTH123456789"
	version := 1
	x := 2
	y := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	numGuesses := 3
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600

	// Insert record
	err = db.Insert(uid, did, bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to insert record: %v", err)
	}

	// Find guess number
	foundGuesses, err := db.FindGuessNumber(uid, did, bid)
	if err != nil {
		t.Fatalf("Failed to find guess number: %v", err)
	}

	if foundGuesses != numGuesses {
		t.Errorf("Expected guess number %d, got %d", numGuesses, foundGuesses)
	}

	// Test non-existent record
	_, err = db.FindGuessNumber("non-existent", "non-existent", "non-existent")
	if err == nil {
		t.Error("Expected error for non-existent record")
	}
}

func TestValidateExpiration(t *testing.T) {
	// Test no expiration (0)
	err := ValidateExpiration(0)
	if err != nil {
		t.Errorf("Expected no error for expiration 0, got: %v", err)
	}

	// Test future expiration
	futureTime := time.Now().Unix() + 3600 // 1 hour from now
	err = ValidateExpiration(futureTime)
	if err != nil {
		t.Errorf("Expected no error for future expiration, got: %v", err)
	}

	// Test past expiration
	pastTime := time.Now().Unix() - 3600 // 1 hour ago
	err = ValidateExpiration(pastTime)
	if err == nil {
		t.Error("Expected error for past expiration")
	}
}

func TestReplaceOperation(t *testing.T) {
	// Create temporary database file
	dbPath := "test_replace.db"
	defer os.Remove(dbPath)

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "test-user@example.com"
	did := "test-device"
	bid := "test-backup"
	authCode := "AUTH123456789"
	version1 := 1
	version2 := 2
	x := 2
	y := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	numGuesses := 0
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600

	// Insert first version
	err = db.Insert(uid, did, bid, authCode, version1, x, y, numGuesses, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to insert first version: %v", err)
	}

	// Insert second version (should replace)
	err = db.Insert(uid, did, bid, authCode, version2, x, y, numGuesses, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to insert second version: %v", err)
	}

	// Verify replacement
	record, err := db.Lookup(uid, did, bid)
	if err != nil {
		t.Fatalf("Failed to lookup record: %v", err)
	}

	if record.Version != version2 {
		t.Errorf("Expected version %d, got %d", version2, record.Version)
	}
}
