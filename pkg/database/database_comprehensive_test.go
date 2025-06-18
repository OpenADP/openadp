package database

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDatabaseInitialization tests database initialization and table creation
func TestDatabaseInitialization(t *testing.T) {
	// Create temporary database file
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_init.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Database file should exist
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Database file was not created")
	}

	// Should be able to get path
	if db.GetPath() != dbPath {
		t.Errorf("Expected path %s, got %s", dbPath, db.GetPath())
	}
}

// TestInsertAndLookupEdgeCases tests insert and lookup with edge cases
func TestInsertAndLookupEdgeCases(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_edge_cases.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	testCases := []struct {
		name       string
		uid        string
		did        string
		bid        string
		authCode   string
		version    int
		x          int
		y          []byte
		numGuesses int
		maxGuesses int
		expiration int64
		shouldFail bool
	}{
		{
			name:       "normal_case",
			uid:        "user@example.com",
			did:        "device123",
			bid:        "backup456",
			authCode:   "AUTH123456789",
			version:    1,
			x:          2,
			y:          make([]byte, 32),
			numGuesses: 0,
			maxGuesses: 10,
			expiration: time.Now().Unix() + 3600,
			shouldFail: false,
		},
		{
			name:       "empty_uid",
			uid:        "",
			did:        "device123",
			bid:        "backup456",
			authCode:   "AUTH123456789",
			version:    1,
			x:          2,
			y:          make([]byte, 32),
			numGuesses: 0,
			maxGuesses: 10,
			expiration: time.Now().Unix() + 3600,
			shouldFail: false, // Database allows empty strings
		},
		{
			name:       "empty_did",
			uid:        "user@example.com",
			did:        "",
			bid:        "backup456",
			authCode:   "AUTH123456789",
			version:    1,
			x:          2,
			y:          make([]byte, 32),
			numGuesses: 0,
			maxGuesses: 10,
			expiration: time.Now().Unix() + 3600,
			shouldFail: false, // Database allows empty strings
		},
		{
			name:       "empty_bid",
			uid:        "user@example.com",
			did:        "device123",
			bid:        "",
			authCode:   "AUTH123456789",
			version:    1,
			x:          2,
			y:          make([]byte, 32),
			numGuesses: 0,
			maxGuesses: 10,
			expiration: time.Now().Unix() + 3600,
			shouldFail: false, // Database allows empty strings
		},
		{
			name:       "long_identifiers",
			uid:        "very_long_user_id_" + string(make([]byte, 100)),
			did:        "very_long_device_id_" + string(make([]byte, 100)),
			bid:        "very_long_backup_id_" + string(make([]byte, 100)),
			authCode:   "AUTH123456789",
			version:    1,
			x:          2,
			y:          make([]byte, 32),
			numGuesses: 0,
			maxGuesses: 10,
			expiration: time.Now().Unix() + 3600,
			shouldFail: false,
		},
		{
			name:       "zero_max_guesses",
			uid:        "user@example.com",
			did:        "device123",
			bid:        "backup456",
			authCode:   "AUTH123456789",
			version:    1,
			x:          2,
			y:          make([]byte, 32),
			numGuesses: 0,
			maxGuesses: 0,
			expiration: time.Now().Unix() + 3600,
			shouldFail: false, // This might be valid depending on implementation
		},
		{
			name:       "negative_version",
			uid:        "user@example.com",
			did:        "device123",
			bid:        "backup456",
			authCode:   "AUTH123456789",
			version:    -1,
			x:          2,
			y:          make([]byte, 32),
			numGuesses: 0,
			maxGuesses: 10,
			expiration: time.Now().Unix() + 3600,
			shouldFail: false, // Version might allow negative values
		},
		{
			name:       "large_y_data",
			uid:        "user@example.com",
			did:        "device123",
			bid:        "backup456",
			authCode:   "AUTH123456789",
			version:    1,
			x:          2,
			y:          make([]byte, 1024), // Large Y data
			numGuesses: 0,
			maxGuesses: 10,
			expiration: time.Now().Unix() + 3600,
			shouldFail: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill Y with test data
			for i := range tc.y {
				tc.y[i] = byte(i % 256)
			}

			err := db.Insert(tc.uid, tc.did, tc.bid, tc.authCode, tc.version, tc.x, tc.y, tc.numGuesses, tc.maxGuesses, tc.expiration)

			if tc.shouldFail {
				if err == nil {
					t.Errorf("Expected insert to fail for case %s", tc.name)
				}
				return
			}

			if err != nil {
				t.Fatalf("Insert failed for case %s: %v", tc.name, err)
			}

			// Try to lookup the record
			record, err := db.Lookup(tc.uid, tc.did, tc.bid)
			if err != nil {
				t.Fatalf("Lookup failed for case %s: %v", tc.name, err)
			}

			if record == nil {
				t.Fatalf("Record not found for case %s", tc.name)
			}

			// Verify record contents
			if record.UID != tc.uid {
				t.Errorf("UID mismatch for case %s: expected %s, got %s", tc.name, tc.uid, record.UID)
			}
			if record.DID != tc.did {
				t.Errorf("DID mismatch for case %s: expected %s, got %s", tc.name, tc.did, record.DID)
			}
			if record.BID != tc.bid {
				t.Errorf("BID mismatch for case %s: expected %s, got %s", tc.name, tc.bid, record.BID)
			}
		})
	}
}

// TestLookupNonexistent tests lookup of non-existent records
func TestLookupNonexistent(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_nonexistent.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Try to lookup non-existent record
	record, err := db.Lookup("nonexistent", "device", "backup")
	if err != nil {
		t.Fatalf("Lookup should not fail for non-existent record: %v", err)
	}

	if record != nil {
		t.Errorf("Expected nil record for non-existent lookup, got %v", record)
	}

	// Try auth code lookup for non-existent record
	record, err = db.LookupByAuthCode("nonexistent", "device", "backup")
	if err != nil {
		t.Fatalf("Auth code lookup should not fail for non-existent record: %v", err)
	}

	if record != nil {
		t.Errorf("Expected nil record for non-existent auth code lookup, got %v", record)
	}
}

// TestGuessCountManagement tests guess count tracking
func TestGuessCountManagement(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_guess_count.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Insert test record
	uid := "user@example.com"
	did := "device123"
	bid := "backup456"
	authCode := "AUTH123456789"
	version := 1
	x := 2
	y := make([]byte, 32)
	numGuesses := 0
	maxGuesses := 5
	expiration := time.Now().Unix() + 3600

	err = db.Insert(uid, did, bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to insert record: %v", err)
	}

	// Test guess count updates
	testCounts := []int{1, 3, 5, 10, 0} // Including edge cases

	for _, count := range testCounts {
		err = db.UpdateGuessCount(uid, did, bid, count)
		if err != nil {
			t.Fatalf("Failed to update guess count to %d: %v", count, err)
		}

		record, err := db.Lookup(uid, did, bid)
		if err != nil {
			t.Fatalf("Failed to lookup record after guess count update: %v", err)
		}

		if record.NumGuesses != count {
			t.Errorf("Expected guess count %d, got %d", count, record.NumGuesses)
		}
	}
}

// TestConcurrentAccess tests concurrent database access
func TestConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_concurrent.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create multiple goroutines that access the database
	// Use fewer goroutines and operations to reduce contention
	const numGoroutines = 3
	const numOperations = 2

	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines*numOperations)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()

			for j := 0; j < numOperations; j++ {
				uid := "user" + string(rune(goroutineID+'0'))
				did := "device" + string(rune(j+'0'))
				bid := "backup" + string(rune(j+'0'))
				authCode := "AUTH" + string(rune(goroutineID+'0')) + string(rune(j+'0'))
				version := 1
				x := 2
				y := make([]byte, 32)
				numGuesses := 0
				maxGuesses := 10
				expiration := time.Now().Unix() + 3600

				// Insert with retry logic
				err := retryDatabaseOperation(func() error {
					return db.Insert(uid, did, bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
				})
				if err != nil {
					errors <- err
					continue
				}

				// Lookup with retry logic
				var record *ShareRecord
				err = retryDatabaseOperation(func() error {
					var lookupErr error
					record, lookupErr = db.Lookup(uid, did, bid)
					return lookupErr
				})
				if err != nil {
					errors <- err
					continue
				}

				if record == nil {
					errors <- fmt.Errorf("record not found after insert")
					continue
				}

				// Update guess count with retry logic
				err = retryDatabaseOperation(func() error {
					return db.UpdateGuessCount(uid, did, bid, j+1)
				})
				if err != nil {
					errors <- err
					continue
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Check for errors
	close(errors)
	for err := range errors {
		if err != nil {
			t.Errorf("Concurrent access error: %v", err)
		}
	}
}

// retryDatabaseOperation retries a database operation with exponential backoff
func retryDatabaseOperation(operation func() error) error {
	maxRetries := 5
	baseDelay := 10 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		err := operation()
		if err == nil {
			return nil
		}

		// Check if it's a database busy error
		if strings.Contains(err.Error(), "database is locked") || strings.Contains(err.Error(), "SQLITE_BUSY") {
			if i < maxRetries-1 {
				// Wait with exponential backoff
				delay := baseDelay * time.Duration(1<<uint(i))
				time.Sleep(delay)
				continue
			}
		}

		// Return the error if it's not a busy error or we've exhausted retries
		return err
	}

	return fmt.Errorf("database operation failed after %d retries", maxRetries)
}

// TestDataPersistence tests that data persists across database reopens
func TestDataPersistence(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_persistence.db")

	// Create database and insert data
	{
		db, err := NewDatabase(dbPath)
		if err != nil {
			t.Fatalf("Failed to create database: %v", err)
		}

		uid := "user@example.com"
		did := "device123"
		bid := "backup456"
		authCode := "AUTH123456789"
		version := 1
		x := 2
		y := make([]byte, 32)
		for i := range y {
			y[i] = byte(i)
		}
		numGuesses := 3
		maxGuesses := 10
		expiration := time.Now().Unix() + 3600

		err = db.Insert(uid, did, bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
		if err != nil {
			t.Fatalf("Failed to insert record: %v", err)
		}

		db.Close()
	}

	// Reopen database and verify data
	{
		db, err := NewDatabase(dbPath)
		if err != nil {
			t.Fatalf("Failed to reopen database: %v", err)
		}
		defer db.Close()

		record, err := db.Lookup("user@example.com", "device123", "backup456")
		if err != nil {
			t.Fatalf("Failed to lookup record after reopen: %v", err)
		}

		if record == nil {
			t.Fatal("Record not found after database reopen")
		}

		// Verify all fields are preserved
		if record.UID != "user@example.com" {
			t.Errorf("UID not preserved: expected user@example.com, got %s", record.UID)
		}
		if record.NumGuesses != 3 {
			t.Errorf("NumGuesses not preserved: expected 3, got %d", record.NumGuesses)
		}
		if len(record.Y) != 32 {
			t.Errorf("Y length not preserved: expected 32, got %d", len(record.Y))
		}
		for i, b := range record.Y {
			if b != byte(i) {
				t.Errorf("Y[%d] not preserved: expected %d, got %d", i, i, b)
			}
		}
	}
}

// TestListBackupsComprehensive tests backup listing functionality
func TestListBackupsComprehensive(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_list_backups.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	uid := "user@example.com"
	did := "device123"

	// Insert multiple backups for the same user/device
	backupIDs := []string{"backup1", "backup2", "backup3"}
	for i, bid := range backupIDs {
		authCode := "AUTH" + bid
		version := i + 1
		x := i + 1
		y := make([]byte, 32)
		numGuesses := i
		maxGuesses := 10
		expiration := time.Now().Unix() + 3600

		err = db.Insert(uid, did, bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
		if err != nil {
			t.Fatalf("Failed to insert backup %s: %v", bid, err)
		}
	}

	// Insert backup for different user
	err = db.Insert("other@example.com", did, "other_backup", "AUTH_OTHER", 1, 1, make([]byte, 32), 0, 10, time.Now().Unix()+3600)
	if err != nil {
		t.Fatalf("Failed to insert other user backup: %v", err)
	}

	// List backups for our user
	backups, err := db.ListBackups(uid)
	if err != nil {
		t.Fatalf("Failed to list backups: %v", err)
	}

	if len(backups) != 3 {
		t.Errorf("Expected 3 backups, got %d", len(backups))
	}

	// Verify backup IDs are present
	foundBackups := make(map[string]bool)
	for _, backup := range backups {
		foundBackups[backup.BID] = true
	}

	for _, expectedBID := range backupIDs {
		if !foundBackups[expectedBID] {
			t.Errorf("Expected backup %s not found in list", expectedBID)
		}
	}

	// Test listing for non-existent user
	emptyBackups, err := db.ListBackups("nonexistent@example.com")
	if err != nil {
		t.Fatalf("Failed to list backups for non-existent user: %v", err)
	}

	if len(emptyBackups) != 0 {
		t.Errorf("Expected 0 backups for non-existent user, got %d", len(emptyBackups))
	}
}

// TestServerConfigOperations tests server configuration functionality
func TestServerConfigOperations(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_server_config.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test setting server configuration
	testKey := "test_key"
	testValue := []byte("test_value")

	err = db.SetServerConfig(testKey, testValue)
	if err != nil {
		t.Fatalf("Failed to set server config: %v", err)
	}

	// Test getting server configuration
	retrievedValue, err := db.GetServerConfig(testKey)
	if err != nil {
		t.Fatalf("Failed to get server config: %v", err)
	}

	if string(retrievedValue) != string(testValue) {
		t.Errorf("Server config value mismatch: expected %s, got %s", string(testValue), string(retrievedValue))
	}

	// Test getting non-existent config
	nonExistentValue, err := db.GetServerConfig("nonexistent_key")
	if err != nil {
		t.Fatalf("Failed to get non-existent server config: %v", err)
	}

	if len(nonExistentValue) != 0 {
		t.Errorf("Expected empty byte slice for non-existent config, got %v", nonExistentValue)
	}

	// Test updating existing config
	newValue := []byte("updated_value")
	err = db.SetServerConfig(testKey, newValue)
	if err != nil {
		t.Fatalf("Failed to update server config: %v", err)
	}

	updatedValue, err := db.GetServerConfig(testKey)
	if err != nil {
		t.Fatalf("Failed to get updated server config: %v", err)
	}

	if string(updatedValue) != string(newValue) {
		t.Errorf("Updated server config value mismatch: expected %s, got %s", string(newValue), string(updatedValue))
	}
}

// TestLargeDataHandling tests handling of large data
func TestLargeDataHandling(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_large_data.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	uid := "user@example.com"
	did := "device123"
	bid := "backup456"
	authCode := "AUTH123456789"
	version := 1
	x := 2
	numGuesses := 0
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600

	// Test with various Y data sizes
	testSizes := []int{0, 1, 32, 64, 256, 1024}

	for _, size := range testSizes {
		t.Run("y_size_"+string(rune(size+'0')), func(t *testing.T) {
			testBID := bid + "_size_" + string(rune(size+'0'))
			y := make([]byte, size)

			// Fill with test pattern
			for i := range y {
				y[i] = byte(i % 256)
			}

			err := db.Insert(uid, did, testBID, authCode, version, x, y, numGuesses, maxGuesses, expiration)
			if err != nil {
				t.Fatalf("Failed to insert record with Y size %d: %v", size, err)
			}

			record, err := db.Lookup(uid, did, testBID)
			if err != nil {
				t.Fatalf("Failed to lookup record with Y size %d: %v", size, err)
			}

			if record == nil {
				t.Fatalf("Record not found for Y size %d", size)
			}

			if len(record.Y) != size {
				t.Errorf("Y size mismatch: expected %d, got %d", size, len(record.Y))
			}

			// Verify data integrity
			for i, b := range record.Y {
				expected := byte(i % 256)
				if b != expected {
					t.Errorf("Y[%d] data corruption: expected %d, got %d", i, expected, b)
					break
				}
			}
		})
	}
}

// TestErrorConditions tests various error conditions
func TestErrorConditions(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_errors.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test update on non-existent record
	err = db.UpdateGuessCount("nonexistent", "device", "backup", 5)
	if err == nil {
		t.Errorf("Expected error when updating non-existent record")
	}

	// Note: Replace method doesn't exist in the database interface
	// This is expected behavior - records are updated via Insert with REPLACE INTO
}

// TestDatabaseCleanupAndClose tests proper database cleanup
func TestDatabaseCleanupAndClose(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_cleanup.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Insert some data
	err = db.Insert("user", "device", "backup", "auth", 1, 1, make([]byte, 32), 0, 10, time.Now().Unix()+3600)
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	// Close database
	err = db.Close()
	if err != nil {
		t.Errorf("Failed to close database: %v", err)
	}

	// Verify file still exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Database file was deleted on close")
	}

	// Multiple closes should not cause errors
	err = db.Close()
	if err != nil {
		t.Errorf("Multiple close calls should not error: %v", err)
	}
}
