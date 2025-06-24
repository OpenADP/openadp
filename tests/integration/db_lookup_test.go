package integration

import (
	"fmt"
	"os"
	"testing"

	"github.com/openadp/server/database"
)

func TestDatabaseLookup(t *testing.T) {
	fmt.Println("Testing database lookup format...")

	// Create temporary database file
	dbPath := "test_recover.db"
	defer func() {
		// Clean up
		os.Remove(dbPath)
	}()

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "test"
	did := "device"
	bid := "backup"
	authCode := "test_auth_code"
	version := 1
	x := 1
	y := make([]byte, 32)
	for i := range y {
		y[i] = 0x01 // Fill with 0x01 bytes
	}
	numGuesses := 0
	maxGuesses := 10
	expiration := int64(0)

	fmt.Println("Inserting test data...")
	err = db.Insert(uid, did, bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to insert data: %v", err)
	}

	fmt.Println("Looking up data...")
	result, err := db.Lookup(uid, did, bid)
	if err != nil {
		t.Fatalf("Failed to lookup data: %v", err)
	}

	if result == nil {
		t.Fatal("Lookup result is nil")
	}

	fmt.Printf("Lookup result: %+v\n", result)
	fmt.Printf("Result type: %T\n", result)

	// Verify the data
	if result.Version != version {
		t.Errorf("Expected version %d, got %d", version, result.Version)
	}
	if result.X != x {
		t.Errorf("Expected x %d, got %d", x, result.X)
	}
	if len(result.Y) != len(y) {
		t.Errorf("Expected Y length %d, got %d", len(y), len(result.Y))
	}
	for i, b := range result.Y {
		if b != y[i] {
			t.Errorf("Y data mismatch at index %d: expected %02x, got %02x", i, y[i], b)
			break
		}
	}
	if result.NumGuesses != numGuesses {
		t.Errorf("Expected NumGuesses %d, got %d", numGuesses, result.NumGuesses)
	}
	if result.MaxGuesses != maxGuesses {
		t.Errorf("Expected MaxGuesses %d, got %d", maxGuesses, result.MaxGuesses)
	}
	if result.Expiration != expiration {
		t.Errorf("Expected Expiration %d, got %d", expiration, result.Expiration)
	}

	fmt.Printf("Unpacked: version=%d, x=%d, y_type=%T, num_guesses=%d\n",
		result.Version, result.X, result.Y, result.NumGuesses)
	fmt.Printf("Y length: %d\n", len(result.Y))

	fmt.Println("✅ Database lookup test passed")
}

func TestDatabaseLookupByAuthCode(t *testing.T) {
	fmt.Println("Testing database lookup by auth code...")

	// Create temporary database file
	dbPath := "test_auth_lookup.db"
	defer func() {
		// Clean up
		os.Remove(dbPath)
	}()

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "test_user"
	did := "test_device"
	bid := "test_backup"
	authCode := "test_auth_code_12345"
	version := 1
	x := 2
	y := make([]byte, 32)
	for i := range y {
		y[i] = byte(i % 256) // Fill with incremental bytes
	}
	numGuesses := 0
	maxGuesses := 5
	expiration := int64(1234567890)

	fmt.Println("Inserting test data...")
	err = db.Insert(uid, did, bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to insert data: %v", err)
	}

	fmt.Println("Looking up data by auth code...")
	result, err := db.LookupByAuthCode(authCode, did, bid)
	if err != nil {
		t.Fatalf("Failed to lookup by auth code: %v", err)
	}

	if result == nil {
		t.Fatal("Lookup by auth code result is nil")
	}

	fmt.Printf("Auth code lookup result: %+v\n", result)

	// Verify the data matches
	if result.UID != uid {
		t.Errorf("Expected UID %s, got %s", uid, result.UID)
	}
	if result.Version != version {
		t.Errorf("Expected version %d, got %d", version, result.Version)
	}
	if result.X != x {
		t.Errorf("Expected x %d, got %d", x, result.X)
	}
	if len(result.Y) != len(y) {
		t.Errorf("Expected Y length %d, got %d", len(y), len(result.Y))
	}

	fmt.Println("✅ Database lookup by auth code test passed")
}

func TestDatabaseLookupEdgeCases(t *testing.T) {
	fmt.Println("Testing database lookup edge cases...")

	// Create temporary database file
	dbPath := "test_edge_cases.db"
	defer func() {
		// Clean up
		os.Remove(dbPath)
	}()

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test lookup of non-existent data
	result, err := db.Lookup("nonexistent", "device", "backup")
	if err != nil {
		t.Fatalf("Lookup of non-existent data should not error: %v", err)
	}
	if result != nil {
		t.Error("Expected nil result for non-existent data")
	}

	// Test lookup by auth code for non-existent data
	result, err = db.LookupByAuthCode("nonexistent_code", "device", "backup")
	if err != nil {
		t.Fatalf("Lookup by auth code of non-existent data should not error: %v", err)
	}
	if result != nil {
		t.Error("Expected nil result for non-existent auth code")
	}

	// Test with empty strings
	result, err = db.Lookup("", "", "")
	if err != nil {
		t.Fatalf("Lookup with empty strings should not error: %v", err)
	}
	if result != nil {
		t.Error("Expected nil result for empty string lookup")
	}

	fmt.Println("✅ Database lookup edge cases test passed")
}
