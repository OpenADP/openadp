package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/openadp/common/crypto"
	"github.com/openadp/server/database"
)

// FuzzRegisterInputs fuzzes the RegisterSecret input validation
func FuzzRegisterInputs(f *testing.F) {
	// Seed with some valid and invalid inputs
	f.Add("user", "device", "backup", 1, []byte{1, 2, 3, 4}, 10, int64(1234567890))
	f.Add("", "", "", 0, []byte{}, 0, int64(0))
	f.Add("verylonguid", "verylongdid", "verylongbid", 999, bytes.Repeat([]byte{0xFF}, 100), 999, int64(2000000000))

	f.Fuzz(func(t *testing.T, uid, did, bid string, x int, y []byte, maxGuesses int, expiration int64) {
		// Fuzz ValidateRegisterInputs - should not panic
		err := ValidateRegisterInputs(uid, did, bid, x, y, maxGuesses, expiration)

		// Check that extremely long strings are rejected
		if len(uid) > MaxIdentifierLength && err == nil {
			t.Errorf("Expected error for UID length %d > %d", len(uid), MaxIdentifierLength)
		}
		if len(did) > MaxIdentifierLength && err == nil {
			t.Errorf("Expected error for DID length %d > %d", len(did), MaxIdentifierLength)
		}
		if len(bid) > MaxIdentifierLength && err == nil {
			t.Errorf("Expected error for BID length %d > %d", len(bid), MaxIdentifierLength)
		}

		// Check that too many shares are rejected
		if x > MaxShares && err == nil {
			t.Errorf("Expected error for X %d > %d", x, MaxShares)
		}

		// Check that oversized Y coordinates are rejected
		if len(y) > MaxYSize && err == nil {
			t.Errorf("Expected error for Y size %d > %d", len(y), MaxYSize)
		}

		// Check that too many guesses are rejected
		if maxGuesses > MaxGuesses && err == nil {
			t.Errorf("Expected error for maxGuesses %d > %d", maxGuesses, MaxGuesses)
		}
	})
}

// FuzzRecoverInputs fuzzes the RecoverSecret input validation
func FuzzRecoverInputs(f *testing.F) {
	// Seed with valid and edge case inputs
	f.Add("user", "device", "backup", int64(123), int64(456))
	f.Add("", "", "", int64(0), int64(0))
	f.Add("extremelyverylonguidthatexceedslimits", "device", "backup", int64(-1), int64(-1))

	f.Fuzz(func(t *testing.T, uid, did, bid string, x, y int64) {
		// Create point from fuzzed inputs
		point := &crypto.Point2D{
			X: big.NewInt(x),
			Y: big.NewInt(y),
		}

		// Fuzz ValidateRecoverInputs - should not panic
		err := ValidateRecoverInputs(uid, did, bid, point)

		// Check constraints
		if len(uid) > MaxIdentifierLength && err == nil {
			t.Errorf("Expected error for UID length %d > %d", len(uid), MaxIdentifierLength)
		}
		if len(did) > MaxIdentifierLength && err == nil {
			t.Errorf("Expected error for DID length %d > %d", len(did), MaxIdentifierLength)
		}
		if len(bid) > MaxIdentifierLength && err == nil {
			t.Errorf("Expected error for BID length %d > %d", len(bid), MaxIdentifierLength)
		}
	})
}

// FuzzRegisterSecretE2E fuzzes the complete RegisterSecret flow
func FuzzRegisterSecretE2E(f *testing.F) {
	// Seed with realistic data
	f.Add("user@example.com", "device-123", "backup-456", "AUTH-CODE-789", 1, 2,
		[]byte{0x01, 0x02, 0x03, 0x04}, 5, int64(2000000000))

	f.Fuzz(func(t *testing.T, uid, did, bid, authCode string, version, x int,
		y []byte, maxGuesses int, expiration int64) {

		// Create temporary database for each fuzz iteration
		dbPath := fmt.Sprintf("fuzz_test_%d.db", rand.Int())
		defer os.Remove(dbPath)

		db, err := database.NewDatabase(dbPath)
		if err != nil {
			t.Skip("Failed to create database") // Skip rather than fail on infrastructure issues
		}
		defer db.Close()

		// Call RegisterSecret - should not panic
		err = RegisterSecret(db, uid, did, bid, authCode, version, x, y, maxGuesses, expiration)

		// If registration succeeded, verify we can look it up
		if err == nil {
			record, lookupErr := db.Lookup(uid, did, bid)
			if lookupErr != nil {
				t.Errorf("Failed to lookup after successful registration: %v", lookupErr)
			}
			if record == nil {
				t.Error("Record is nil after successful registration")
			} else if record.Version != version {
				t.Errorf("Version mismatch: expected %d, got %d", version, record.Version)
			}
		}
	})
}

// FuzzRecoverSecretE2E fuzzes the complete RecoverSecret flow
func FuzzRecoverSecretE2E(f *testing.F) {
	f.Add("user@example.com", "device-123", "backup-456", int64(100), int64(200), 0)

	f.Fuzz(func(t *testing.T, uid, did, bid string, pointX, pointY int64, guessNum int) {
		// Create temporary database
		dbPath := fmt.Sprintf("fuzz_recover_%d.db", rand.Int())
		defer os.Remove(dbPath)

		db, err := database.NewDatabase(dbPath)
		if err != nil {
			t.Skip("Failed to create database")
		}
		defer db.Close()

		// First register a valid secret to recover
		validY := make([]byte, 16) // Valid size
		for i := range validY {
			validY[i] = byte(i + 1)
		}

		err = RegisterSecret(db, uid, did, bid, "AUTH123", 1, 2, validY, 10,
			time.Now().Unix()+3600)
		if err != nil {
			t.Skip("Failed to register secret for fuzz test")
		}

		// Create point from fuzzed data
		b := &crypto.Point2D{
			X: big.NewInt(pointX),
			Y: big.NewInt(pointY),
		}

		// Attempt recovery - should not panic
		response, err := RecoverSecret(db, uid, did, bid, b, guessNum)

		// Basic sanity checks on successful responses
		if err == nil && response != nil {
			if response.X <= 0 {
				t.Error("Response X should be positive")
			}
			if response.SiB == nil {
				t.Error("Response SiB should not be nil")
			}
			if response.NumGuesses < 0 {
				t.Error("NumGuesses should not be negative")
			}
		}
	})
}

// FuzzPointValid fuzzes the pointValid function
func FuzzPointValid(f *testing.F) {
	f.Add(int64(0), int64(0))
	f.Add(int64(1), int64(1))
	f.Add(int64(-1), int64(-1))

	f.Fuzz(func(t *testing.T, x, y int64) {
		// Test nil point
		if pointValid(nil) {
			t.Error("pointValid should return false for nil point")
		}

		// Test point with nil coordinates
		nilXPoint := &crypto.Point2D{X: nil, Y: big.NewInt(y)}
		if pointValid(nilXPoint) {
			t.Error("pointValid should return false for point with nil X")
		}

		nilYPoint := &crypto.Point2D{X: big.NewInt(x), Y: nil}
		if pointValid(nilYPoint) {
			t.Error("pointValid should return false for point with nil Y")
		}

		// Test valid point
		validPoint := &crypto.Point2D{X: big.NewInt(x), Y: big.NewInt(y)}
		if !pointValid(validPoint) {
			t.Error("pointValid should return true for valid point")
		}
	})
}

// FuzzServerInfo fuzzes the GetServerInfo function
func FuzzServerInfo(f *testing.F) {
	f.Add("1.0.0", []byte{0x01, 0x02, 0x03})
	f.Add("", []byte{})
	f.Add("v2.1.0-beta+build123", bytes.Repeat([]byte{0xFF}, 1000))

	f.Fuzz(func(t *testing.T, version string, noiseKey []byte) {
		// GetServerInfo should not panic with any inputs
		monitoring := NewMonitoringTracker()
		info := GetServerInfo(version, noiseKey, monitoring)

		if info == nil {
			t.Error("GetServerInfo should not return nil")
		}

		if info.Version != version {
			t.Errorf("Version mismatch: expected %s, got %s", version, info.Version)
		}

		// Capabilities should always be present
		if info.Capabilities == nil {
			t.Error("Capabilities should not be nil")
		}
	})
}

// FuzzEcho fuzzes the Echo function
func FuzzEcho(f *testing.F) {
	f.Add("hello world")
	f.Add("")
	f.Add(string(bytes.Repeat([]byte("A"), 10000)))

	f.Fuzz(func(t *testing.T, message string) {
		// Echo should not panic and should return the same message
		result := Echo(message)
		if result != message {
			t.Errorf("Echo mismatch: expected %q, got %q", message, result)
		}
	})
}

// FuzzListBackups fuzzes the ListBackups function
func FuzzListBackups(f *testing.F) {
	f.Add("user@example.com")
	f.Add("")
	f.Add(string(bytes.Repeat([]byte("x"), MaxIdentifierLength+100)))

	f.Fuzz(func(t *testing.T, uid string) {
		// Create temporary database
		dbPath := fmt.Sprintf("fuzz_list_%d.db", rand.Int())
		defer os.Remove(dbPath)

		db, err := database.NewDatabase(dbPath)
		if err != nil {
			t.Skip("Failed to create database")
		}
		defer db.Close()

		// ListBackups should not panic
		backups, err := ListBackups(db, uid)

		// Should return empty list for non-existent user, not error
		if err == nil && backups == nil {
			t.Error("ListBackups should return empty slice, not nil")
		}
	})
}

// FuzzJSONSerialization tests JSON serialization/deserialization of server types
func FuzzJSONSerialization(f *testing.F) {
	f.Add("user", "device", "backup", "auth", 1, 2, 5, int64(1234567890))

	f.Fuzz(func(t *testing.T, uid, did, bid, authCode string, version, x, maxGuesses int, expiration int64) {
		// Test RegisterSecretRequest JSON handling
		req := RegisterSecretRequest{
			UID:        uid,
			DID:        did,
			BID:        bid,
			AuthCode:   authCode,
			Version:    version,
			X:          x,
			Y:          "dGVzdA==", // base64 "test"
			MaxGuesses: maxGuesses,
			Expiration: expiration,
		}

		// Serialize to JSON
		jsonData, err := json.Marshal(req)
		if err != nil {
			t.Errorf("Failed to marshal RegisterSecretRequest: %v", err)
		}

		// Deserialize from JSON
		var decoded RegisterSecretRequest
		err = json.Unmarshal(jsonData, &decoded)
		if err != nil {
			t.Errorf("Failed to unmarshal RegisterSecretRequest: %v", err)
		}

		// Verify round-trip
		if decoded.UID != req.UID {
			t.Errorf("UID mismatch after JSON round-trip: %s != %s", decoded.UID, req.UID)
		}
	})
}

// FuzzConcurrentAccess tests concurrent access patterns
func FuzzConcurrentAccess(f *testing.F) {
	f.Add(5) // number of concurrent operations

	f.Fuzz(func(t *testing.T, numOps int) {
		if numOps <= 0 || numOps > 100 {
			t.Skip("Invalid number of operations")
		}

		// Create temporary database
		dbPath := fmt.Sprintf("fuzz_concurrent_%d.db", rand.Int())
		defer os.Remove(dbPath)

		db, err := database.NewDatabase(dbPath)
		if err != nil {
			t.Skip("Failed to create database")
		}
		defer db.Close()

		// Channel to collect errors
		errChan := make(chan error, numOps)

		// Launch concurrent operations
		for i := 0; i < numOps; i++ {
			go func(id int) {
				uid := fmt.Sprintf("user-%d", id)
				did := fmt.Sprintf("device-%d", id)
				bid := fmt.Sprintf("backup-%d", id)

				// Register a secret
				y := make([]byte, 8)
				for j := range y {
					y[j] = byte(id + j)
				}

				err := RegisterSecret(db, uid, did, bid, "AUTH", 1, id+1, y, 10,
					time.Now().Unix()+3600)
				errChan <- err
			}(i)
		}

		// Collect results
		errorCount := 0
		for i := 0; i < numOps; i++ {
			if err := <-errChan; err != nil {
				errorCount++
			}
		}

		// Some errors are expected due to race conditions, but not all should fail
		if errorCount == numOps {
			t.Error("All concurrent operations failed - possible deadlock or severe issue")
		}
	})
}
