package server

import (
	"math/big"
	"os"
	"testing"
	"time"

	crypto "github.com/openadp/ocrypt/common"
	"github.com/openadp/server/database"
)

func TestValidateRegisterInputs(t *testing.T) {
	// Valid inputs
	err := ValidateRegisterInputs("user", "device", "backup", 2, make([]byte, 32), 10, time.Now().Unix()+3600)
	if err != nil {
		t.Errorf("Expected no error for valid inputs, got: %v", err)
	}

	// UID too long
	longUID := make([]byte, MaxIdentifierLength+1)
	err = ValidateRegisterInputs(string(longUID), "device", "backup", 2, make([]byte, 32), 10, time.Now().Unix()+3600)
	if err == nil {
		t.Error("Expected error for UID too long")
	}

	// DID too long
	longDID := make([]byte, MaxIdentifierLength+1)
	err = ValidateRegisterInputs("user", string(longDID), "backup", 2, make([]byte, 32), 10, time.Now().Unix()+3600)
	if err == nil {
		t.Error("Expected error for DID too long")
	}

	// BID too long
	longBID := make([]byte, MaxIdentifierLength+1)
	err = ValidateRegisterInputs("user", "device", string(longBID), 2, make([]byte, 32), 10, time.Now().Unix()+3600)
	if err == nil {
		t.Error("Expected error for BID too long")
	}

	// Too many shares
	err = ValidateRegisterInputs("user", "device", "backup", MaxShares+1, make([]byte, 32), 10, time.Now().Unix()+3600)
	if err == nil {
		t.Error("Expected error for too many shares")
	}

	// Y share too large
	largeY := make([]byte, MaxYSize+1)
	err = ValidateRegisterInputs("user", "device", "backup", 2, largeY, 10, time.Now().Unix()+3600)
	if err == nil {
		t.Error("Expected error for Y share too large")
	}

	// Max guesses too high
	err = ValidateRegisterInputs("user", "device", "backup", 2, make([]byte, 32), MaxGuesses+1, time.Now().Unix()+3600)
	if err == nil {
		t.Error("Expected error for max guesses too high")
	}

	// Expiration in the past
	err = ValidateRegisterInputs("user", "device", "backup", 2, make([]byte, 32), 10, time.Now().Unix()-3600)
	if err == nil {
		t.Error("Expected error for expiration in the past")
	}
}

func TestValidateRecoverInputs(t *testing.T) {
	// Create a valid point
	validPoint := &crypto.Point2D{
		X: big.NewInt(1),
		Y: big.NewInt(2),
	}

	// Valid inputs
	err := ValidateRecoverInputs("user", "device", "backup", validPoint)
	if err != nil {
		t.Errorf("Expected no error for valid inputs, got: %v", err)
	}

	// Invalid point (nil)
	err = ValidateRecoverInputs("user", "device", "backup", nil)
	if err == nil {
		t.Error("Expected error for nil point")
	}

	// Invalid point (nil X)
	invalidPoint := &crypto.Point2D{
		X: nil,
		Y: big.NewInt(2),
	}
	err = ValidateRecoverInputs("user", "device", "backup", invalidPoint)
	if err == nil {
		t.Error("Expected error for point with nil X")
	}
}

func TestRegisterSecret(t *testing.T) {
	// Create temporary database
	dbPath := "test_register_secret.db"
	defer os.Remove(dbPath)

	db, err := database.NewDatabase(dbPath)
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
	y := make([]byte, 32)
	for i := range y {
		y[i] = byte(i)
	}
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600

	// Register secret
	err = RegisterSecret(db, uid, did, bid, authCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to register secret: %v", err)
	}

	// Verify registration
	record, err := db.Lookup(uid, did, bid)
	if err != nil {
		t.Fatalf("Failed to lookup registered secret: %v", err)
	}

	if record == nil {
		t.Fatal("Registered secret not found")
	}

	if record.Version != version {
		t.Errorf("Expected version %d, got %d", version, record.Version)
	}
	if record.X != x {
		t.Errorf("Expected X %d, got %d", x, record.X)
	}
}

func TestRecoverSecret(t *testing.T) {
	// Create temporary database
	dbPath := "test_recover_secret.db"
	defer os.Remove(dbPath)

	db, err := database.NewDatabase(dbPath)
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
	y := make([]byte, 32)
	for i := range y {
		y[i] = byte(i + 1) // Avoid zero bytes
	}
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600

	// Register secret first
	err = RegisterSecret(db, uid, did, bid, authCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to register secret: %v", err)
	}

	// Create a test point B
	b := &crypto.Point2D{
		X: big.NewInt(123),
		Y: big.NewInt(456),
	}

	// Recover secret
	response, err := RecoverSecret(db, uid, did, bid, b, 0)
	if err != nil {
		t.Fatalf("Failed to recover secret: %v", err)
	}

	if response == nil {
		t.Fatal("Recovery response is nil")
	}

	if response.Version != version {
		t.Errorf("Expected version %d, got %d", version, response.Version)
	}
	if response.X != x {
		t.Errorf("Expected X %d, got %d", x, response.X)
	}
	if response.NumGuesses != 1 {
		t.Errorf("Expected NumGuesses 1, got %d", response.NumGuesses)
	}
	if response.MaxGuesses != maxGuesses {
		t.Errorf("Expected MaxGuesses %d, got %d", maxGuesses, response.MaxGuesses)
	}
}

func TestRecoverSecretByAuthCode(t *testing.T) {
	// Create temporary database
	dbPath := "test_recover_by_auth.db"
	defer os.Remove(dbPath)

	db, err := database.NewDatabase(dbPath)
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
	y := make([]byte, 32)
	for i := range y {
		y[i] = byte(i + 1)
	}
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600

	// Register secret first
	err = RegisterSecret(db, uid, did, bid, authCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to register secret: %v", err)
	}

	// Create a test point B
	b := &crypto.Point2D{
		X: big.NewInt(123),
		Y: big.NewInt(456),
	}

	// Recover secret by auth code
	response, err := RecoverSecretByAuthCode(db, authCode, did, bid, b, 0)
	if err != nil {
		t.Fatalf("Failed to recover secret by auth code: %v", err)
	}

	if response == nil {
		t.Fatal("Recovery response is nil")
	}

	if response.Version != version {
		t.Errorf("Expected version %d, got %d", version, response.Version)
	}
	if response.X != x {
		t.Errorf("Expected X %d, got %d", x, response.X)
	}
}

func TestRecoverSecretTooManyGuesses(t *testing.T) {
	// Create temporary database
	dbPath := "test_too_many_guesses.db"
	defer os.Remove(dbPath)

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data with low max guesses
	uid := "test-user@example.com"
	did := "test-device"
	bid := "test-backup"
	authCode := "AUTH123456789"
	version := 1
	x := 2
	y := make([]byte, 32)
	maxGuesses := 2 // Low limit for testing
	expiration := time.Now().Unix() + 3600

	// Register secret first
	err = RegisterSecret(db, uid, did, bid, authCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to register secret: %v", err)
	}

	// Create a test point B
	b := &crypto.Point2D{
		X: big.NewInt(123),
		Y: big.NewInt(456),
	}

	// Make maximum allowed guesses
	for i := 0; i < maxGuesses; i++ {
		_, err := RecoverSecret(db, uid, did, bid, b, i)
		if err != nil {
			t.Fatalf("Failed to recover secret on guess %d: %v", i, err)
		}
	}

	// Try one more guess - should fail
	_, err = RecoverSecret(db, uid, did, bid, b, maxGuesses)
	if err == nil {
		t.Error("Expected error for too many guesses")
	}
}

func TestRecoverSecretExpired(t *testing.T) {
	// Create temporary database
	dbPath := "test_expired.db"
	defer os.Remove(dbPath)

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data with future expiration initially
	uid := "test-user@example.com"
	did := "test-device"
	bid := "test-backup"
	authCode := "AUTH123456789"
	version := 1
	x := 2
	y := make([]byte, 32)
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600 // 1 hour from now

	// Register secret first with future expiration
	err = RegisterSecret(db, uid, did, bid, authCode, version, x, y, maxGuesses, expiration)
	if err != nil {
		t.Fatalf("Failed to register secret: %v", err)
	}

	// Manually update the expiration to be in the past
	pastExpiration := time.Now().Unix() - 3600 // 1 hour ago
	err = db.Insert(uid, did, bid, authCode, version, x, y, 0, maxGuesses, pastExpiration)
	if err != nil {
		t.Fatalf("Failed to update expiration: %v", err)
	}

	// Create a test point B
	b := &crypto.Point2D{
		X: big.NewInt(123),
		Y: big.NewInt(456),
	}

	// Try to recover - should fail due to expiration
	_, err = RecoverSecret(db, uid, did, bid, b, 0)
	if err == nil {
		t.Error("Expected error for expired backup")
	}
}

func TestListBackups(t *testing.T) {
	// Create temporary database
	dbPath := "test_list_backups_server.db"
	defer os.Remove(dbPath)

	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test data
	uid := "test-user@example.com"
	authCode := "AUTH123456789"
	version := 1
	x := 2
	y := make([]byte, 32)
	maxGuesses := 10
	expiration := time.Now().Unix() + 3600

	// Register multiple backups
	backups := []struct {
		did string
		bid string
	}{
		{"device1", "backup1"},
		{"device1", "backup2"},
		{"device2", "backup1"},
	}

	for _, backup := range backups {
		err = RegisterSecret(db, uid, backup.did, backup.bid, authCode, version, x, y, maxGuesses, expiration)
		if err != nil {
			t.Fatalf("Failed to register backup %s/%s: %v", backup.did, backup.bid, err)
		}
	}

	// List backups
	backupList, err := ListBackups(db, uid)
	if err != nil {
		t.Fatalf("Failed to list backups: %v", err)
	}

	if len(backupList) != len(backups) {
		t.Errorf("Expected %d backups, got %d", len(backups), len(backupList))
	}

	// Verify backup contents
	for _, backup := range backupList {
		if backup.UID != uid {
			t.Errorf("Expected UID %s, got %s", uid, backup.UID)
		}
		if backup.Version != version {
			t.Errorf("Expected version %d, got %d", version, backup.Version)
		}
	}
}

func TestGetServerInfo(t *testing.T) {
	version := "1.0.0"
	noiseKey := []byte("test-noise-key-32-bytes-long!!")
	monitoring := NewMonitoringTracker()

	info := GetServerInfo(version, noiseKey, monitoring)

	if info.Version != version {
		t.Errorf("Expected version %s, got %s", version, info.Version)
	}

	if info.NoiseNKKey == "" {
		t.Error("Expected NoiseNK key to be set")
	}

	expectedCapabilities := []string{
		"register_secret",
		"recover_secret",
		"list_backups",
		"echo",
		"noise_nk_encryption",
	}

	if len(info.Capabilities) != len(expectedCapabilities) {
		t.Errorf("Expected %d capabilities, got %d", len(expectedCapabilities), len(info.Capabilities))
	}

	// Check monitoring data is included
	if info.Monitoring == nil {
		t.Error("Expected monitoring data to be included")
	}

	// Test without noise key
	infoNoNoise := GetServerInfo(version, nil, monitoring)
	if infoNoNoise.NoiseNKKey != "" {
		t.Error("Expected empty NoiseNK key when none provided")
	}

	expectedCapabilitiesNoNoise := []string{
		"register_secret",
		"recover_secret",
		"list_backups",
		"echo",
	}

	if len(infoNoNoise.Capabilities) != len(expectedCapabilitiesNoNoise) {
		t.Errorf("Expected %d capabilities without noise, got %d", len(expectedCapabilitiesNoNoise), len(infoNoNoise.Capabilities))
	}

	// Test without monitoring
	infoNoMonitoring := GetServerInfo(version, noiseKey, nil)
	if infoNoMonitoring.Monitoring != nil {
		t.Error("Expected no monitoring data when monitoring is nil")
	}
}

func TestEcho(t *testing.T) {
	testMessage := "Hello, OpenADP!"
	result := Echo(testMessage)

	if result != testMessage {
		t.Errorf("Expected echo result %s, got %s", testMessage, result)
	}
}
