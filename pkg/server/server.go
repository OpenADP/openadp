// Package server provides core business logic for OpenADP server operations.
package server

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/openadp/openadp/pkg/crypto"
	"github.com/openadp/openadp/pkg/database"
)

const (
	// Maximum length for string identifiers
	MaxIdentifierLength = 512
	// Maximum number of shares allowed
	MaxShares = 1000
	// Maximum number of guesses allowed
	MaxGuesses = 1000
	// Maximum size for Y coordinate (32 bytes for Ed25519 point)
	MaxYSize = 32
)

// RegisterSecretRequest represents a request to register a secret share
type RegisterSecretRequest struct {
	UID        string `json:"uid"`
	DID        string `json:"did"`
	BID        string `json:"bid"`
	AuthCode   string `json:"auth_code"`
	Version    int    `json:"version"`
	X          int    `json:"x"`
	Y          string `json:"y"` // Base64 encoded
	MaxGuesses int    `json:"max_guesses"`
	Expiration int64  `json:"expiration"`
}

// RecoverSecretRequest represents a request to recover a secret share
type RecoverSecretRequest struct {
	UID      string          `json:"uid"`
	DID      string          `json:"did"`
	BID      string          `json:"bid"`
	AuthCode string          `json:"auth_code"`
	B        *crypto.Point2D `json:"b"`
	GuessNum int             `json:"guess_num"`
}

// RecoverSecretResponse represents the response from recovering a secret share
type RecoverSecretResponse struct {
	Version    int             `json:"version"`
	X          int             `json:"x"`
	SiB        *crypto.Point2D `json:"si_b"`
	NumGuesses int             `json:"num_guesses"`
	MaxGuesses int             `json:"max_guesses"`
	Expiration int64           `json:"expiration"`
}

// ListBackupsResponse represents a backup entry in the list response
type ListBackupsResponse struct {
	UID        string `json:"uid"`
	BID        string `json:"bid"`
	Version    int    `json:"version"`
	NumGuesses int    `json:"num_guesses"`
	MaxGuesses int    `json:"max_guesses"`
	Expiration int64  `json:"expiration"`
}

// pointValid checks if a point is valid (basic validation)
func pointValid(p *crypto.Point2D) bool {
	if p == nil || p.X == nil || p.Y == nil {
		return false
	}
	// Additional validation could be added here
	return true
}

// ValidateRegisterInputs validates inputs for secret registration
func ValidateRegisterInputs(uid, did, bid string, x int, y []byte, maxGuesses int, expiration int64) error {
	if len(uid) > MaxIdentifierLength {
		return fmt.Errorf("UID too long")
	}
	if len(did) > MaxIdentifierLength {
		return fmt.Errorf("DID too long")
	}
	if len(bid) > MaxIdentifierLength {
		return fmt.Errorf("BID too long")
	}
	if x > MaxShares {
		return fmt.Errorf("too many shares")
	}
	if len(y) > MaxYSize {
		// Debug logging for Y share size issue
		fmt.Printf("DEBUG: Y validation failed - len(y)=%d, MaxYSize=%d, y bytes: %v\n", len(y), MaxYSize, y)
		return fmt.Errorf("Y share too large")
	}
	if maxGuesses > MaxGuesses {
		return fmt.Errorf("max guesses too high")
	}

	// Check expiration (0 means no expiration)
	if expiration != 0 && expiration < time.Now().Unix() {
		return fmt.Errorf("expiration is in the past")
	}

	return nil
}

// ValidateRecoverInputs validates inputs for secret recovery
func ValidateRecoverInputs(uid, did, bid string, b *crypto.Point2D) error {
	if len(uid) > MaxIdentifierLength {
		return fmt.Errorf("UID too long")
	}
	if len(did) > MaxIdentifierLength {
		return fmt.Errorf("DID too long")
	}
	if len(bid) > MaxIdentifierLength {
		return fmt.Errorf("BID too long")
	}
	if !pointValid(b) {
		return fmt.Errorf("invalid point")
	}

	return nil
}

// RegisterSecret registers a secret share with the server
func RegisterSecret(db *database.Database, uid, did, bid, authCode string, version, x int, y []byte, maxGuesses int, expiration int64) error {
	// Validate inputs
	if err := ValidateRegisterInputs(uid, did, bid, x, y, maxGuesses, expiration); err != nil {
		return err
	}

	// Insert into database
	err := db.Insert(uid, did, bid, authCode, version, x, y, 0, maxGuesses, expiration)
	if err != nil {
		return fmt.Errorf("failed to register secret: %v", err)
	}

	return nil
}

// RecoverSecret recovers a secret share from the server
func RecoverSecret(db *database.Database, uid, did, bid string, b *crypto.Point2D, guessNum int) (*RecoverSecretResponse, error) {
	// Validate inputs
	if err := ValidateRecoverInputs(uid, did, bid, b); err != nil {
		return nil, err
	}

	// Look up the stored share
	record, err := db.Lookup(uid, did, bid)
	if err != nil {
		return nil, fmt.Errorf("database lookup failed: %v", err)
	}
	if record == nil {
		return nil, fmt.Errorf("share not found")
	}

	// Verify expected guess number (for idempotency)
	if guessNum != record.NumGuesses {
		return nil, fmt.Errorf("expecting guess_num = %d", record.NumGuesses)
	}

	// Check if too many guesses have been made
	if record.NumGuesses >= record.MaxGuesses {
		return nil, fmt.Errorf("too many guesses")
	}

	// Check expiration
	if record.Expiration != 0 && record.Expiration < time.Now().Unix() {
		return nil, fmt.Errorf("backup has expired")
	}

	// Increment guess counter
	newGuessCount := record.NumGuesses + 1
	err = db.UpdateGuessCount(uid, did, bid, newGuessCount)
	if err != nil {
		return nil, fmt.Errorf("failed to update guess count: %v", err)
	}

	// Perform cryptographic recovery calculation
	yInt := new(big.Int)
	yBytes := make([]byte, len(record.Y))
	copy(yBytes, record.Y)

	// Y is now stored in little-endian format (to match Python server)
	// Convert from little-endian to big integer
	for i, j := 0, len(yBytes)-1; i < j; i, j = i+1, j-1 {
		yBytes[i], yBytes[j] = yBytes[j], yBytes[i]
	}
	yInt.SetBytes(yBytes)

	// Convert Point2D to Point4D for multiplication
	b4D := &crypto.Point4D{
		X: new(big.Int).Set(b.X),
		Y: new(big.Int).Set(b.Y),
		Z: big.NewInt(1),
		T: new(big.Int).Mul(b.X, b.Y),
	}

	// Calculate si_b = y * b (scalar multiplication)
	siB4D := crypto.PointMul(yInt, b4D)

	// Convert back to Point2D
	siB := crypto.Unexpand(siB4D)

	response := &RecoverSecretResponse{
		Version:    record.Version,
		X:          record.X,
		SiB:        siB,
		NumGuesses: newGuessCount,
		MaxGuesses: record.MaxGuesses,
		Expiration: record.Expiration,
	}

	return response, nil
}

// RecoverSecretByAuthCode recovers a secret share using authentication code
func RecoverSecretByAuthCode(db *database.Database, authCode, did, bid string, b *crypto.Point2D, guessNum int) (*RecoverSecretResponse, error) {
	// Look up the stored share by auth code
	record, err := db.LookupByAuthCode(authCode, did, bid)
	if err != nil {
		return nil, fmt.Errorf("database lookup failed: %v", err)
	}
	if record == nil {
		return nil, fmt.Errorf("share not found")
	}

	// Debug: Print what we retrieved from database
	yIntFromDB := new(big.Int)
	yBytesFromDB := make([]byte, len(record.Y))
	copy(yBytesFromDB, record.Y)

	// Y is stored in little-endian format
	for i, j := 0, len(yBytesFromDB)-1; i < j; i, j = i+1, j-1 {
		yBytesFromDB[i], yBytesFromDB[j] = yBytesFromDB[j], yBytesFromDB[i]
	}
	yIntFromDB.SetBytes(yBytesFromDB)
	fmt.Printf("DATABASE RETRIEVED: x=%d, y=%s (hex: %x)\n",
		record.X, yIntFromDB.String(), record.Y)

	// Verify expected guess number (for idempotency)
	if guessNum != record.NumGuesses {
		return nil, fmt.Errorf("expecting guess_num = %d", record.NumGuesses)
	}

	// Check if too many guesses have been made
	if record.NumGuesses >= record.MaxGuesses {
		return nil, fmt.Errorf("too many guesses")
	}

	// Check expiration
	if record.Expiration != 0 && record.Expiration < time.Now().Unix() {
		return nil, fmt.Errorf("backup has expired")
	}

	// Increment guess counter
	newGuessCount := record.NumGuesses + 1
	err = db.UpdateGuessCount(record.UID, did, bid, newGuessCount)
	if err != nil {
		return nil, fmt.Errorf("failed to update guess count: %v", err)
	}

	// Perform cryptographic recovery calculation
	yInt := new(big.Int)
	yBytes := make([]byte, len(record.Y))
	copy(yBytes, record.Y)

	// Y is now stored in little-endian format (to match Python server)
	// Convert from little-endian to big integer
	for i, j := 0, len(yBytes)-1; i < j; i, j = i+1, j-1 {
		yBytes[i], yBytes[j] = yBytes[j], yBytes[i]
	}
	yInt.SetBytes(yBytes)

	// Convert Point2D to Point4D for multiplication
	b4D := &crypto.Point4D{
		X: new(big.Int).Set(b.X),
		Y: new(big.Int).Set(b.Y),
		Z: big.NewInt(1),
		T: new(big.Int).Mul(b.X, b.Y),
	}

	// Calculate si_b = y * b (scalar multiplication)
	siB4D := crypto.PointMul(yInt, b4D)

	// Convert back to Point2D
	siB := crypto.Unexpand(siB4D)

	response := &RecoverSecretResponse{
		Version:    record.Version,
		X:          record.X,
		SiB:        siB,
		NumGuesses: newGuessCount,
		MaxGuesses: record.MaxGuesses,
		Expiration: record.Expiration,
	}

	return response, nil
}

// ListBackups lists all backups for a user
func ListBackups(db *database.Database, uid string) ([]ListBackupsResponse, error) {
	backups, err := db.ListBackups(uid)
	if err != nil {
		return nil, fmt.Errorf("failed to list backups: %v", err)
	}

	response := make([]ListBackupsResponse, len(backups))
	for i, backup := range backups {
		response[i] = ListBackupsResponse{
			UID:        uid,
			BID:        backup.BID,
			Version:    backup.Version,
			NumGuesses: backup.NumGuesses,
			MaxGuesses: backup.MaxGuesses,
			Expiration: backup.Expiration,
		}
	}

	return response, nil
}

// ListBackupsByAuthCode lists all backups for a user identified by auth code
func ListBackupsByAuthCode(db *database.Database, authCode string) ([]ListBackupsResponse, error) {
	backups, err := db.ListBackupsByAuthCode(authCode)
	if err != nil {
		return nil, fmt.Errorf("failed to list backups by auth code: %v", err)
	}

	response := make([]ListBackupsResponse, len(backups))
	for i, backup := range backups {
		response[i] = ListBackupsResponse{
			UID:        "", // UID not exposed when using auth code
			BID:        backup.BID,
			Version:    backup.Version,
			NumGuesses: backup.NumGuesses,
			MaxGuesses: backup.MaxGuesses,
			Expiration: backup.Expiration,
		}
	}

	return response, nil
}

// MonitoringInfo represents server monitoring data
type MonitoringInfo struct {
	QueriesCurrentHour int     `json:"queries_current_hour"`
	QueriesLast24H     int     `json:"queries_last_24h"`
	UptimeStart        string  `json:"uptime_start"`
	ResponseTimeAvgMs  float64 `json:"response_time_avg_ms"`
	ErrorRatePercent   float64 `json:"error_rate_percent"`
	LastHourHistogram  []int   `json:"last_hour_histogram,omitempty"`
}

// ServerInfo represents server information
type ServerInfo struct {
	Version      string          `json:"version"`
	NoiseNKKey   string          `json:"noise_nk_public_key,omitempty"`
	Capabilities []string        `json:"capabilities"`
	Monitoring   *MonitoringInfo `json:"monitoring,omitempty"`
}

// GetServerInfo returns server information
func GetServerInfo(version string, noiseNKKey []byte, monitoring *MonitoringTracker) *ServerInfo {
	info := &ServerInfo{
		Version: version,
		Capabilities: []string{
			"register_secret",
			"recover_secret",
			"list_backups",
			"echo",
		},
	}

	if len(noiseNKKey) > 0 {
		info.NoiseNKKey = base64.StdEncoding.EncodeToString(noiseNKKey)
		info.Capabilities = append(info.Capabilities, "noise_nk_encryption")
	}

	// Include monitoring data if available
	if monitoring != nil {
		info.Monitoring = monitoring.GetMonitoringInfo()
	}

	return info
}

// Echo simply returns the input message (for testing connectivity)
func Echo(message string) string {
	return message
}
