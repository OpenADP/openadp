// Package database provides SQLite-based storage for OpenADP server operations.
package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Database represents a connection to the OpenADP SQLite database
type Database struct {
	db   *sql.DB
	path string
}

// ShareRecord represents a secret share stored in the database
type ShareRecord struct {
	UID        string
	DID        string
	BID        string
	AuthCode   string
	Version    int
	X          int
	Y          []byte
	NumGuesses int
	MaxGuesses int
	Expiration int64
}

// BackupInfo represents backup information for listing
type BackupInfo struct {
	DID        string
	BID        string
	Version    int
	NumGuesses int
	MaxGuesses int
	Expiration int64
}

// NewDatabase creates a new database connection and initializes tables
func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Configure SQLite for better concurrent access
	if err := configureSQLite(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to configure SQLite: %v", err)
	}

	database := &Database{
		db:   db,
		path: dbPath,
	}

	if err := database.createTablesIfNeeded(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tables: %v", err)
	}

	return database, nil
}

// configureSQLite sets up SQLite for better concurrent access
func configureSQLite(db *sql.DB) error {
	// Enable WAL mode for better concurrent access
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return fmt.Errorf("failed to enable WAL mode: %v", err)
	}

	// Set busy timeout to handle concurrent access
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		return fmt.Errorf("failed to set busy timeout: %v", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return fmt.Errorf("failed to enable foreign keys: %v", err)
	}

	return nil
}

// createTablesIfNeeded creates the necessary tables if they don't exist
func (d *Database) createTablesIfNeeded() error {
	// Check if shares table exists
	var tableName string
	err := d.db.QueryRow("SELECT name FROM sqlite_master WHERE name='shares'").Scan(&tableName)
	if err == sql.ErrNoRows {
		// Create shares table
		createSharesSQL := `
			CREATE TABLE shares(
				UID TEXT NOT NULL,
				DID TEXT NOT NULL,
				BID TEXT NOT NULL,
				auth_code TEXT NOT NULL,
				version INTEGER NOT NULL,
				x INTEGER NOT NULL,
				y BLOB NOT NULL,
				num_guesses INTEGER NOT NULL,
				max_guesses INTEGER NOT NULL,
				expiration INTEGER NOT NULL,
				PRIMARY KEY(UID, DID, BID)
			)
		`
		if _, err := d.db.Exec(createSharesSQL); err != nil {
			return fmt.Errorf("failed to create shares table: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check shares table: %v", err)
	}

	// Check if server_config table exists
	err = d.db.QueryRow("SELECT name FROM sqlite_master WHERE name='server_config'").Scan(&tableName)
	if err == sql.ErrNoRows {
		// Create server_config table
		createConfigSQL := `
			CREATE TABLE server_config(
				key TEXT PRIMARY KEY NOT NULL,
				value BLOB NOT NULL
			)
		`
		if _, err := d.db.Exec(createConfigSQL); err != nil {
			return fmt.Errorf("failed to create server_config table: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check server_config table: %v", err)
	}

	return nil
}

// Insert inserts or updates a secret share in the database
func (d *Database) Insert(uid, did, bid, authCode string, version, x int, y []byte, numGuesses, maxGuesses int, expiration int64) error {
	insertSQL := `
		REPLACE INTO shares(UID, DID, BID, auth_code, version, x, y, num_guesses, max_guesses, expiration)
		VALUES(?,?,?,?,?,?,?,?,?,?)
	`

	_, err := d.db.Exec(insertSQL, uid, did, bid, authCode, version, x, y, numGuesses, maxGuesses, expiration)
	if err != nil {
		return fmt.Errorf("failed to insert share: %v", err)
	}

	return nil
}

// Lookup retrieves a specific share by UID, DID, and BID
func (d *Database) Lookup(uid, did, bid string) (*ShareRecord, error) {
	lookupSQL := `
		SELECT version, x, y, num_guesses, max_guesses, expiration 
		FROM shares
		WHERE UID = ? AND DID = ? AND BID = ?
	`

	var record ShareRecord
	record.UID = uid
	record.DID = did
	record.BID = bid

	err := d.db.QueryRow(lookupSQL, uid, did, bid).Scan(
		&record.Version,
		&record.X,
		&record.Y,
		&record.NumGuesses,
		&record.MaxGuesses,
		&record.Expiration,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to lookup share: %v", err)
	}

	return &record, nil
}

// LookupByAuthCode retrieves a share by authentication code, DID, and BID
func (d *Database) LookupByAuthCode(authCode, did, bid string) (*ShareRecord, error) {
	lookupSQL := `
		SELECT UID, version, x, y, num_guesses, max_guesses, expiration 
		FROM shares
		WHERE auth_code = ? AND DID = ? AND BID = ?
	`

	var record ShareRecord
	record.AuthCode = authCode
	record.DID = did
	record.BID = bid

	err := d.db.QueryRow(lookupSQL, authCode, did, bid).Scan(
		&record.UID,
		&record.Version,
		&record.X,
		&record.Y,
		&record.NumGuesses,
		&record.MaxGuesses,
		&record.Expiration,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to lookup share by auth code: %v", err)
	}

	return &record, nil
}

// UpdateGuessCount updates the guess count for a specific share
func (d *Database) UpdateGuessCount(uid, did, bid string, numGuesses int) error {
	updateSQL := `
		UPDATE shares 
		SET num_guesses = ? 
		WHERE UID = ? AND DID = ? AND BID = ?
	`

	result, err := d.db.Exec(updateSQL, numGuesses, uid, did, bid)
	if err != nil {
		return fmt.Errorf("failed to update guess count: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no rows updated - share not found")
	}

	return nil
}

// ListBackups lists all backups for a specific user
func (d *Database) ListBackups(uid string) ([]BackupInfo, error) {
	listSQL := `
		SELECT DID, BID, version, num_guesses, max_guesses, expiration 
		FROM shares 
		WHERE UID = ?
	`

	rows, err := d.db.Query(listSQL, uid)
	if err != nil {
		return nil, fmt.Errorf("failed to query backups: %v", err)
	}
	defer rows.Close()

	var backups []BackupInfo
	for rows.Next() {
		var backup BackupInfo
		err := rows.Scan(
			&backup.DID,
			&backup.BID,
			&backup.Version,
			&backup.NumGuesses,
			&backup.MaxGuesses,
			&backup.Expiration,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan backup row: %v", err)
		}
		backups = append(backups, backup)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating backup rows: %v", err)
	}

	return backups, nil
}

// VerifyAuthCodeForUser verifies that an auth code is valid for a specific user
// by checking if any backup exists for that user with that auth code
func (d *Database) VerifyAuthCodeForUser(uid, authCode string) (bool, error) {
	var count int
	err := d.db.QueryRow(
		"SELECT COUNT(*) FROM shares WHERE UID = ? AND auth_code = ?",
		uid, authCode,
	).Scan(&count)

	if err != nil {
		return false, fmt.Errorf("failed to verify auth code: %v", err)
	}

	return count > 0, nil
}

// GetServerConfig retrieves a configuration value from the server_config table
func (d *Database) GetServerConfig(key string) ([]byte, error) {
	var value []byte
	err := d.db.QueryRow("SELECT value FROM server_config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return nil, nil // Not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get server config: %v", err)
	}
	return value, nil
}

// SetServerConfig sets a configuration value in the server_config table
func (d *Database) SetServerConfig(key string, value []byte) error {
	_, err := d.db.Exec("REPLACE INTO server_config(key, value) VALUES(?, ?)", key, value)
	if err != nil {
		return fmt.Errorf("failed to set server config: %v", err)
	}
	return nil
}

// FindGuessNumber finds the current guess number for a share
func (d *Database) FindGuessNumber(uid, did, bid string) (int, error) {
	var numGuesses int
	err := d.db.QueryRow(
		"SELECT num_guesses FROM shares WHERE UID = ? AND DID = ? AND BID = ?",
		uid, did, bid,
	).Scan(&numGuesses)

	if err == sql.ErrNoRows {
		return -1, fmt.Errorf("share not found")
	}
	if err != nil {
		return -1, fmt.Errorf("failed to find guess number: %v", err)
	}

	return numGuesses, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// GetPath returns the database file path
func (d *Database) GetPath() string {
	return d.path
}

// ValidateExpiration checks if a backup has expired
func ValidateExpiration(expiration int64) error {
	if expiration == 0 {
		return nil // No expiration
	}

	now := time.Now().Unix()
	if expiration < now {
		return fmt.Errorf("backup has expired")
	}

	return nil
}

// GetUIDFromAuthCode retrieves the UID associated with an auth code
// by finding any backup that uses that auth code
func (d *Database) GetUIDFromAuthCode(authCode string) (string, error) {
	var uid string
	err := d.db.QueryRow(
		"SELECT UID FROM shares WHERE auth_code = ? LIMIT 1",
		authCode,
	).Scan(&uid)

	if err == sql.ErrNoRows {
		return "", fmt.Errorf("auth code not found")
	}
	if err != nil {
		return "", fmt.Errorf("failed to get UID from auth code: %v", err)
	}

	return uid, nil
}
