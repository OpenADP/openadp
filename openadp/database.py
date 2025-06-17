#!/usr/bin/env python3
"""
OpenADP Database Module

This module provides database functionality for the OpenADP (Open Asynchronous 
Distributed Password) system. It handles storage and retrieval of secret shares
using SQLite as the backend database.

The main class `Database` provides methods for:
- Creating and managing the shares table
- Inserting/updating secret shares  
- Querying shares by user, device, and backup identifiers
- Listing all backups for a user

Database Schema:
- UID: User identifier (JWT 'sub' claim - UUID format)
- DID: Device identifier (hostname)
- BID: Backup identifier (file:// URLs)
- version: Version number for backup
- x, y: Secret sharing coordinates
- num_guesses, max_guesses: Guess tracking
- expiration: Expiration timestamp
"""

import sqlite3
from typing import List, Optional, Tuple, Union


class Database:
    """
    Database interface for OpenADP secret share storage.
    
    Uses SQLite to store secret shares with associated metadata including
    user/device/backup identifiers, version info, guess counters, and expiration.
    """
    
    def __init__(self, db_name: str):
        """
        Initialize database connection and create tables if needed.
        
        Args:
            db_name: Path to the SQLite database file
        """
        self.db_name = db_name
        self.con = sqlite3.connect(db_name)
        self._create_tables_if_needed()

    def __del__(self):
        """Clean up database connection when object is destroyed."""
        if hasattr(self, 'con'):
            self.con.close()

    def _create_tables_if_needed(self) -> None:
        """Create the shares table if it doesn't already exist."""
        cur = self.con.cursor()
        
        # Check if shares table exists
        result = cur.execute(
            "SELECT name FROM sqlite_master WHERE name='shares'"
        ).fetchone()
        
        if result is None:
            print(f"Creating shares table in {self.db_name}")
            cur.execute("""
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
            """)
            self.con.commit()

        # Check if server_config table exists
        result = cur.execute(
            "SELECT name FROM sqlite_master WHERE name='server_config'"
        ).fetchone()

        if result is None:
            print(f"Creating server_config table in {self.db_name}")
            cur.execute("""
                CREATE TABLE server_config(
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                )
            """)
            self.con.commit()

    def get_server_config(self, key: str) -> Optional[bytes]:
        """Gets a value from the server_config table."""
        sql = "SELECT value FROM server_config WHERE key = ?"
        cur = self.con.cursor()
        results = cur.execute(sql, [key]).fetchall()
        if not results:
            return None
        return results[0][0]

    def set_server_config(self, key: str, value: bytes) -> None:
        """Sets a value in the server_config table."""
        sql = "REPLACE INTO server_config(key, value) VALUES(?, ?)"
        cur = self.con.cursor()
        cur.execute(sql, (key, value))
        self.con.commit()

    def insert(self, uid: bytes, did: bytes, bid: bytes, auth_code: str, version: int, x: int, 
               y: bytes, num_guesses: int, max_guesses: int, expiration: int) -> None:
        """
        Insert or update a secret share in the database.
        
        Uses REPLACE to handle both insert and update operations.
        
        Args:
            uid: User identifier (bytes)
            did: Device identifier (bytes)  
            bid: Backup identifier (bytes)
            auth_code: Server-specific authentication code
            version: Version number for this backup
            x: X coordinate for secret sharing
            y: Y coordinate (encrypted share data)
            num_guesses: Current number of recovery attempts
            max_guesses: Maximum number of recovery attempts allowed
            expiration: Expiration timestamp (0 for no expiration)
        """
        sql = """
            REPLACE INTO shares(UID, DID, BID, auth_code, version, x, y, num_guesses, max_guesses, expiration)
            VALUES(?,?,?,?,?,?,?,?,?,?)
        """
        cur = self.con.cursor()
        cur.execute(sql, (
            uid.decode('utf-8'), 
            did.decode('utf-8'), 
            bid.decode('utf-8'),
            auth_code, 
            version, 
            x, 
            y,
            num_guesses, 
            max_guesses, 
            expiration
        ))
        self.con.commit()

    def list_backups(self, uid: Union[str, bytes]) -> List[Tuple]:
        """
        List all backups for a specific user.
        
        Args:
            uid: User identifier (string or bytes)
            
        Returns:
            List of tuples containing:
            (did, bid, version, num_guesses, max_guesses, expiration)
        """
        sql = """
            SELECT DID, BID, version, num_guesses, max_guesses, expiration 
            FROM shares 
            WHERE UID = ?
        """
        cur = self.con.cursor()
        
        # Handle both string and bytes input
        uid_str = uid.decode('utf-8') if isinstance(uid, bytes) else uid
        
        return cur.execute(sql, [uid_str]).fetchall()

    def lookup(self, uid: bytes, did: bytes, bid: bytes) -> Optional[Tuple]:
        """
        Look up a specific share by user, device, and backup identifiers.
        
        Args:
            uid: User identifier (bytes)
            did: Device identifier (bytes)
            bid: Backup identifier (bytes)
            
        Returns:
            Tuple containing (version, x, y, num_guesses, max_guesses, expiration)
            or None if not found
        """
        sql = """
            SELECT version, x, y, num_guesses, max_guesses, expiration 
            FROM shares
            WHERE UID = ? AND DID = ? AND BID = ?
        """
        cur = self.con.cursor()
        results = cur.execute(sql, [
            uid.decode('utf-8'), 
            did.decode('utf-8'), 
            bid.decode('utf-8')
        ]).fetchall()
        
        if not results:
            return None
        
        assert len(results) == 1, f"Expected 1 result, got {len(results)}"
        return results[0]

    def find_guess_number(self, uid: bytes, did: bytes, bid: bytes) -> Optional[int]:
        """
        Find the current guess number for a specific share.
        
        Args:
            uid: User identifier (bytes)
            did: Device identifier (bytes)
            bid: Backup identifier (bytes)
            
        Returns:
            Current guess number, or None if share not found
        """
        backup = self.lookup(uid, did, bid)
        if backup is None:
            return None
        
        # num_guesses is at index 3 in the tuple
        return backup[3]

    def lookup_by_auth_code(self, auth_code: str, did, bid) -> Optional[Tuple]:
        """
        Look up a specific share by authentication code, device, and backup identifiers.
        
        Args:
            auth_code: Server-specific authentication code
            did: Device identifier (string or bytes)
            bid: Backup identifier (string or bytes)
            
        Returns:
            Tuple containing (uid, version, x, y, num_guesses, max_guesses, expiration)
            or None if not found
        """
        sql = """
            SELECT UID, version, x, y, num_guesses, max_guesses, expiration 
            FROM shares
            WHERE auth_code = ? AND DID = ? AND BID = ?
        """
        cur = self.con.cursor()
        
        # Handle both string and bytes input
        did_str = did.decode('utf-8') if isinstance(did, bytes) else did
        bid_str = bid.decode('utf-8') if isinstance(bid, bytes) else bid
        
        results = cur.execute(sql, [
            auth_code,
            did_str, 
            bid_str
        ]).fetchall()
        
        if not results:
            return None
        
        assert len(results) == 1, f"Expected 1 result, got {len(results)}"
        return results[0]

    def list_backups_by_auth_code(self, auth_code: str) -> List[Tuple]:
        """
        List all backups for a specific authentication code.
        
        Args:
            auth_code: Server-specific authentication code
            
        Returns:
            List of tuples containing:
            (did, bid, version, num_guesses, max_guesses, expiration)
        """
        sql = """
            SELECT DID, BID, version, num_guesses, max_guesses, expiration 
            FROM shares 
            WHERE auth_code = ?
        """
        cur = self.con.cursor()
        return cur.execute(sql, [auth_code]).fetchall()

    def update_guess_count(self, uid, did, bid, num_guesses: int) -> None:
        """
        Update the guess count for a specific share.
        
        Args:
            uid: User identifier (string or bytes)
            did: Device identifier (string or bytes)
            bid: Backup identifier (string or bytes)
            num_guesses: New guess count
        """
        sql = """
            UPDATE shares 
            SET num_guesses = ? 
            WHERE UID = ? AND DID = ? AND BID = ?
        """
        cur = self.con.cursor()
        
        # Handle both string and bytes input
        uid_str = uid.decode('utf-8') if isinstance(uid, bytes) else uid
        did_str = did.decode('utf-8') if isinstance(did, bytes) else did
        bid_str = bid.decode('utf-8') if isinstance(bid, bytes) else bid
        
        cur.execute(sql, [
            num_guesses,
            uid_str, 
            did_str, 
            bid_str
        ])
        self.con.commit()

    def close(self) -> None:
        """Explicitly close the database connection."""
        if hasattr(self, 'con'):
            self.con.close()


def main():
    """
    Test/demo function for database functionality.
    
    Creates test data and demonstrates database operations.
    """
    print("Testing OpenADP Database...")
    
    # Create test database
    db = Database("openadp_test.db")
    
    # Test data
    expiration = 1906979047  # Some time in 2030 (seconds since 1970)
    uid = b"waywardgeek@gmail.com"
    did = b"Ubuntu beast Alienware laptop"
    version = 1
    x = 1
    y = 234
    
    # Test insertions
    print("Inserting test data...")
    db.insert(uid, did, b"file://archive.tgz", "test_auth_code_12345", version, x, y, 0, 10, expiration)
    db.insert(uid, did, b"firefox_passwords://passwords.json", "test_auth_code_67890", version, x, y, 0, 10, expiration)
    
    # Test list_backups
    print("Testing list_backups...")
    backups = db.list_backups(uid)
    print(f"Found {len(backups)} backups:")
    for backup in backups:
        print(f"  {backup}")
    
    # Test lookup
    print("Testing lookup...")
    share = db.lookup(uid, did, b"file://archive.tgz")
    print(f"Lookup result: {share}")
    
    # Test find_guess_number
    print("Testing find_guess_number...")
    guess_num = db.find_guess_number(uid, did, b"file://archive.tgz")
    print(f"Current guess number: {guess_num}")
    
    # Clean up
    db.close()
    print("✅ Database tests completed!")


if __name__ == '__main__':
    main()
