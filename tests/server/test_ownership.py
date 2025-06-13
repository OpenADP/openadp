#!/usr/bin/env python3
"""
Test ownership functionality for Phase 3 authentication.

Tests that users can only access backups they own, and that ownership
is properly enforced in RegisterSecret, RecoverSecret, and ListBackups.
"""

import unittest
import sys
import os
import tempfile

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'prototype', 'src'))

from openadp import database
from server import server


class TestOwnership(unittest.TestCase):
    """Test ownership tracking and enforcement."""
    
    def setUp(self):
        """Set up test database and test data."""
        # Create temporary database
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.db = database.Database(self.db_path)
        
        # Test data
        self.uid = "test@device"
        self.did = "device"
        self.bid = "file://test.txt"
        self.version = 1
        self.x = 1
        self.y = b'\x01' * 32
        self.max_guesses = 10
        self.expiration = 0
        
        # Test users
        self.alice_sub = "alice-oauth-sub-12345"
        self.bob_sub = "bob-oauth-sub-67890"
    
    def tearDown(self):
        """Clean up test database."""
        self.db.close()
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_register_secret_new_backup(self):
        """Test that registering a new backup succeeds."""
        result = server.register_secret(
            self.db, self.uid, self.did, self.bid,
            self.version, self.x, self.y, self.max_guesses, self.expiration,
            self.alice_sub
        )
        
        self.assertTrue(result)
        
        # Verify ownership was recorded
        backup = self.db.lookup(self.uid.encode(), self.did.encode(), self.bid.encode())
        self.assertIsNotNone(backup)
        self.assertEqual(backup[6], self.alice_sub)  # owner_sub is at index 6
    
    def test_register_secret_ownership_conflict(self):
        """Test that a user cannot register a backup owned by another user."""
        # Alice registers first
        result = server.register_secret(
            self.db, self.uid, self.did, self.bid,
            self.version, self.x, self.y, self.max_guesses, self.expiration,
            self.alice_sub
        )
        self.assertTrue(result)
        
        # Bob tries to register the same backup
        result = server.register_secret(
            self.db, self.uid, self.did, self.bid,
            self.version, 2, b'\x02' * 32, self.max_guesses, self.expiration,
            self.bob_sub
        )
        
        self.assertIsInstance(result, Exception)
        self.assertIn("Access denied", str(result))
        self.assertIn(self.bob_sub, str(result))
    
    def test_register_secret_owner_can_update(self):
        """Test that an owner can update their own backup."""
        # Alice registers first
        result = server.register_secret(
            self.db, self.uid, self.did, self.bid,
            self.version, self.x, self.y, self.max_guesses, self.expiration,
            self.alice_sub
        )
        self.assertTrue(result)
        
        # Alice updates her own backup
        new_y = b'\x02' * 32
        result = server.register_secret(
            self.db, self.uid, self.did, self.bid,
            self.version, self.x, new_y, self.max_guesses, self.expiration,
            self.alice_sub
        )
        self.assertTrue(result)
        
        # Verify update was successful
        backup = self.db.lookup(self.uid.encode(), self.did.encode(), self.bid.encode())
        self.assertEqual(backup[2], new_y)  # y is at index 2
        self.assertEqual(backup[6], self.alice_sub)  # ownership preserved
    
    def test_recover_secret_owner_access(self):
        """Test that an owner can recover their own backup."""
        # Alice registers a backup
        server.register_secret(
            self.db, self.uid, self.did, self.bid,
            self.version, self.x, self.y, self.max_guesses, self.expiration,
            self.alice_sub
        )
        
        # Create mock point B for recovery
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'openadp'))
        import crypto
        
        # Alice recovers her backup
        b = crypto.G  # Mock point B
        result = server.recover_secret(
            self.db, self.uid, self.did, self.bid, b, 0, self.alice_sub
        )
        
        self.assertNotIsInstance(result, Exception)
        self.assertEqual(len(result), 6)  # Should return tuple with 6 elements
    
    def test_recover_secret_non_owner_denied(self):
        """Test that a non-owner cannot recover someone else's backup."""
        # Alice registers a backup
        server.register_secret(
            self.db, self.uid, self.did, self.bid,
            self.version, self.x, self.y, self.max_guesses, self.expiration,
            self.alice_sub
        )
        
        # Create mock point B for recovery
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'openadp'))
        import crypto
        
        # Bob tries to recover Alice's backup
        b = crypto.G  # Mock point B
        result = server.recover_secret(
            self.db, self.uid, self.did, self.bid, b, 0, self.bob_sub
        )
        
        self.assertIsInstance(result, Exception)
        self.assertIn("Access denied", str(result))
        self.assertIn(self.bob_sub, str(result))
        self.assertIn(self.alice_sub, str(result))
    
    def test_list_backups_owner_filter(self):
        """Test that list_backups only returns backups owned by the requesting user."""
        # Alice registers a backup
        server.register_secret(
            self.db, self.uid, self.did, "alice_backup",
            self.version, self.x, self.y, self.max_guesses, self.expiration,
            self.alice_sub
        )
        
        # Bob registers a different backup with same UID
        server.register_secret(
            self.db, self.uid, self.did, "bob_backup",
            self.version, 2, b'\x02' * 32, self.max_guesses, self.expiration,
            self.bob_sub
        )
        
        # Alice lists her backups
        alice_backups = server.list_backups(self.db, self.uid, self.alice_sub)
        self.assertEqual(len(alice_backups), 1)
        self.assertEqual(alice_backups[0][1], "alice_backup")  # BID is at index 1
        self.assertEqual(alice_backups[0][6], self.alice_sub)  # owner_sub at index 6
        
        # Bob lists his backups
        bob_backups = server.list_backups(self.db, self.uid, self.bob_sub)
        self.assertEqual(len(bob_backups), 1)
        self.assertEqual(bob_backups[0][1], "bob_backup")  # BID is at index 1
        self.assertEqual(bob_backups[0][6], self.bob_sub)  # owner_sub at index 6
    
    def test_database_check_ownership(self):
        """Test the database ownership checking method directly."""
        uid_bytes = self.uid.encode()
        did_bytes = self.did.encode()
        bid_bytes = self.bid.encode()
        
        # No existing backup - ownership check should pass
        self.assertTrue(self.db.check_ownership(uid_bytes, did_bytes, bid_bytes, self.alice_sub))
        
        # Alice creates a backup
        self.db.insert(uid_bytes, did_bytes, bid_bytes, self.version, self.x, self.y, 
                      0, self.max_guesses, self.expiration, self.alice_sub)
        
        # Alice should own it
        self.assertTrue(self.db.check_ownership(uid_bytes, did_bytes, bid_bytes, self.alice_sub))
        
        # Bob should not own it
        self.assertFalse(self.db.check_ownership(uid_bytes, did_bytes, bid_bytes, self.bob_sub))


if __name__ == '__main__':
    unittest.main() 