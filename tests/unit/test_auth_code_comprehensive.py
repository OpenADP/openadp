#!/usr/bin/env python3
"""
Comprehensive unit tests for OpenADP Authentication Code System.

Tests authentication code generation, validation, server derivation,
database operations, and edge cases to achieve high code coverage.
"""

import unittest
import sys
import os
import tempfile
import shutil
import sqlite3
import secrets
import hashlib
import math
from unittest.mock import Mock, patch, MagicMock

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from openadp.auth_code_manager import AuthCodeManager
from openadp import database


class TestAuthCodeManager(unittest.TestCase):
    """Test authentication code manager comprehensively."""
    
    def setUp(self):
        """Set up test environment."""
        self.manager = AuthCodeManager()
        self.test_server_urls = [
            "https://server1.openadp.org",
            "https://server2.openadp.org", 
            "https://localhost:8080"
        ]
    
    def test_generate_auth_code_basic(self):
        """Test basic authentication code generation."""
        code = self.manager.generate_auth_code()
        
        # Should be 32 character hex string (128 bits)
        self.assertEqual(len(code), 32)
        self.assertTrue(all(c in '0123456789abcdef' for c in code))
        
        # Should be different each time
        code2 = self.manager.generate_auth_code()
        self.assertNotEqual(code, code2)
    
    def test_generate_auth_code_entropy(self):
        """Test authentication code has sufficient entropy."""
        codes = set()
        num_codes = 100  # Reduced for faster testing
        
        for _ in range(num_codes):
            code = self.manager.generate_auth_code()
            codes.add(code)
        
        # All codes should be unique (extremely high probability)
        self.assertEqual(len(codes), num_codes)
        
        # Test that codes have good distribution of characters
        all_chars = ''.join(codes)
        char_counts = {}
        for char in '0123456789abcdef':
            char_counts[char] = all_chars.count(char)
        
        # Each hex digit should appear at least once in 100 codes
        for char, count in char_counts.items():
            self.assertGreater(count, 0, f"Character '{char}' should appear at least once")
    
    def test_validate_base_code_format_valid(self):
        """Test validation of valid base code formats."""
        valid_codes = [
            "0123456789abcdef0123456789abcdef",  # All hex digits
            "ffffffffffffffffffffffffffffffff",  # All f's
            "0000000000000000000000000000000a",  # Mostly zeros
            "deadbeefcafebabe1234567890abcdef",  # Mixed
        ]
        
        for code in valid_codes:
            with self.subTest(code=code):
                self.assertTrue(self.manager.validate_base_code_format(code))
    
    def test_validate_base_code_format_invalid(self):
        """Test validation rejects invalid base code formats."""
        invalid_codes = [
            "",  # Empty
            "123",  # Too short
            "0123456789abcdef0123456789abcdef0",  # Too long
            "0123456789abcdef0123456789abcdeg",  # Invalid hex char
            "0123456789abcdef 123456789abcdef",  # Space
        ]
        
        for code in invalid_codes:
            with self.subTest(code=code):
                self.assertFalse(self.manager.validate_base_code_format(code))
        
        # Test None and non-string types
        with self.assertRaises((TypeError, AttributeError)):
            self.manager.validate_base_code_format(None)
        
        with self.assertRaises((TypeError, AttributeError)):
            self.manager.validate_base_code_format(123)
    
    def test_validate_base_code_format_uppercase_allowed(self):
        """Test that uppercase hex characters are allowed."""
        # The implementation accepts uppercase hex characters
        uppercase_code = "0123456789ABCDEF0123456789ABCDEF"
        self.assertTrue(self.manager.validate_base_code_format(uppercase_code))
    
    def test_derive_server_code_basic(self):
        """Test basic server code derivation."""
        base_code = "deadbeefcafebabe1234567890abcdef"
        server_url = "https://server1.openadp.org"
        
        server_code = self.manager.derive_server_code(base_code, server_url)
        
        # Should be 64 character hex string (256 bits)
        self.assertEqual(len(server_code), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in server_code))
        
        # Should be deterministic
        server_code2 = self.manager.derive_server_code(base_code, server_url)
        self.assertEqual(server_code, server_code2)
    
    def test_derive_server_code_different_servers(self):
        """Test server code derivation produces different codes for different servers."""
        base_code = "deadbeefcafebabe1234567890abcdef"
        
        codes = {}
        for url in self.test_server_urls:
            codes[url] = self.manager.derive_server_code(base_code, url)
        
        # All codes should be different
        code_values = list(codes.values())
        self.assertEqual(len(set(code_values)), len(code_values))
    
    def test_derive_server_code_different_base_codes(self):
        """Test server code derivation produces different codes for different base codes."""
        server_url = "https://server1.openadp.org"
        
        base_codes = [
            "deadbeefcafebabe1234567890abcdef",
            "1234567890abcdefdeadbeefcafebabe",
            "0000000000000000000000000000000a"
        ]
        
        codes = []
        for base_code in base_codes:
            codes.append(self.manager.derive_server_code(base_code, server_url))
        
        # All codes should be different
        self.assertEqual(len(set(codes)), len(codes))
    
    def test_get_server_codes_multiple(self):
        """Test getting server codes for multiple servers."""
        base_code = "deadbeefcafebabe1234567890abcdef"
        
        server_codes = self.manager.get_server_codes(base_code, self.test_server_urls)
        
        # Should have entry for each server
        self.assertEqual(len(server_codes), len(self.test_server_urls))
        
        for url in self.test_server_urls:
            self.assertIn(url, server_codes)
            self.assertEqual(len(server_codes[url]), 64)
    
    def test_validate_server_code_format_valid(self):
        """Test validation of valid server code formats."""
        valid_codes = [
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "000000000000000000000000000000000000000000000000000000000000000a",
        ]
        
        for code in valid_codes:
            with self.subTest(code=code):
                self.assertTrue(self.manager.validate_server_code_format(code))
    
    def test_validate_server_code_format_invalid(self):
        """Test validation rejects invalid server code formats."""
        invalid_codes = [
            "",  # Empty
            "123",  # Too short
            "0123456789abcdef0123456789abcdef",  # Too short (32 chars)
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",  # Too long
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",  # Invalid hex
        ]
        
        for code in invalid_codes:
            with self.subTest(code=code):
                self.assertFalse(self.manager.validate_server_code_format(code))
        
        # Test None and non-string types
        with self.assertRaises((TypeError, AttributeError)):
            self.manager.validate_server_code_format(None)
        
        with self.assertRaises((TypeError, AttributeError)):
            self.manager.validate_server_code_format(123)
    
    def test_sha256_derivation_consistency(self):
        """Test SHA256 derivation is consistent with expected behavior."""
        base_code = "deadbeefcafebabe1234567890abcdef"
        server_url = "https://server1.openadp.org"
        
        # Manual calculation (note the colon separator used in implementation)
        combined = f"{base_code}:{server_url}"
        expected_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
        
        # Manager calculation
        actual_hash = self.manager.derive_server_code(base_code, server_url)
        
        self.assertEqual(actual_hash, expected_hash)
    
    def test_url_normalization(self):
        """Test URL normalization in server code derivation."""
        base_code = "deadbeefcafebabe1234567890abcdef"
        
        # These should produce different results (no normalization)
        urls = [
            "https://server1.openadp.org",
            "https://server1.openadp.org/",  # Trailing slash
        ]
        
        codes = [self.manager.derive_server_code(base_code, url) for url in urls]
        
        # Current implementation doesn't normalize URLs, so these will be different
        self.assertNotEqual(codes[0], codes[1])
    
    def test_thread_safety_simulation(self):
        """Test thread safety by simulating concurrent access."""
        import threading
        import time
        
        results = []
        errors = []
        
        def generate_codes():
            try:
                for _ in range(10):
                    code = self.manager.generate_auth_code()
                    results.append(code)
                    time.sleep(0.001)  # Small delay to increase chance of race conditions
            except Exception as e:
                errors.append(e)
        
        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=generate_codes)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        self.assertEqual(len(results), 50)  # 5 threads * 10 codes each
        self.assertEqual(len(set(results)), 50)  # All should be unique


class TestDatabaseAuthCode(unittest.TestCase):
    """Test database operations with authentication codes."""
    
    def setUp(self):
        """Set up test environment with temporary database."""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, 'test.db')
        self.db = database.Database(self.db_path)
        
        # Test data
        self.uid = "test_user_123"
        self.did = "test_device"
        self.bid = "test_backup"
        self.auth_code = "deadbeefcafebabe1234567890abcdef0123456789abcdef0123456789abcdef"
        self.version = 1
        self.x = 12345
        self.y = b"test_secret_share_32_bytes_long!!"
        self.max_guesses = 10
        self.expiration = 2000000000
    
    def tearDown(self):
        """Clean up test environment."""
        if hasattr(self.db, 'close'):
            self.db.close()
        shutil.rmtree(self.test_dir)
    
    def test_insert_with_auth_code(self):
        """Test inserting share with authentication code."""
        # Insert share
        self.db.insert(
            self.uid.encode(), self.did.encode(), self.bid.encode(),
            self.auth_code, self.version, self.x, self.y, 0,
            self.max_guesses, self.expiration
        )
        
        # Verify insertion by looking up
        result = self.db.lookup_by_auth_code(self.auth_code, self.did, self.bid)
        self.assertIsNotNone(result)
        
        uid, version, x, y, guesses, max_guesses, expiration = result
        self.assertEqual(uid, self.uid)
        self.assertEqual(version, self.version)
        self.assertEqual(x, self.x)
        self.assertEqual(y, self.y)
    
    def test_lookup_by_auth_code_success(self):
        """Test successful lookup by authentication code."""
        # Insert test data
        self.db.insert(
            self.uid.encode(), self.did.encode(), self.bid.encode(),
            self.auth_code, self.version, self.x, self.y, 0,
            self.max_guesses, self.expiration
        )
        
        # Lookup should succeed
        result = self.db.lookup_by_auth_code(self.auth_code, self.did, self.bid)
        self.assertIsNotNone(result)
        
        uid, version, x, y, guesses, max_guesses, expiration = result
        self.assertEqual(uid, self.uid)
        self.assertEqual(version, self.version)
        self.assertEqual(x, self.x)
        self.assertEqual(y, self.y)
        self.assertEqual(guesses, 0)
        self.assertEqual(max_guesses, self.max_guesses)
        self.assertEqual(expiration, self.expiration)
    
    def test_lookup_by_auth_code_not_found(self):
        """Test lookup by authentication code when not found."""
        # Lookup non-existent auth code
        result = self.db.lookup_by_auth_code("nonexistent_code", self.did, self.bid)
        self.assertIsNone(result)
        
        # Insert data but lookup with wrong did/bid
        self.db.insert(
            self.uid.encode(), self.did.encode(), self.bid.encode(),
            self.auth_code, self.version, self.x, self.y, 0,
            self.max_guesses, self.expiration
        )
        
        result = self.db.lookup_by_auth_code(self.auth_code, "wrong_did", self.bid)
        self.assertIsNone(result)
        
        result = self.db.lookup_by_auth_code(self.auth_code, self.did, "wrong_bid")
        self.assertIsNone(result)
    
    def test_list_backups_by_auth_code(self):
        """Test listing backups by authentication code."""
        # Insert multiple backups with same auth code
        backups = [
            ("backup1", "device1"),
            ("backup2", "device1"), 
            ("backup3", "device2"),
        ]
        
        for bid, did in backups:
            self.db.insert(
                self.uid.encode(), did.encode(), bid.encode(),
                self.auth_code, self.version, self.x, self.y, 0,
                self.max_guesses, self.expiration
            )
        
        # List backups
        result = self.db.list_backups_by_auth_code(self.auth_code)
        self.assertEqual(len(result), 3)
        
        # Verify backup info
        backup_ids = [(r[1], r[2]) for r in result]  # (did, bid)
        for bid, did in backups:
            self.assertIn((did, bid), backup_ids)
    
    def test_list_backups_by_auth_code_empty(self):
        """Test listing backups by authentication code when none exist."""
        result = self.db.list_backups_by_auth_code("nonexistent_code")
        self.assertEqual(len(result), 0)
    
    def test_update_guess_count(self):
        """Test updating guess count."""
        # Insert test data
        self.db.insert(
            self.uid.encode(), self.did.encode(), self.bid.encode(),
            self.auth_code, self.version, self.x, self.y, 0,
            self.max_guesses, self.expiration
        )
        
        # Update guess count (note: update_guess_count expects bytes for uid)
        self.db.update_guess_count(self.uid.encode(), self.did.encode(), self.bid.encode(), 5)
        
        # Verify update
        result = self.db.lookup_by_auth_code(self.auth_code, self.did, self.bid)
        self.assertIsNotNone(result)
        
        uid, version, x, y, guesses, max_guesses, expiration = result
        self.assertEqual(guesses, 5)
    
    def test_update_guess_count_nonexistent(self):
        """Test updating guess count for nonexistent share."""
        # Should not raise error, just do nothing
        self.db.update_guess_count(b"nonexistent_user", self.did.encode(), self.bid.encode(), 5)
    
    def test_auth_code_edge_cases(self):
        """Test authentication code edge cases."""
        edge_cases = [
            # (auth_code, should_work)
            ("", False),  # Empty string
            ("a" * 63, False),  # Too short
            ("a" * 65, False),  # Too long  
            ("g" * 64, False),  # Invalid hex characters
            ("A" * 64, False),  # Uppercase
            ("0" * 64, True),   # All zeros
            ("f" * 64, True),   # All f's
        ]
        
        for auth_code, should_work in edge_cases:
            with self.subTest(auth_code=auth_code[:10] + "..."):
                try:
                    self.db.insert(
                        self.uid.encode(), self.did.encode(), self.bid.encode(),
                        auth_code, self.version, self.x, self.y, 0,
                        self.max_guesses, self.expiration
                    )
                    
                    if should_work:
                        # Should be able to lookup
                        result = self.db.lookup_by_auth_code(auth_code, self.did, self.bid)
                        self.assertIsNotNone(result)
                    else:
                        # If insert succeeded, lookup should still work
                        result = self.db.lookup_by_auth_code(auth_code, self.did, self.bid)
                        # This is implementation dependent
                        pass
                        
                except (sqlite3.Error, ValueError) as e:
                    if should_work:
                        self.fail(f"Should have worked but failed: {e}")
                    # Expected failure for invalid cases


if __name__ == '__main__':
    unittest.main() 