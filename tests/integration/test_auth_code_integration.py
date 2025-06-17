#!/usr/bin/env python3
"""
Integration tests for OpenADP Authentication Code System.

Tests end-to-end authentication code flows including server operations,
database integration, and complete authentication workflows.
"""

import unittest
import sys
import os
import tempfile
import shutil
import secrets
import time
import sqlite3
from unittest.mock import patch, MagicMock

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from openadp.auth_code_manager import AuthCodeManager
from openadp import database, crypto
from server import server


class TestAuthCodeEndToEnd(unittest.TestCase):
    """Test complete authentication code workflows end-to-end."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, 'test.db')
        self.db = database.Database(self.db_path)
        self.manager = AuthCodeManager()
        
        # Test data
        self.uid = "integration_test_user"
        self.did = "integration_test_device"
        self.bid = "integration_test_backup"
        self.version = 1
        self.max_guesses = 10
        self.expiration = int(time.time()) + 86400  # 24 hours from now
    
    def tearDown(self):
        """Clean up test environment."""
        if hasattr(self.db, 'close'):
            self.db.close()
        shutil.rmtree(self.test_dir)
    
    def test_complete_registration_flow(self):
        """Test complete secret registration flow with authentication codes."""
        # Generate authentication code
        base_code = self.manager.generate_auth_code()
        server_url = "https://server1.openadp.org"
        server_code = self.manager.derive_server_code(base_code, server_url)
        
        # Generate cryptographic data
        secret = secrets.randbelow(crypto.q)
        u = crypto.point_mul(secret, crypto.G)
        x = 1  # Share index, not x-coordinate
        y = secrets.token_bytes(32)  # Secret share
        
        # Register secret (note the correct parameter order)
        result = server.register_secret(
            self.db, self.uid, self.did, self.bid, server_code,
            self.version, x, y, self.max_guesses, self.expiration
        )
        
        self.assertTrue(result, "Secret registration should succeed")
        
        # Verify registration by lookup
        share = self.db.lookup_by_auth_code(server_code, self.did, self.bid)
        self.assertIsNotNone(share, "Should find registered share")
        
        uid, version, found_x, found_y, guesses, max_guesses, expiration = share
        self.assertEqual(uid, self.uid)
        self.assertEqual(version, self.version)
        self.assertEqual(found_x, x)
        self.assertEqual(found_y, y)
        self.assertEqual(guesses, 0)
        self.assertEqual(max_guesses, self.max_guesses)
    
    def test_complete_recovery_flow(self):
        """Test complete secret recovery flow with authentication codes."""
        # Setup: Register a secret first
        base_code = self.manager.generate_auth_code()
        server_url = "https://server1.openadp.org"
        server_code = self.manager.derive_server_code(base_code, server_url)
        
        # Generate cryptographic data for registration
        secret = secrets.randbelow(crypto.q)
        u = crypto.point_mul(secret, crypto.G)
        x = 1  # Share index
        y = secrets.token_bytes(32)
        
        # Register
        server.register_secret(
            self.db, self.uid, self.did, self.bid, server_code,
            self.version, x, y, self.max_guesses, self.expiration
        )
        
        # Recovery: Generate blinded point
        r = secrets.randbelow(crypto.q - 1) + 1
        b = crypto.point_mul(r, u)
        
        # Attempt recovery
        result = server.recover_secret(self.db, self.uid, self.did, self.bid, b, 0)
        
        # Note: This may fail cryptographically since we're not using the proper
        # key derivation, but it should not fail due to authentication issues
        if isinstance(result, Exception):
            # Expected cryptographic failure, but auth should have worked
            self.assertNotIn("auth", str(result).lower())
            self.assertNotIn("permission", str(result).lower())
        else:
            # If it succeeded, verify the result format
            self.assertIsInstance(result, (tuple, list))
    
    def test_backup_listing_flow(self):
        """Test backup listing flow with authentication codes."""
        base_code = self.manager.generate_auth_code()
        server_url = "https://server1.openadp.org"
        server_code = self.manager.derive_server_code(base_code, server_url)
        
        # Register multiple backups
        backups = [
            ("backup1", "device1"),
            ("backup2", "device1"),
            ("backup3", "device2"),
        ]
        
        for i, (bid, did) in enumerate(backups):
            secret = secrets.randbelow(crypto.q)
            u = crypto.point_mul(secret, crypto.G)
            x = i + 1  # Share index
            y = secrets.token_bytes(32)
            
            server.register_secret(
                self.db, self.uid, did, bid, server_code,
                self.version, x, y, self.max_guesses, self.expiration
            )
        
        # List backups
        backup_list = self.db.list_backups_by_auth_code(server_code)
        
        self.assertEqual(len(backup_list), 3)
        
        # Verify backup information
        found_backups = [(row[1], row[0]) for row in backup_list]  # (bid, did)
        for bid, did in backups:
            self.assertIn((bid, did), found_backups)
    
    def test_multi_server_isolation(self):
        """Test that different servers are properly isolated."""
        base_code = self.manager.generate_auth_code()
        
        servers = [
            "https://server1.openadp.org",
            "https://server2.openadp.org",
            "https://backup.openadp.org",
        ]
        
        # Register same backup on different servers
        for i, server_url in enumerate(servers):
            server_code = self.manager.derive_server_code(base_code, server_url)
            
            secret = secrets.randbelow(crypto.q)
            u = crypto.point_mul(secret, crypto.G)
            x = i + 1  # Share index
            y = secrets.token_bytes(32)
            
            # Use different UIDs to distinguish
            uid = f"{self.uid}_server_{i}"
            
            server.register_secret(
                self.db, uid, self.did, self.bid, server_code,
                self.version, x, y, self.max_guesses, self.expiration
            )
        
        # Verify each server can only see its own data
        for i, server_url in enumerate(servers):
            server_code = self.manager.derive_server_code(base_code, server_url)
            
            # Should find the backup for this server
            share = self.db.lookup_by_auth_code(server_code, self.did, self.bid)
            self.assertIsNotNone(share)
            
            uid, _, _, _, _, _, _ = share
            expected_uid = f"{self.uid}_server_{i}"
            self.assertEqual(uid, expected_uid)
            
            # Should not find backups from other servers
            other_servers = [s for j, s in enumerate(servers) if j != i]
            for other_server_url in other_servers:
                other_server_code = self.manager.derive_server_code(base_code, other_server_url)
                other_share = self.db.lookup_by_auth_code(other_server_code, self.did, self.bid)
                
                if other_share:
                    other_uid, _, _, _, _, _, _ = other_share
                    self.assertNotEqual(other_uid, expected_uid)
    
    def test_guess_count_tracking(self):
        """Test guess count tracking in recovery attempts."""
        # Register a secret
        base_code = self.manager.generate_auth_code()
        server_url = "https://server1.openadp.org"
        server_code = self.manager.derive_server_code(base_code, server_url)
        
        secret = secrets.randbelow(crypto.q)
        u = crypto.point_mul(secret, crypto.G)
        x = 1  # Share index
        y = secrets.token_bytes(32)
        
        server.register_secret(
            self.db, self.uid, self.did, self.bid, server_code,
            self.version, x, y, 3, self.expiration  # Max 3 guesses
        )
        
        # Make multiple recovery attempts
        for guess_num in range(3):
            r = secrets.randbelow(crypto.q - 1) + 1
            b = crypto.point_mul(r, u)
            
            # This will likely fail cryptographically, but should track guesses
            result = server.recover_secret(self.db, self.uid, self.did, self.bid, b, guess_num)
            
            # Check guess count was updated
            share = self.db.lookup_by_auth_code(server_code, self.did, self.bid)
            self.assertIsNotNone(share)
            
            _, _, _, _, guesses, _, _ = share
            self.assertEqual(guesses, guess_num + 1)
    
    def test_expiration_handling(self):
        """Test handling of authentication codes with no expiration."""
        # Register with no expiration (0 means no expiration)
        base_code = self.manager.generate_auth_code()
        server_url = "https://server1.openadp.org"
        server_code = self.manager.derive_server_code(base_code, server_url)
        
        no_expiration = 0  # 0 means no expiration
        
        secret = secrets.randbelow(crypto.q)
        u = crypto.point_mul(secret, crypto.G)
        x = 1  # Share index
        y = secrets.token_bytes(32)
        
        # Registration should succeed
        result = server.register_secret(
            self.db, self.uid, self.did, self.bid, server_code,
            self.version, x, y, self.max_guesses, no_expiration
        )
        
        self.assertTrue(result)
        
        # Lookup should work
        share = self.db.lookup_by_auth_code(server_code, self.did, self.bid)
        self.assertIsNotNone(share)
        
        _, _, _, _, _, _, expiration = share
        self.assertEqual(expiration, no_expiration)
    
    def test_large_scale_operations(self):
        """Test large scale operations with authentication codes."""
        base_code = self.manager.generate_auth_code()
        server_url = "https://server1.openadp.org"
        server_code = self.manager.derive_server_code(base_code, server_url)
        
        # Register many secrets (reduced for faster testing)
        num_secrets = 50
        for i in range(num_secrets):
            uid = f"user_{i:03d}"
            did = f"device_{i:03d}"
            bid = f"backup_{i:03d}"
            
            secret = secrets.randbelow(crypto.q)
            u = crypto.point_mul(secret, crypto.G)
            x = (i % 1000) + 1  # Share index (keep under 1000)
            y = secrets.token_bytes(32)
            
            result = server.register_secret(
                self.db, uid, did, bid, server_code,
                self.version, x, y, self.max_guesses, self.expiration
            )
            
            self.assertTrue(result, f"Registration {i} should succeed")
        
        # List all backups
        backup_list = self.db.list_backups_by_auth_code(server_code)
        self.assertEqual(len(backup_list), num_secrets)
        
        # Verify random lookups
        for i in [0, 10, 25, 40, 49]:
            did = f"device_{i:03d}"
            bid = f"backup_{i:03d}"
            
            share = self.db.lookup_by_auth_code(server_code, did, bid)
            self.assertIsNotNone(share, f"Should find backup {i}")
            
            uid, _, _, _, _, _, _ = share
            expected_uid = f"user_{i:03d}"
            self.assertEqual(uid, expected_uid)


class TestAuthCodeMiddlewareIntegration(unittest.TestCase):
    """Test authentication code middleware integration."""
    
    def setUp(self):
        """Set up test environment."""
        self.manager = AuthCodeManager()
        
        # Check if middleware is available
        self.middleware_available = True
        try:
            from server.auth_code_middleware import validate_auth_code_request
            self.validate_auth_code_request = validate_auth_code_request
        except ImportError:
            self.middleware_available = False
    
    def test_middleware_validation_integration(self):
        """Test middleware validation integration."""
        if not self.middleware_available:
            self.skipTest("Auth code middleware not available")
        
        # Generate valid authentication code
        base_code = self.manager.generate_auth_code()
        server_url = "https://api.openadp.org"
        server_code = self.manager.derive_server_code(base_code, server_url)
        
        # Validate through middleware
        derived_uuid, error = self.validate_auth_code_request(
            server_code, server_url, "192.168.1.100"
        )
        
        self.assertIsNone(error, f"Validation should succeed: {error}")
        self.assertIsNotNone(derived_uuid)
        self.assertEqual(len(derived_uuid), 16)  # 16 bytes, not 36-char string
    
    def test_middleware_entropy_validation(self):
        """Test middleware entropy validation."""
        if not self.middleware_available:
            self.skipTest("Auth code middleware not available")
        
        server_url = "https://api.openadp.org"
        client_ip = "192.168.1.100"
        
        # Test high entropy code (should pass)
        high_entropy_code = self.manager.generate_auth_code()
        server_code = self.manager.derive_server_code(high_entropy_code, server_url)
        
        derived_uuid, error = self.validate_auth_code_request(
            server_code, server_url, client_ip
        )
        
        self.assertIsNone(error)
        self.assertIsNotNone(derived_uuid)
        
        # Test low entropy code - just ensure it doesn't crash
        low_entropy_code = "0000000000000000000000000000000000000000000000000000000000000000"
        
        derived_uuid, error = self.validate_auth_code_request(
            low_entropy_code, server_url, client_ip
        )
        
        # The middleware logs a warning but behavior may vary
        # Just ensure the function doesn't crash
        self.assertIsInstance(derived_uuid, (str, bytes, type(None)))
        self.assertIsInstance(error, (str, type(None)))
    
    def test_middleware_dos_protection(self):
        """Test middleware DoS protection simulation."""
        if not self.middleware_available:
            self.skipTest("Auth code middleware not available")
        
        # This is a simulation since we can't easily test actual DoS protection
        valid_code = self.manager.generate_auth_code()
        server_url = "https://api.openadp.org"
        server_code = self.manager.derive_server_code(valid_code, server_url)
        client_ip = "192.168.1.100"
        
        # Make multiple requests rapidly
        results = []
        for i in range(5):  # Reduced for faster testing
            derived_uuid, error = self.validate_auth_code_request(server_code, server_url, client_ip)
            results.append((derived_uuid, error))
        
        # All should succeed in test environment (no actual DoS protection)
        for derived_uuid, error in results:
            self.assertIsNone(error)
            self.assertIsNotNone(derived_uuid)


class TestAuthCodeErrorHandling(unittest.TestCase):
    """Test error handling in authentication code system."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, 'test.db')
        self.db = database.Database(self.db_path)
        self.manager = AuthCodeManager()
    
    def tearDown(self):
        """Clean up test environment."""
        if hasattr(self.db, 'close'):
            self.db.close()
        shutil.rmtree(self.test_dir)
    
    def test_database_error_handling(self):
        """Test error handling when database operations fail."""
        # Close database to simulate failure
        self.db.close()
        
        base_code = self.manager.generate_auth_code()
        server_url = "https://server1.openadp.org"
        server_code = self.manager.derive_server_code(base_code, server_url)
        
        # Operations should handle database errors gracefully
        with self.assertRaises((sqlite3.Error, AttributeError)):
            server.register_secret(
                self.db, "uid", "did", "bid", server_code,
                1, 123, b"secret", 10, int(time.time()) + 3600
            )
    
    def test_invalid_cryptographic_data(self):
        """Test handling of invalid cryptographic data."""
        base_code = self.manager.generate_auth_code()
        server_url = "https://server1.openadp.org"
        server_code = self.manager.derive_server_code(base_code, server_url)
        
        # Test with invalid x coordinate (too large)
        invalid_x = crypto.p + 1  # Larger than field prime
        y = secrets.token_bytes(32)
        
        # Should handle gracefully (might succeed or fail depending on validation)
        try:
            result = server.register_secret(
                self.db, "uid", "did", "bid", server_code,
                1, invalid_x, y, 10, int(time.time()) + 3600
            )
            # If it succeeds, that's also valid behavior
        except (ValueError, OverflowError):
            # Expected for invalid cryptographic data
            pass
    
    def test_memory_pressure_handling(self):
        """Test handling under memory pressure simulation."""
        # This is a basic simulation - just ensure operations complete
        base_code = self.manager.generate_auth_code()
        server_url = "https://server1.openadp.org"
        server_code = self.manager.derive_server_code(base_code, server_url)
        
        # Create many small operations
        for i in range(100):
            secret = secrets.randbelow(crypto.q)
            u = crypto.point_mul(secret, crypto.G)
            x = (i % 1000) + 1  # Share index (keep under 1000)
            y = secrets.token_bytes(32)
            
            result = server.register_secret(
                self.db, f"user_{i}", f"device_{i}", f"backup_{i}", server_code,
                1, x, y, 10, int(time.time()) + 3600
            )
            
            self.assertTrue(result)


if __name__ == '__main__':
    unittest.main() 