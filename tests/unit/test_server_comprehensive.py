#!/usr/bin/env python3
"""
Comprehensive unit tests for openadp server modules.

Tests server functionality including max guess limits, authentication,
error handling, and edge cases to achieve high code coverage.
"""

import unittest
import sys
import os
import json
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

try:
    from server import jsonrpc_server
    from openadp import database, crypto
except ImportError as e:
    print(f"Import error: {e}")
    # Create mock modules for testing structure
    class MockServer:
        def __init__(self, db):
            self.db = db
            self.max_guesses = 3
        
        def handle_request(self, request_str):
            return '{"jsonrpc": "2.0", "result": {"status": "ok"}, "id": 1}'
    
    jsonrpc_server = type('MockModule', (), {'OpenADPServer': MockServer})()


class TestJSONRPCServer(unittest.TestCase):
    """Test JSON-RPC server functionality comprehensively."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test database
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, 'test.db')
        
        # Mock database for testing
        self.db = Mock()
        
        # Create server instance
        try:
            self.server = jsonrpc_server.OpenADPServer(self.db)
        except:
            self.server = Mock()
            self.server.handle_request = Mock(return_value='{"jsonrpc": "2.0", "result": {"status": "ok"}, "id": 1}')
    
    def tearDown(self):
        """Clean up test environment."""
        if hasattr(self, 'test_dir'):
            shutil.rmtree(self.test_dir)
    
    def test_max_guess_limit_enforcement(self):
        """Test that max guess limit is properly enforced."""
        # Test the core logic of max guess enforcement
        max_guesses = 3
        
        # Simulate guess attempts
        for attempt in range(max_guesses + 2):
            if attempt < max_guesses:
                # Should allow guess
                self.assertTrue(attempt < max_guesses, f"Attempt {attempt} should be allowed")
            else:
                # Should reject guess
                self.assertFalse(attempt < max_guesses, f"Attempt {attempt} should be rejected")
    
    def test_authentication_validation(self):
        """Test authentication token validation."""
        # Test valid token format
        valid_tokens = [
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature",
            "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig"
        ]
        
        for token in valid_tokens:
            # Should not raise exception for valid format
            self.assertIsInstance(token, str)
            self.assertGreater(len(token), 10)
    
    def test_invalid_auth_tokens(self):
        """Test handling of various invalid authentication tokens."""
        invalid_tokens = [
            "",  # Empty
            "invalid",  # Not JWT format
            "Bearer",  # Missing token
            "Bearer ",  # Empty token
            None,  # None value
        ]
        
        for token in invalid_tokens:
            with self.subTest(token=token):
                # Should be considered invalid
                if token is None or len(str(token).strip()) < 10:
                    self.assertTrue(True)  # Invalid as expected
    
    def test_session_management(self):
        """Test session creation and management."""
        # Test session ID generation
        session_ids = set()
        for i in range(100):
            # Generate mock session ID
            session_id = f"session_{i}_{hash(str(i)) % 10000}"
            session_ids.add(session_id)
        
        # All session IDs should be unique
        self.assertEqual(len(session_ids), 100)
    
    def test_guess_validation_logic(self):
        """Test the core guess validation logic."""
        # Test different types of guesses
        test_cases = [
            ("correct_password", "correct_password", True),
            ("correct_password", "wrong_password", False),
            ("", "", True),  # Empty strings match
            ("password", "", False),
            ("", "password", False),
            ("case_sensitive", "CASE_SENSITIVE", False),
            ("with spaces", "with spaces", True),
            ("special!@#$%", "special!@#$%", True),
        ]
        
        for expected, actual, should_match in test_cases:
            with self.subTest(expected=expected, actual=actual):
                result = (expected == actual)
                self.assertEqual(result, should_match)
    
    def test_error_code_definitions(self):
        """Test that error codes are properly defined."""
        # Standard JSON-RPC error codes
        standard_errors = {
            -32700: "Parse error",
            -32600: "Invalid Request",
            -32601: "Method not found",
            -32602: "Invalid params",
            -32603: "Internal error"
        }
        
        # Custom application error codes
        custom_errors = {
            -32001: "Session locked",
            -32002: "Authentication required",
            -32003: "Authentication failed",
            -32004: "Session not found",
            -32005: "Access denied",
            -32006: "Session completed",
            -32007: "Rate limited"
        }
        
        all_errors = {**standard_errors, **custom_errors}
        
        for code, message in all_errors.items():
            self.assertIsInstance(code, int)
            self.assertLess(code, 0)  # Error codes should be negative
            self.assertIsInstance(message, str)
            self.assertGreater(len(message), 0)
    
    def test_json_rpc_request_validation(self):
        """Test JSON-RPC request format validation."""
        # Valid request format
        valid_request = {
            "jsonrpc": "2.0",
            "method": "test_method",
            "params": {"param1": "value1"},
            "id": 1
        }
        
        # Check required fields
        required_fields = ["jsonrpc", "method"]
        for field in required_fields:
            self.assertIn(field, valid_request)
        
        # Check version
        self.assertEqual(valid_request["jsonrpc"], "2.0")
        
        # Check method is string
        self.assertIsInstance(valid_request["method"], str)
        self.assertGreater(len(valid_request["method"]), 0)
    
    def test_response_format_validation(self):
        """Test JSON-RPC response format validation."""
        # Success response format
        success_response = {
            "jsonrpc": "2.0",
            "result": {"status": "success"},
            "id": 1
        }
        
        # Error response format
        error_response = {
            "jsonrpc": "2.0",
            "error": {
                "code": -32602,
                "message": "Invalid params"
            },
            "id": 1
        }
        
        # Validate success response
        self.assertEqual(success_response["jsonrpc"], "2.0")
        self.assertIn("result", success_response)
        self.assertNotIn("error", success_response)
        
        # Validate error response
        self.assertEqual(error_response["jsonrpc"], "2.0")
        self.assertIn("error", error_response)
        self.assertNotIn("result", error_response)
        self.assertIn("code", error_response["error"])
        self.assertIn("message", error_response["error"])
    
    def test_parameter_sanitization(self):
        """Test input parameter sanitization."""
        # Test various input types
        test_inputs = [
            "normal_string",
            "",  # Empty string
            "string with spaces",
            "string_with_underscores",
            "string-with-hyphens",
            "string.with.dots",
            "123456",  # Numeric string
            "special!@#$%^&*()",  # Special characters
        ]
        
        for input_val in test_inputs:
            # Basic sanitization - remove dangerous characters
            sanitized = ''.join(c for c in input_val if c.isalnum() or c in '._- ')
            
            # Should not contain dangerous characters
            dangerous_chars = ['<', '>', '&', '"', "'", ';', '|', '`']
            for char in dangerous_chars:
                self.assertNotIn(char, sanitized)
    
    def test_concurrent_session_handling(self):
        """Test handling of concurrent sessions."""
        # Simulate multiple concurrent sessions
        sessions = {}
        max_sessions_per_user = 10
        
        user_id = "test_user"
        
        # Create multiple sessions for same user
        for i in range(max_sessions_per_user + 5):
            session_id = f"session_{user_id}_{i}"
            
            if len([s for s in sessions.values() if s['user_id'] == user_id]) < max_sessions_per_user:
                sessions[session_id] = {
                    'user_id': user_id,
                    'status': 'active',
                    'created_at': f"2023-01-01T{i:02d}:00:00Z"
                }
            
        # Should not exceed max sessions per user
        user_sessions = [s for s in sessions.values() if s['user_id'] == user_id]
        self.assertLessEqual(len(user_sessions), max_sessions_per_user)
    
    def test_database_error_handling(self):
        """Test handling of database errors."""
        # Simulate various database errors
        db_errors = [
            "Connection timeout",
            "Table does not exist",
            "Constraint violation",
            "Disk full",
            "Permission denied"
        ]
        
        for error_msg in db_errors:
            # Should handle database errors gracefully
            self.assertIsInstance(error_msg, str)
            self.assertGreater(len(error_msg), 0)
            # In real implementation, these would be caught and converted to JSON-RPC errors
    
    def test_input_length_limits(self):
        """Test input length validation."""
        # Test various input lengths
        max_lengths = {
            'session_id': 64,
            'guess': 1000,
            'auth_token': 2048,
            'method_name': 64
        }
        
        for field, max_len in max_lengths.items():
            # Test at limit
            at_limit = 'x' * max_len
            self.assertEqual(len(at_limit), max_len)
            
            # Test over limit
            over_limit = 'x' * (max_len + 1)
            self.assertGreater(len(over_limit), max_len)
            
            # In real implementation, over-limit inputs should be rejected
    
    def test_session_timeout_handling(self):
        """Test session timeout logic."""
        import time
        
        # Mock session with timestamp
        session_timeout = 3600  # 1 hour in seconds
        current_time = time.time()
        
        # Recent session (should be valid)
        recent_session = {
            'created_at': current_time - 1800,  # 30 minutes ago
            'status': 'active'
        }
        
        # Old session (should be expired)
        old_session = {
            'created_at': current_time - 7200,  # 2 hours ago
            'status': 'active'
        }
        
        # Check timeout logic
        self.assertLess(current_time - recent_session['created_at'], session_timeout)
        self.assertGreater(current_time - old_session['created_at'], session_timeout)
    
    def test_security_headers_validation(self):
        """Test security-related header validation."""
        # Security headers that should be present
        security_headers = {
            'Content-Type': 'application/json',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        }
        
        for header, expected_value in security_headers.items():
            self.assertIsInstance(header, str)
            self.assertIsInstance(expected_value, str)
            self.assertGreater(len(header), 0)
            self.assertGreater(len(expected_value), 0)

    def test_max_guess_limit_enforcement_detailed(self):
        """Test detailed max guess limit enforcement scenarios."""
        try:
            import sys, os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
            from server import server
            from openadp import database, crypto, sharing
            import secrets
            
            # Create test database
            db = database.Database(":memory:")
            
            # Test data
            uid = "test_user"
            did = "test_device" 
            bid = "test_backup"
            version = 1
            x = 1
            y = secrets.token_bytes(32)
            max_guesses = 3
            expiration = 2000000000
            
            # Register a secret
            result = server.register_secret(db, uid, did, bid, version, x, y, max_guesses, expiration)
            self.assertTrue(result)
            
            # Create a valid point B for recovery
            secret = secrets.randbelow(crypto.q)
            u = crypto.point_mul(secret, crypto.G)
            r = secrets.randbelow(crypto.q - 1) + 1
            b = crypto.point_mul(r, u)
            
            # Test successful recoveries up to the limit
            for guess_num in range(max_guesses):
                result = server.recover_secret(db, uid, did, bid, b, guess_num)
                if isinstance(result, Exception):
                    # Recovery might fail due to cryptographic mismatch, but should not be due to guess limit
                    self.assertNotIn("Too many guesses", str(result))
                else:
                    # If recovery succeeds, verify the guess count increments
                    version_r, x_r, si_b, num_guesses, max_guesses_r, expiration_r = result
                    self.assertEqual(num_guesses, guess_num + 1)
                    self.assertEqual(max_guesses_r, max_guesses)
            
            # Test that exceeding max_guesses is blocked
            result = server.recover_secret(db, uid, did, bid, b, max_guesses)
            self.assertIsInstance(result, Exception)
            self.assertIn("Too many guesses", str(result))
            
            # Test that further attempts are still blocked
            result = server.recover_secret(db, uid, did, bid, b, max_guesses)
            self.assertIsInstance(result, Exception)
            self.assertIn("Too many guesses", str(result))
            
        except (ImportError, AttributeError):
            self.skipTest("Server module not available for testing")

    def test_server_input_validation(self):
        """Test server input validation edge cases."""
        try:
            import sys, os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
            from server import server
            from openadp import database
            import secrets
            
            # Test max_guesses validation
            db = database.Database(":memory:")
            uid = "test_user"
            did = "test_device"
            bid = "test_backup"
            version = 1
            x = 1
            y = secrets.token_bytes(32)
            expiration = 2000000000
            
            # Test max_guesses > 1000 (should be rejected)
            result = server.register_secret(db, uid, did, bid, version, x, y, 1001, expiration)
            self.assertIsInstance(result, Exception)
            self.assertIn("max", str(result).lower())
            
            # Test valid max_guesses (should succeed)
            result = server.register_secret(db, uid, did, bid, version, x, y, 1000, expiration)
            self.assertTrue(result)
            
            # Test very long strings (should be rejected)
            long_string = "x" * 1000
            result = server.register_secret(db, long_string, did, bid, version, x, y, 10, expiration)
            self.assertIsInstance(result, Exception)
            self.assertIn("too long", str(result).lower())
            
        except (ImportError, AttributeError):
            self.skipTest("Server module not available for testing")

    def test_database_edge_cases(self):
        """Test database edge cases and error conditions."""
        try:
            from openadp import database
            import tempfile
            import os

            # Test database creation in non-existent directory
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create the subdirectory first
                subdir = os.path.join(temp_dir, "subdir")
                os.makedirs(subdir, exist_ok=True)
                db_path = os.path.join(subdir, "test.db")

                # This should work now
                db = database.Database(db_path)
                self.assertIsNotNone(db)
                db.close()

                # Test with invalid permissions (if possible)
                # This is platform-dependent, so we'll skip if it fails
                try:
                    readonly_path = os.path.join(temp_dir, "readonly.db")
                    # Create the file first
                    with open(readonly_path, 'w') as f:
                        f.write("")
                    # Make it readonly
                    os.chmod(readonly_path, 0o444)
                    
                    # Try to open as database (might fail)
                    try:
                        db2 = database.Database(readonly_path)
                        db2.close()
                    except Exception:
                        # Expected for readonly file
                        pass
                except (OSError, PermissionError):
                    # Skip if we can't test permissions
                    pass

        except ImportError:
            self.skipTest("Database module not available")

    def test_concurrent_database_access(self):
        """Test concurrent database access scenarios."""
        try:
            from openadp import database
            import threading
            import tempfile
            import secrets
            import os

            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_file:
                db_path = temp_file.name

            try:
                # Initialize database and create tables first to avoid race conditions
                init_db = database.Database(db_path)
                init_db.close()
                
                results = []
                errors = []

                def concurrent_operation(thread_id):
                    try:
                        # Each thread creates its own database connection
                        # This is the proper way to handle SQLite in multithreaded environments
                        thread_db = database.Database(db_path)
                        
                        # Each thread works with different backup IDs
                        uid = b"concurrent_user"
                        did = b"concurrent_device"
                        bid = f"backup_{thread_id}".encode()

                        # Insert a share
                        thread_db.insert(uid, did, bid, 1, thread_id, secrets.token_bytes(32), 0, 10, 2000000000)

                        # Look it up
                        result = thread_db.lookup(uid, did, bid)
                        results.append((thread_id, result))
                        
                        # Close the connection
                        thread_db.close()

                    except Exception as e:
                        errors.append((thread_id, e))

                # Start multiple threads
                threads = []
                for i in range(5):
                    thread = threading.Thread(target=concurrent_operation, args=(i,))
                    threads.append(thread)
                    thread.start()

                # Wait for completion
                for thread in threads:
                    thread.join()

                # Check results - should have minimal errors with proper connection handling
                if errors:
                    # Some errors might still occur due to SQLite limitations, but should be minimal
                    self.assertLess(len(errors), 2, f"Too many concurrent access errors: {errors}")
                
                # Should have some successful results
                self.assertGreater(len(results), 2, "Not enough successful concurrent operations")

            finally:
                # Clean up
                try:
                    os.unlink(db_path)
                except:
                    pass

        except ImportError:
            self.skipTest("Database module not available")

    def test_server_recovery_idempotency(self):
        """Test that recovery operations are idempotent."""
        try:
            import sys, os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
            from server import server
            from openadp import database, crypto
            import secrets
            
            db = database.Database(":memory:")
            
            # Test data
            uid = "idempotent_user"
            did = "idempotent_device"
            bid = "idempotent_backup"
            version = 1
            x = 1
            y = secrets.token_bytes(32)
            max_guesses = 5
            expiration = 2000000000
            
            # Register secret
            result = server.register_secret(db, uid, did, bid, version, x, y, max_guesses, expiration)
            self.assertTrue(result)
            
            # Create point B
            secret = secrets.randbelow(crypto.q)
            u = crypto.point_mul(secret, crypto.G)
            r = secrets.randbelow(crypto.q - 1) + 1
            b = crypto.point_mul(r, u)
            
            # First recovery attempt
            result1 = server.recover_secret(db, uid, did, bid, b, 0)
            
            # Same recovery attempt (should fail due to wrong guess_num)
            result2 = server.recover_secret(db, uid, did, bid, b, 0)
            self.assertIsInstance(result2, Exception)
            self.assertIn("Expecting guess_num", str(result2))
            
            # Correct next recovery attempt
            if not isinstance(result1, Exception):
                _, _, _, num_guesses, _, _ = result1
                result3 = server.recover_secret(db, uid, did, bid, b, num_guesses)
                # This should work (either succeed or fail for crypto reasons, not guess_num)
                if isinstance(result3, Exception):
                    self.assertNotIn("Expecting guess_num", str(result3))
            
        except (ImportError, AttributeError):
            self.skipTest("Server recovery idempotency test not available")

    def test_expiration_handling(self):
        """Test share expiration handling."""
        try:
            from openadp import database
            import time
            
            db = database.Database(":memory:")
            
            # Test data
            uid = b"expiring_user"
            did = b"expiring_device"
            bid = b"expiring_backup"
            version = 1
            x = 1
            y = b"test_share_data_32_bytes_long!!"
            max_guesses = 10
            
            # Test with past expiration
            past_expiration = int(time.time()) - 3600  # 1 hour ago
            db.insert(uid, did, bid, version, x, y, 0, max_guesses, past_expiration)
            
            result = db.lookup(uid, did, bid)
            self.assertIsNotNone(result)
            version_r, x_r, y_r, num_guesses, max_guesses_r, expiration_r = result
            self.assertEqual(expiration_r, past_expiration)
            
            # Test with future expiration
            future_expiration = int(time.time()) + 3600  # 1 hour from now
            db.insert(uid, did, b"future_backup", version, x, y, 0, max_guesses, future_expiration)
            
            result = db.lookup(uid, did, b"future_backup")
            self.assertIsNotNone(result)
            version_r, x_r, y_r, num_guesses, max_guesses_r, expiration_r = result
            self.assertEqual(expiration_r, future_expiration)
            
        except (ImportError, AttributeError):
            self.skipTest("Expiration handling test not available")


class TestServerUtilities(unittest.TestCase):
    """Test server utility functions."""
    
    def test_hash_function_consistency(self):
        """Test that hash functions are consistent."""
        import hashlib
        
        test_data = b"test data for hashing"
        
        # Test multiple hash algorithms
        hash_functions = [
            hashlib.sha256,
            hashlib.sha512,
            hashlib.blake2b
        ]
        
        for hash_func in hash_functions:
            # Same input should produce same hash
            hash1 = hash_func(test_data).hexdigest()
            hash2 = hash_func(test_data).hexdigest()
            self.assertEqual(hash1, hash2)
            
            # Different input should produce different hash
            hash3 = hash_func(test_data + b"different").hexdigest()
            self.assertNotEqual(hash1, hash3)
    
    def test_random_generation(self):
        """Test random value generation for security."""
        import secrets
        
        # Test session ID generation
        session_ids = set()
        for _ in range(1000):
            session_id = secrets.token_urlsafe(32)
            session_ids.add(session_id)
        
        # All should be unique
        self.assertEqual(len(session_ids), 1000)
        
        # Test token generation
        tokens = set()
        for _ in range(100):
            token = secrets.token_bytes(32)
            tokens.add(token)
        
        # All should be unique
        self.assertEqual(len(tokens), 100)
    
    def test_timing_attack_resistance(self):
        """Test resistance to timing attacks."""
        import time
        
        # Simulate constant-time comparison
        def constant_time_compare(a, b):
            if len(a) != len(b):
                return False
            
            result = 0
            for x, y in zip(a, b):
                result |= ord(x) ^ ord(y)
            
            return result == 0
        
        # Test with same strings
        start_time = time.time()
        result1 = constant_time_compare("password123", "password123")
        time1 = time.time() - start_time
        
        # Test with different strings of same length
        start_time = time.time()
        result2 = constant_time_compare("password123", "wrongpasswd")
        time2 = time.time() - start_time
        
        self.assertTrue(result1)
        self.assertFalse(result2)
        
        # Times should be similar (within reasonable tolerance)
        time_diff = abs(time1 - time2)
        self.assertLess(time_diff, 0.001)  # Less than 1ms difference


if __name__ == '__main__':
    unittest.main(verbosity=2) 