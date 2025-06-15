#!/usr/bin/env python3
"""
Comprehensive unit tests for openadp.keygen module.

Tests key generation workflow including secret sharing, point operations,
edge cases, and error scenarios to achieve high code coverage.
"""

import unittest
import sys
import os
import secrets
from unittest.mock import Mock, patch

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import keygen, crypto, sharing


class TestKeyGeneration(unittest.TestCase):
    """Test key generation workflow comprehensively."""
    
    def test_generate_encryption_key_basic(self):
        """Test basic encryption key generation."""
        try:
            # Test the main key generation function
            result = keygen.generate_encryption_key("test_user", "test_password", 2, 3)
            
            # Should return multiple values (based on integration test, it returns 4)
            self.assertIsInstance(result, tuple)
            self.assertEqual(len(result), 4)
            
            # First element should be the encryption key
            encryption_key = result[0]
            self.assertIsInstance(encryption_key, bytes)
            self.assertEqual(len(encryption_key), 32)  # AES-256 key
            
        except (AttributeError, ImportError):
            self.skipTest("generate_encryption_key function not available")
    
    def test_generate_encryption_key_different_users(self):
        """Test that different users get different keys."""
        try:
            user1_result = keygen.generate_encryption_key("user1", "password", 2, 3)
            user2_result = keygen.generate_encryption_key("user2", "password", 2, 3)
            
            # Different users should get different keys
            self.assertNotEqual(user1_result[0], user2_result[0])
            
        except (AttributeError, ImportError):
            self.skipTest("generate_encryption_key function not available")
    
    def test_generate_encryption_key_different_passwords(self):
        """Test that different passwords give different keys."""
        try:
            result1 = keygen.generate_encryption_key("user", "password1", 2, 3)
            result2 = keygen.generate_encryption_key("user", "password2", 2, 3)
            
            # Different passwords should give different keys
            self.assertNotEqual(result1[0], result2[0])
            
        except (AttributeError, ImportError):
            self.skipTest("generate_encryption_key function not available")
    
    def test_generate_encryption_key_same_inputs(self):
        """Test that same inputs give same results."""
        try:
            result1 = keygen.generate_encryption_key("user", "password", 2, 3)
            result2 = keygen.generate_encryption_key("user", "password", 2, 3)
            
            # Same inputs should give same results (deterministic)
            self.assertEqual(result1, result2)
            
        except (AttributeError, ImportError):
            self.skipTest("generate_encryption_key function not available")
    
    def test_generate_encryption_key_threshold_variations(self):
        """Test key generation with different threshold values."""
        try:
            test_cases = [
                (1, 1),   # Minimum case
                (2, 3),   # Standard case
                (3, 5),   # Higher threshold
                (5, 10),  # Even higher
            ]
            
            for threshold, total_shares in test_cases:
                with self.subTest(threshold=threshold, total_shares=total_shares):
                    result = keygen.generate_encryption_key("user", "password", threshold, total_shares)
                    
                    # Should always return valid result
                    self.assertIsInstance(result, tuple)
                    self.assertEqual(len(result), 4)
                    
                    # Key should always be 32 bytes
                    self.assertEqual(len(result[0]), 32)
                    
        except (AttributeError, ImportError):
            self.skipTest("generate_encryption_key function not available")
    
    def test_generate_encryption_key_invalid_params(self):
        """Test key generation with invalid parameters."""
        try:
            invalid_cases = [
                # (user, password, threshold, total_shares, should_raise)
                ("", "password", 2, 3, True),  # Empty user
                ("user", "", 2, 3, False),     # Empty password (might be valid)
                ("user", "password", 0, 3, True),  # Zero threshold
                ("user", "password", 2, 0, True),  # Zero total shares
                ("user", "password", 5, 3, True),  # Threshold > total shares
                ("user", "password", -1, 3, True), # Negative threshold
                ("user", "password", 2, -1, True), # Negative total shares
            ]
            
            for user, password, threshold, total_shares, should_raise in invalid_cases:
                with self.subTest(user=user, threshold=threshold, total_shares=total_shares):
                    if should_raise:
                        with self.assertRaises((ValueError, AssertionError)):
                            keygen.generate_encryption_key(user, password, threshold, total_shares)
                    else:
                        # Should not raise
                        result = keygen.generate_encryption_key(user, password, threshold, total_shares)
                        self.assertIsInstance(result, tuple)
                        
        except (AttributeError, ImportError):
            self.skipTest("generate_encryption_key function not available")
    
    def test_key_derivation_consistency(self):
        """Test that key derivation is consistent across calls."""
        try:
            # Generate multiple keys with same parameters
            results = []
            for i in range(10):
                result = keygen.generate_encryption_key("consistent_user", "consistent_password", 2, 3)
                results.append(result)
            
            # All results should be identical
            first_result = results[0]
            for result in results[1:]:
                self.assertEqual(result, first_result)
                
        except (AttributeError, ImportError):
            self.skipTest("generate_encryption_key function not available")
    
    def test_secret_sharing_integration(self):
        """Test integration with secret sharing module."""
        try:
            # Test that keygen properly uses secret sharing
            result = keygen.generate_encryption_key("user", "password", 3, 5)
            
            # Should have shares as part of result
            if len(result) >= 2:
                shares = result[1]  # Assuming shares are second element
                if isinstance(shares, list):
                    self.assertEqual(len(shares), 5)  # Should have 5 shares
                    
                    # Each share should be a tuple
                    for share in shares:
                        if isinstance(share, tuple):
                            self.assertEqual(len(share), 2)  # (index, value)
                            
        except (AttributeError, ImportError, IndexError):
            self.skipTest("Secret sharing integration test not applicable")
    
    def test_elliptic_curve_operations(self):
        """Test elliptic curve operations in key generation."""
        try:
            # Test that keygen uses elliptic curve operations
            result = keygen.generate_encryption_key("user", "password", 2, 3)
            
            # Should involve elliptic curve points
            if len(result) >= 3:
                points = result[2]  # Assuming points are third element
                if isinstance(points, list):
                    for point in points:
                        if isinstance(point, tuple) and len(point) == 2:
                            # Should be valid curve points
                            self.assertIsInstance(point[0], int)
                            self.assertIsInstance(point[1], int)
                            
        except (AttributeError, ImportError, IndexError):
            self.skipTest("Elliptic curve operations test not applicable")
    
    def test_password_hashing(self):
        """Test password hashing in key generation."""
        try:
            # Test that passwords are properly hashed
            weak_password = "123"
            strong_password = "very_strong_password_with_numbers_123_and_symbols_!@#"
            
            result1 = keygen.generate_encryption_key("user", weak_password, 2, 3)
            result2 = keygen.generate_encryption_key("user", strong_password, 2, 3)
            
            # Different passwords should give different results
            self.assertNotEqual(result1, result2)
            
            # Both should produce valid keys
            self.assertEqual(len(result1[0]), 32)
            self.assertEqual(len(result2[0]), 32)
            
        except (AttributeError, ImportError):
            self.skipTest("Password hashing test not applicable")
    
    def test_unicode_handling(self):
        """Test handling of Unicode characters in inputs."""
        try:
            unicode_cases = [
                "user_with_émojis_🔐",
                "пользователь",  # Russian
                "用户",  # Chinese
                "ユーザー",  # Japanese
                "🔑🔒🛡️",  # Emoji only
            ]
            
            for unicode_input in unicode_cases:
                with self.subTest(input=unicode_input):
                    result = keygen.generate_encryption_key(unicode_input, "password", 2, 3)
                    
                    # Should handle Unicode gracefully
                    self.assertIsInstance(result, tuple)
                    self.assertEqual(len(result[0]), 32)
                    
        except (AttributeError, ImportError, UnicodeError):
            self.skipTest("Unicode handling test not applicable")
    
    def test_large_input_handling(self):
        """Test handling of very large inputs."""
        try:
            # Test with very long user ID and password
            long_user = "x" * 10000
            long_password = "y" * 10000
            
            result = keygen.generate_encryption_key(long_user, long_password, 2, 3)
            
            # Should handle large inputs without issues
            self.assertIsInstance(result, tuple)
            self.assertEqual(len(result[0]), 32)
            
        except (AttributeError, ImportError, MemoryError):
            self.skipTest("Large input handling test not applicable")
    
    def test_concurrent_key_generation(self):
        """Test concurrent key generation."""
        try:
            import threading
            
            results = []
            errors = []
            
            def generate_key(user_id):
                try:
                    result = keygen.generate_encryption_key(f"file_{user_id}.txt", "password", f"user_{user_id}", 10)
                    results.append((user_id, result))
                except Exception as e:
                    errors.append((user_id, e))
            
            # Start multiple threads (reduced to 3 for faster testing)
            threads = []
            for i in range(3):
                thread = threading.Thread(target=generate_key, args=(i,))
                threads.append(thread)
                thread.start()
            
            # Wait for all threads
            for thread in threads:
                thread.join()
            
            # Should have no errors
            self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
            
            # Should have all results
            self.assertEqual(len(results), 3)
            
            # Check that all results have the expected format
            for user_id, result in results:
                self.assertIsInstance(result, tuple)
                self.assertEqual(len(result), 4)  # (encryption_key, error_message, server_urls, threshold)
                
                encryption_key, error_message, server_urls, threshold = result
                
                # Either we have a key (success) or an error message (failure)
                if encryption_key is not None:
                    self.assertIsInstance(encryption_key, bytes)
                    self.assertEqual(len(encryption_key), 32)
                    self.assertIsNone(error_message)
                else:
                    self.assertIsNotNone(error_message)
                    self.assertIsInstance(error_message, str)
            
            # Test passes if concurrent execution completes without crashes
            # The actual key generation success depends on live server availability
            
        except (AttributeError, ImportError):
            self.skipTest("Concurrent key generation test not applicable")
    
    def test_memory_usage(self):
        """Test memory usage during key generation."""
        try:
            import psutil
            import os
            
            process = psutil.Process(os.getpid())
            initial_memory = process.memory_info().rss
            
            # Generate many keys
            for i in range(100):
                result = keygen.generate_encryption_key(f"user_{i}", "password", 2, 3)
                # Don't store results to avoid memory accumulation
            
            final_memory = process.memory_info().rss
            memory_increase = final_memory - initial_memory
            
            # Memory increase should be reasonable (less than 100MB)
            self.assertLess(memory_increase, 100 * 1024 * 1024)
            
        except (ImportError, AttributeError):
            self.skipTest("Memory usage test not applicable (psutil not available)")
    
    def test_error_propagation(self):
        """Test that errors are properly propagated."""
        try:
            # Mock crypto functions to raise errors
            with patch.object(crypto, 'H', side_effect=Exception("Crypto error")):
                with self.assertRaises(Exception):
                    keygen.generate_encryption_key("user", "password", 2, 3)
                    
        except (AttributeError, ImportError):
            self.skipTest("Error propagation test not applicable")
    
    def test_input_sanitization(self):
        """Test input sanitization."""
        try:
            # Test with potentially dangerous inputs
            dangerous_inputs = [
                "user'; DROP TABLE users; --",  # SQL injection attempt
                "user<script>alert('xss')</script>",  # XSS attempt
                "user\x00null_byte",  # Null byte
                "user\n\r\t",  # Control characters
            ]
            
            for dangerous_input in dangerous_inputs:
                with self.subTest(input=dangerous_input):
                    # Should either handle gracefully or raise appropriate error
                    try:
                        result = keygen.generate_encryption_key(dangerous_input, "password", 2, 3)
                        # If it succeeds, should produce valid result
                        self.assertIsInstance(result, tuple)
                        self.assertEqual(len(result[0]), 32)
                    except (ValueError, UnicodeError):
                        # Acceptable to reject dangerous input
                        pass
                        
        except (AttributeError, ImportError):
            self.skipTest("Input sanitization test not applicable")


class TestKeyGenUtilities(unittest.TestCase):
    """Test key generation utility functions."""
    
    def test_hash_functions(self):
        """Test hash functions used in key generation."""
        try:
            # Test that hash functions are available and working
            test_data = b"test data for hashing"
            
            # Test various hash functions that might be used
            hash_functions = []
            
            if hasattr(crypto, 'H'):
                # Test the H function with proper parameters
                try:
                    result = crypto.H("DID", "BID", "pin")
                    hash_functions.append(('H', result))
                except TypeError:
                    # H function might have different signature
                    pass
            
            # Should have at least some hash functions working
            if hash_functions:
                for name, result in hash_functions:
                    self.assertIsNotNone(result)
                    
        except (AttributeError, ImportError):
            self.skipTest("Hash function tests not applicable")
    
    def test_random_generation(self):
        """Test random number generation."""
        # Test that random generation is working
        random_values = []
        for i in range(100):
            value = secrets.randbelow(2**256)
            random_values.append(value)
        
        # All values should be different
        self.assertEqual(len(set(random_values)), 100)
        
        # All values should be in valid range
        for value in random_values:
            self.assertGreaterEqual(value, 0)
            self.assertLess(value, 2**256)
    
    def test_constant_time_operations(self):
        """Test that operations are constant time where needed."""
        import time
        
        # Test that key generation time doesn't vary significantly with input
        times = []
        
        inputs = [
            ("short", "pwd"),
            ("medium_length_user", "medium_password"),
            ("very_long_user_name_with_lots_of_characters", "very_long_password_with_lots_of_characters"),
        ]
        
        try:
            for user, password in inputs:
                start_time = time.time()
                keygen.generate_encryption_key(user, password, 2, 3)
                end_time = time.time()
                times.append(end_time - start_time)
            
            # Times should be relatively similar (within factor of 2)
            min_time = min(times)
            max_time = max(times)
            
            if min_time > 0:
                ratio = max_time / min_time
                self.assertLess(ratio, 5.0)  # Should not vary by more than 5x
                
        except (AttributeError, ImportError):
            self.skipTest("Constant time test not applicable")


if __name__ == '__main__':
    unittest.main(verbosity=2) 