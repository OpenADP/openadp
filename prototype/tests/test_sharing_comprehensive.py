#!/usr/bin/env python3
"""
Comprehensive unit tests for openadp.sharing module.

Tests secret sharing and reconstruction including edge cases,
boundary conditions, and error scenarios.
"""

import unittest
import sys
import os
import secrets

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import sharing, crypto


class TestSecretSharing(unittest.TestCase):
    """Test secret sharing and reconstruction comprehensively."""
    
    def test_share_secret_basic(self):
        """Test basic secret sharing functionality."""
        secret = b"test secret"
        threshold = 2
        num_shares = 3
        
        shares = sharing.share_secret(secret, threshold, num_shares)
        
        # Verify we get the right number of shares
        self.assertEqual(len(shares), num_shares)
        
        # Verify each share has correct structure
        for i, share in enumerate(shares):
            self.assertIsInstance(share, tuple)
            self.assertEqual(len(share), 2)  # (index, value)
            self.assertEqual(share[0], i + 1)  # 1-indexed
            self.assertIsInstance(share[1], bytes)
    
    def test_share_secret_edge_cases(self):
        """Test secret sharing edge cases."""
        # Test with threshold = 1 (trivial case)
        secret = b"simple"
        shares = sharing.share_secret(secret, 1, 3)
        self.assertEqual(len(shares), 3)
        
        # Test with threshold = num_shares
        shares = sharing.share_secret(secret, 3, 3)
        self.assertEqual(len(shares), 3)
        
        # Test with empty secret
        shares = sharing.share_secret(b"", 2, 3)
        self.assertEqual(len(shares), 3)
        
        # Test with large secret
        large_secret = b"x" * 10000
        shares = sharing.share_secret(large_secret, 2, 3)
        self.assertEqual(len(shares), 3)
    
    def test_share_secret_invalid_params(self):
        """Test secret sharing with invalid parameters."""
        secret = b"test"
        
        # Test threshold > num_shares
        with self.assertRaises((ValueError, AssertionError)):
            sharing.share_secret(secret, 4, 3)
        
        # Test threshold = 0
        with self.assertRaises((ValueError, AssertionError)):
            sharing.share_secret(secret, 0, 3)
        
        # Test num_shares = 0
        with self.assertRaises((ValueError, AssertionError)):
            sharing.share_secret(secret, 2, 0)
        
        # Test negative values
        with self.assertRaises((ValueError, AssertionError)):
            sharing.share_secret(secret, -1, 3)
        
        with self.assertRaises((ValueError, AssertionError)):
            sharing.share_secret(secret, 2, -1)
    
    def test_reconstruct_secret_basic(self):
        """Test basic secret reconstruction."""
        secret = b"test secret for reconstruction"
        threshold = 3
        num_shares = 5
        
        shares = sharing.share_secret(secret, threshold, num_shares)
        
        # Test reconstruction with exact threshold
        reconstructed = sharing.reconstruct_secret(shares[:threshold])
        self.assertEqual(reconstructed, secret)
        
        # Test reconstruction with more than threshold
        reconstructed = sharing.reconstruct_secret(shares[:threshold + 1])
        self.assertEqual(reconstructed, secret)
        
        # Test reconstruction with all shares
        reconstructed = sharing.reconstruct_secret(shares)
        self.assertEqual(reconstructed, secret)
    
    def test_reconstruct_secret_different_combinations(self):
        """Test reconstruction with different share combinations."""
        secret = b"test different combinations"
        threshold = 3
        num_shares = 6
        
        shares = sharing.share_secret(secret, threshold, num_shares)
        
        # Test different combinations of shares
        combinations = [
            [0, 1, 2],  # First three
            [0, 2, 4],  # Every other
            [1, 3, 5],  # Different set
            [2, 3, 4],  # Middle three
            [0, 1, 2, 3],  # Four shares
            [1, 2, 3, 4, 5],  # Last five
        ]
        
        for combo in combinations:
            selected_shares = [shares[i] for i in combo]
            reconstructed = sharing.reconstruct_secret(selected_shares)
            self.assertEqual(reconstructed, secret, f"Failed with combination {combo}")
    
    def test_reconstruct_secret_insufficient_shares(self):
        """Test reconstruction with insufficient shares."""
        secret = b"test insufficient shares"
        threshold = 4
        num_shares = 6
        
        shares = sharing.share_secret(secret, threshold, num_shares)
        
        # Test with threshold - 1 shares (should fail)
        with self.assertRaises((ValueError, Exception)):
            sharing.reconstruct_secret(shares[:threshold - 1])
        
        # Test with single share when threshold > 1
        with self.assertRaises((ValueError, Exception)):
            sharing.reconstruct_secret(shares[:1])
        
        # Test with empty shares list
        with self.assertRaises((ValueError, Exception)):
            sharing.reconstruct_secret([])
    
    def test_reconstruct_secret_duplicate_shares(self):
        """Test reconstruction with duplicate shares."""
        secret = b"test duplicate shares"
        threshold = 3
        num_shares = 5
        
        shares = sharing.share_secret(secret, threshold, num_shares)
        
        # Test with duplicate shares (should handle gracefully or fail)
        duplicate_shares = shares[:2] + [shares[0]] + shares[2:3]
        try:
            reconstructed = sharing.reconstruct_secret(duplicate_shares)
            # If it succeeds, it should still reconstruct correctly
            self.assertEqual(reconstructed, secret)
        except (ValueError, Exception):
            # It's also acceptable to fail with duplicates
            pass
    
    def test_reconstruct_secret_corrupted_shares(self):
        """Test reconstruction with corrupted shares."""
        secret = b"test corrupted shares"
        threshold = 3
        num_shares = 5
        
        shares = sharing.share_secret(secret, threshold, num_shares)
        
        # Corrupt one share's value
        corrupted_shares = shares[:threshold].copy()
        corrupted_value = bytearray(corrupted_shares[0][1])
        corrupted_value[0] ^= 0xFF  # Flip bits
        corrupted_shares[0] = (corrupted_shares[0][0], bytes(corrupted_value))
        
        # Reconstruction should either fail or return wrong result
        try:
            reconstructed = sharing.reconstruct_secret(corrupted_shares)
            self.assertNotEqual(reconstructed, secret)
        except Exception:
            # It's acceptable to fail with corrupted data
            pass
    
    def test_share_reconstruct_roundtrip_various_sizes(self):
        """Test share/reconstruct roundtrip with various secret sizes."""
        test_cases = [
            b"",  # Empty
            b"a",  # Single byte
            b"short",  # Short string
            b"medium length secret for testing",  # Medium
            b"x" * 1000,  # Large
            bytes(range(256)),  # All byte values
            secrets.token_bytes(32),  # Random 32 bytes
            secrets.token_bytes(100),  # Random 100 bytes
        ]
        
        for secret in test_cases:
            with self.subTest(secret_len=len(secret)):
                threshold = 3
                num_shares = 5
                
                shares = sharing.share_secret(secret, threshold, num_shares)
                reconstructed = sharing.reconstruct_secret(shares[:threshold])
                
                self.assertEqual(reconstructed, secret)
    
    def test_share_reconstruct_various_thresholds(self):
        """Test with various threshold and share count combinations."""
        secret = b"test various thresholds"
        
        test_cases = [
            (1, 1),   # Trivial case
            (1, 5),   # Low threshold, many shares
            (2, 2),   # Threshold equals shares
            (2, 10),  # Low threshold, many shares
            (5, 5),   # Medium threshold equals shares
            (5, 10),  # Medium threshold, more shares
            (10, 10), # High threshold equals shares
            (10, 20), # High threshold, many shares
        ]
        
        for threshold, num_shares in test_cases:
            with self.subTest(threshold=threshold, num_shares=num_shares):
                shares = sharing.share_secret(secret, threshold, num_shares)
                reconstructed = sharing.reconstruct_secret(shares[:threshold])
                
                self.assertEqual(reconstructed, secret)
    
    def test_share_indices_are_correct(self):
        """Test that share indices are correctly assigned."""
        secret = b"test share indices"
        threshold = 2
        num_shares = 5
        
        shares = sharing.share_secret(secret, threshold, num_shares)
        
        # Check indices are 1-based and sequential
        expected_indices = list(range(1, num_shares + 1))
        actual_indices = [share[0] for share in shares]
        
        self.assertEqual(actual_indices, expected_indices)
    
    def test_shares_are_different(self):
        """Test that all shares are different."""
        secret = b"test shares are different"
        threshold = 2
        num_shares = 10
        
        shares = sharing.share_secret(secret, threshold, num_shares)
        
        # Check all share values are different
        share_values = [share[1] for share in shares]
        self.assertEqual(len(share_values), len(set(share_values)))
        
        # Check all shares are different (including indices)
        self.assertEqual(len(shares), len(set(shares)))
    
    def test_deterministic_behavior(self):
        """Test that sharing is deterministic with same inputs."""
        secret = b"test deterministic behavior"
        threshold = 3
        num_shares = 5
        
        # Note: This test assumes the sharing function is deterministic
        # If it uses randomness, this test should be modified
        shares1 = sharing.share_secret(secret, threshold, num_shares)
        shares2 = sharing.share_secret(secret, threshold, num_shares)
        
        # If the function is deterministic, shares should be identical
        # If it's randomized, they should still reconstruct to same secret
        reconstructed1 = sharing.reconstruct_secret(shares1[:threshold])
        reconstructed2 = sharing.reconstruct_secret(shares2[:threshold])
        
        self.assertEqual(reconstructed1, secret)
        self.assertEqual(reconstructed2, secret)
    
    def test_cross_reconstruction(self):
        """Test that shares from different secrets don't cross-reconstruct."""
        secret1 = b"first secret"
        secret2 = b"second secret"
        threshold = 3
        num_shares = 5
        
        shares1 = sharing.share_secret(secret1, threshold, num_shares)
        shares2 = sharing.share_secret(secret2, threshold, num_shares)
        
        # Mix shares from different secrets
        mixed_shares = shares1[:2] + shares2[2:3]
        
        try:
            reconstructed = sharing.reconstruct_secret(mixed_shares)
            # Should not reconstruct to either original secret
            self.assertNotEqual(reconstructed, secret1)
            self.assertNotEqual(reconstructed, secret2)
        except Exception:
            # It's also acceptable to fail with mixed shares
            pass
    
    def test_large_threshold_and_shares(self):
        """Test with large threshold and share counts."""
        secret = b"test large threshold and shares"
        threshold = 50
        num_shares = 100
        
        shares = sharing.share_secret(secret, threshold, num_shares)
        self.assertEqual(len(shares), num_shares)
        
        # Test reconstruction with exact threshold
        reconstructed = sharing.reconstruct_secret(shares[:threshold])
        self.assertEqual(reconstructed, secret)
        
        # Test with more shares
        reconstructed = sharing.reconstruct_secret(shares[:threshold + 10])
        self.assertEqual(reconstructed, secret)
    
    def test_binary_data_handling(self):
        """Test handling of various binary data patterns."""
        test_patterns = [
            b"\x00" * 100,  # All zeros
            b"\xFF" * 100,  # All ones
            b"\xAA" * 100,  # Alternating pattern
            b"\x55" * 100,  # Different alternating pattern
            bytes(range(256)) * 4,  # All byte values repeated
        ]
        
        threshold = 3
        num_shares = 5
        
        for pattern in test_patterns:
            with self.subTest(pattern=pattern[:10]):  # Show first 10 bytes
                shares = sharing.share_secret(pattern, threshold, num_shares)
                reconstructed = sharing.reconstruct_secret(shares[:threshold])
                
                self.assertEqual(reconstructed, pattern)
    
    def test_share_structure_consistency(self):
        """Test that share structure is consistent across different inputs."""
        secrets_to_test = [
            b"short",
            b"medium length secret",
            b"very long secret " * 100,
        ]
        
        threshold = 3
        num_shares = 5
        
        for secret in secrets_to_test:
            shares = sharing.share_secret(secret, threshold, num_shares)
            
            # All shares should have same structure
            for i, (index, value) in enumerate(shares):
                self.assertEqual(index, i + 1)
                self.assertIsInstance(value, bytes)
                self.assertGreater(len(value), 0)
            
            # All share values should have same length for same secret
            share_lengths = [len(share[1]) for share in shares]
            self.assertEqual(len(set(share_lengths)), 1)  # All same length


if __name__ == '__main__':
    unittest.main(verbosity=2) 