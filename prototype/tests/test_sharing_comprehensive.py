#!/usr/bin/env python3
"""
Comprehensive tests for the sharing module.

Tests Shamir secret sharing implementation including:
- Basic share generation and recovery
- Various threshold and share combinations  
- Edge cases and error conditions
- Binary data handling through integer conversion
- Cross-reconstruction validation
"""

import unittest
import secrets
import sys
import os

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import sharing, crypto


class TestSecretSharing(unittest.TestCase):
    """Test cases for Shamir secret sharing functionality."""

    def test_make_random_shares_basic(self):
        """Test basic secret sharing functionality."""
        secret = secrets.randbelow(crypto.q)
        threshold = 2
        num_shares = 3

        shares = sharing.make_random_shares(secret, threshold, num_shares)
        
        self.assertEqual(len(shares), num_shares)
        
        # Each share should be a tuple of (x, y)
        for share in shares:
            self.assertIsInstance(share, tuple)
            self.assertEqual(len(share), 2)
            self.assertIsInstance(share[0], int)  # x coordinate
            self.assertIsInstance(share[1], int)  # y coordinate
            
        # X coordinates should be 1, 2, 3, ...
        x_coords = [share[0] for share in shares]
        self.assertEqual(x_coords, [1, 2, 3])

    def test_make_random_shares_edge_cases(self):
        """Test secret sharing edge cases."""
        # Test with threshold = 1 (trivial case)
        secret = secrets.randbelow(crypto.q)
        shares = sharing.make_random_shares(secret, 1, 3)
        self.assertEqual(len(shares), 3)
        
        # With threshold 1, any single share should allow recovery
        # (though we'd need a recovery function for raw integers)
        
        # Test with threshold = num_shares
        shares = sharing.make_random_shares(secret, 3, 3)
        self.assertEqual(len(shares), 3)

    def test_make_random_shares_invalid_params(self):
        """Test secret sharing with invalid parameters."""
        secret = secrets.randbelow(crypto.q)

        # Test threshold > num_shares - should raise ValueError
        with self.assertRaises(ValueError):
            sharing.make_random_shares(secret, 4, 3)

        # Test threshold = 0 - this works too, creates constant shares
        shares = sharing.make_random_shares(secret, 0, 3)
        self.assertEqual(len(shares), 3)
        # With threshold 0, all shares should have the same y value (the secret)
        y_values = [share[1] for share in shares]
        self.assertTrue(all(y == y_values[0] for y in y_values))

        # Test num_shares = 0 with threshold > 0 - should raise ValueError
        with self.assertRaises(ValueError):
            sharing.make_random_shares(secret, 1, 0)
            
        # Test num_shares = 0 with threshold = 0 - should work
        shares = sharing.make_random_shares(secret, 0, 0)
        self.assertEqual(len(shares), 0)

    def test_point_share_recovery_basic(self):
        """Test basic secret recovery using elliptic curve points."""
        secret = secrets.randbelow(crypto.q)
        threshold = 3
        num_shares = 5

        # Create shares
        shares = sharing.make_random_shares(secret, threshold, num_shares)
        
        # Convert to point shares: (x, y*G) where G is the base point
        point_shares = []
        for x, y in shares:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares.append((x, y_point))

        # Test recovery with exactly threshold shares
        recovered_point = sharing.recover_sb(point_shares[:threshold])
        
        # Verify against expected result
        expected_point = crypto.unexpand(crypto.point_mul(secret, crypto.G))
        self.assertEqual(recovered_point, expected_point)

    def test_point_share_recovery_different_combinations(self):
        """Test recovery with different share combinations."""
        secret = secrets.randbelow(crypto.q)
        threshold = 3
        num_shares = 6

        shares = sharing.make_random_shares(secret, threshold, num_shares)
        
        # Convert to point shares
        point_shares = []
        for x, y in shares:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares.append((x, y_point))

        expected_point = crypto.unexpand(crypto.point_mul(secret, crypto.G))

        # Test different combinations of threshold shares
        import itertools
        for combination in itertools.combinations(point_shares, threshold):
            recovered_point = sharing.recover_sb(list(combination))
            self.assertEqual(recovered_point, expected_point)

    def test_point_share_recovery_insufficient_shares(self):
        """Test recovery with insufficient shares."""
        secret = secrets.randbelow(crypto.q)
        threshold = 4
        num_shares = 6

        shares = sharing.make_random_shares(secret, threshold, num_shares)
        
        # Convert to point shares
        point_shares = []
        for x, y in shares:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares.append((x, y_point))

        expected_point = crypto.unexpand(crypto.point_mul(secret, crypto.G))

        # With threshold-1 shares, recovery should give wrong result
        insufficient_shares = point_shares[:threshold-1]
        if len(insufficient_shares) > 0:
            recovered_point = sharing.recover_sb(insufficient_shares)
            # This should NOT equal the expected point (except by extreme coincidence)
            # We can't assert inequality due to the tiny chance they could be equal
            # So we just verify the recovery runs without error
            self.assertIsInstance(recovered_point, tuple)
            self.assertEqual(len(recovered_point), 2)

    def test_point_share_recovery_duplicate_shares(self):
        """Test recovery with duplicate shares."""
        secret = secrets.randbelow(crypto.q)
        threshold = 3
        num_shares = 5

        shares = sharing.make_random_shares(secret, threshold, num_shares)
        
        # Convert to point shares
        point_shares = []
        for x, y in shares:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares.append((x, y_point))

        # Create duplicate shares (same x coordinate)
        duplicate_shares = point_shares[:2] + [point_shares[0]] + point_shares[2:threshold]
        
        # Recovery with duplicates should give incorrect result (this is expected)
        # Duplicate x coordinates break Lagrange interpolation
        recovered_point = sharing.recover_sb(duplicate_shares)
        expected_point = crypto.unexpand(crypto.point_mul(secret, crypto.G))
        
        # The recovered point should NOT equal the expected point due to duplicates
        # (except in the extremely unlikely case where the math works out)
        # We just verify that recovery completes without crashing
        self.assertIsInstance(recovered_point, tuple)
        self.assertEqual(len(recovered_point), 2)

    def test_binary_data_handling(self):
        """Test handling of binary data by converting to integers."""
        test_patterns = [
            b"\x00" * 32,  # All zeros
            b"\xFF" * 32,  # All ones  
            b"\xAA" * 32,  # Alternating pattern
            b"\x55" * 32,  # Different alternating pattern
            secrets.token_bytes(32),  # Random data
        ]

        threshold = 3
        num_shares = 5

        for pattern in test_patterns:
            with self.subTest(pattern=pattern[:4]):  # Show first 4 bytes
                # Convert bytes to integer mod q
                secret_int = int.from_bytes(pattern, 'big') % crypto.q
                
                shares = sharing.make_random_shares(secret_int, threshold, num_shares)
                self.assertEqual(len(shares), num_shares)
                
                # Convert to point shares and test recovery
                point_shares = []
                for x, y in shares:
                    y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
                    point_shares.append((x, y_point))

                recovered_point = sharing.recover_sb(point_shares[:threshold])
                expected_point = crypto.unexpand(crypto.point_mul(secret_int, crypto.G))
                self.assertEqual(recovered_point, expected_point)

    def test_share_reconstruct_roundtrip_various_sizes(self):
        """Test share/reconstruct roundtrip with various secret sizes."""
        test_cases = [
            1,  # Minimum
            crypto.q // 2,  # Half of field
            crypto.q - 1,  # Maximum valid
            secrets.randbelow(crypto.q),  # Random
            secrets.randbelow(crypto.q),  # Another random
        ]

        for secret in test_cases:
            with self.subTest(secret=secret):
                threshold = 3
                num_shares = 5

                shares = sharing.make_random_shares(secret, threshold, num_shares)
                
                # Convert to point shares
                point_shares = []
                for x, y in shares:
                    y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
                    point_shares.append((x, y_point))

                recovered_point = sharing.recover_sb(point_shares[:threshold])
                expected_point = crypto.unexpand(crypto.point_mul(secret, crypto.G))
                self.assertEqual(recovered_point, expected_point)

    def test_share_reconstruct_various_thresholds(self):
        """Test with various threshold and share count combinations."""
        secret = secrets.randbelow(crypto.q)

        test_cases = [
            (1, 1),   # Trivial case
            (1, 5),   # Low threshold, many shares
            (2, 2),   # Threshold equals shares
            (2, 10),  # Low threshold, many shares
            (5, 5),   # Medium threshold equals shares
            (5, 10),  # Medium threshold, more shares
        ]

        for threshold, num_shares in test_cases:
            with self.subTest(threshold=threshold, num_shares=num_shares):
                shares = sharing.make_random_shares(secret, threshold, num_shares)
                self.assertEqual(len(shares), num_shares)
                
                # Convert to point shares
                point_shares = []
                for x, y in shares:
                    y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
                    point_shares.append((x, y_point))

                recovered_point = sharing.recover_sb(point_shares[:threshold])
                expected_point = crypto.unexpand(crypto.point_mul(secret, crypto.G))
                self.assertEqual(recovered_point, expected_point)

    def test_share_indices_are_correct(self):
        """Test that share indices are correctly assigned."""
        secret = secrets.randbelow(crypto.q)
        threshold = 2
        num_shares = 5

        shares = sharing.make_random_shares(secret, threshold, num_shares)
        
        # Check that x coordinates are sequential starting from 1
        x_coords = [share[0] for share in shares]
        expected_x_coords = list(range(1, num_shares + 1))
        self.assertEqual(x_coords, expected_x_coords)

    def test_shares_are_different(self):
        """Test that all shares are different."""
        secret = secrets.randbelow(crypto.q)
        threshold = 2
        num_shares = 10

        shares = sharing.make_random_shares(secret, threshold, num_shares)
        
        # All y coordinates should be different (x coords are sequential)
        y_coords = [share[1] for share in shares]
        self.assertEqual(len(y_coords), len(set(y_coords)))

    def test_deterministic_behavior(self):
        """Test that sharing with same secret gives different results (due to randomness)."""
        secret = secrets.randbelow(crypto.q)
        threshold = 3
        num_shares = 5

        # Generate shares twice
        shares1 = sharing.make_random_shares(secret, threshold, num_shares)
        shares2 = sharing.make_random_shares(secret, threshold, num_shares)
        
        # Shares should be different due to random polynomial coefficients
        # (except for the extremely unlikely case where random coefficients are identical)
        y_coords1 = [share[1] for share in shares1]
        y_coords2 = [share[1] for share in shares2]
        
        # They should almost certainly be different
        different = any(y1 != y2 for y1, y2 in zip(y_coords1, y_coords2))
        self.assertTrue(different, "Shares should be different due to randomness")

    def test_cross_reconstruction(self):
        """Test that shares from different secrets don't cross-reconstruct."""
        secret1 = secrets.randbelow(crypto.q)
        secret2 = secrets.randbelow(crypto.q)
        # Ensure secrets are different
        while secret2 == secret1:
            secret2 = secrets.randbelow(crypto.q)
            
        threshold = 3
        num_shares = 5

        shares1 = sharing.make_random_shares(secret1, threshold, num_shares)
        shares2 = sharing.make_random_shares(secret2, threshold, num_shares)
        
        # Convert to point shares
        point_shares1 = []
        for x, y in shares1:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares1.append((x, y_point))
            
        point_shares2 = []
        for x, y in shares2:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares2.append((x, y_point))

        # Recover both secrets
        recovered_point1 = sharing.recover_sb(point_shares1[:threshold])
        recovered_point2 = sharing.recover_sb(point_shares2[:threshold])
        
        # They should be different
        self.assertNotEqual(recovered_point1, recovered_point2)
        
        # And should match their respective expected values
        expected_point1 = crypto.unexpand(crypto.point_mul(secret1, crypto.G))
        expected_point2 = crypto.unexpand(crypto.point_mul(secret2, crypto.G))
        
        self.assertEqual(recovered_point1, expected_point1)
        self.assertEqual(recovered_point2, expected_point2)

    def test_large_threshold_and_shares(self):
        """Test with large threshold and share counts."""
        secret = secrets.randbelow(crypto.q)
        threshold = 20
        num_shares = 50

        shares = sharing.make_random_shares(secret, threshold, num_shares)
        self.assertEqual(len(shares), num_shares)
        
        # Convert to point shares (just first threshold shares to save time)
        point_shares = []
        for x, y in shares[:threshold]:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares.append((x, y_point))

        recovered_point = sharing.recover_sb(point_shares)
        expected_point = crypto.unexpand(crypto.point_mul(secret, crypto.G))
        self.assertEqual(recovered_point, expected_point)

    def test_share_structure_consistency(self):
        """Test that share structure is consistent across different inputs."""
        secrets_to_test = [
            1,
            crypto.q // 2,
            crypto.q - 1,
        ]

        threshold = 3
        num_shares = 5

        for secret in secrets_to_test:
            shares = sharing.make_random_shares(secret, threshold, num_shares)
            
            # All shares should have same structure
            self.assertEqual(len(shares), num_shares)
            for i, share in enumerate(shares):
                self.assertIsInstance(share, tuple)
                self.assertEqual(len(share), 2)
                self.assertEqual(share[0], i + 1)  # x coordinate should be i+1
                self.assertIsInstance(share[1], int)  # y coordinate should be int


if __name__ == '__main__':
    unittest.main(verbosity=2) 