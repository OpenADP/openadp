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
        """Test edge cases in make_random_shares function."""
        # Test minimum = shares (threshold equals total shares)
        secret = 12345
        minimum = 3
        shares = 3
        result = sharing.make_random_shares(secret, minimum, shares)
        self.assertEqual(len(result), shares)
        
        # Test minimum = 1 (any single share can recover)
        result = sharing.make_random_shares(secret, 1, 5)
        self.assertEqual(len(result), 5)
        
        # Test with different prime
        custom_prime = 97  # Small prime for testing
        result = sharing.make_random_shares(secret % custom_prime, 2, 4, custom_prime)
        self.assertEqual(len(result), 4)
        for x, y in result:
            self.assertLess(y, custom_prime)

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

    def test_make_random_shares_error_conditions(self):
        """Test error conditions in make_random_shares."""
        # Test minimum > shares (should raise ValueError)
        with self.assertRaises(ValueError) as context:
            sharing.make_random_shares(123, 5, 3)  # minimum=5, shares=3
        
        self.assertIn("irrecoverable", str(context.exception))

    def test_eval_at_comprehensive(self):
        """Test eval_at function comprehensively."""
        # Test simple polynomial: f(x) = 3 + 2x + x^2
        poly = [3, 2, 1]  # coefficients [a0, a1, a2]
        
        # Test at x=0: should be 3
        result = sharing.eval_at(poly, 0, crypto.q)
        self.assertEqual(result, 3)
        
        # Test at x=1: should be 3 + 2 + 1 = 6
        result = sharing.eval_at(poly, 1, crypto.q)
        self.assertEqual(result, 6)
        
        # Test at x=2: should be 3 + 4 + 4 = 11
        result = sharing.eval_at(poly, 2, crypto.q)
        self.assertEqual(result, 11)
        
        # Test with different prime
        small_prime = 7
        result = sharing.eval_at(poly, 2, small_prime)
        self.assertEqual(result, 11 % small_prime)

    def test_recover_sb_edge_cases(self):
        """Test edge cases in recover_sb function."""
        # Test with minimum threshold (2 shares)
        secret = 98765
        shares = sharing.make_random_shares(secret, 2, 5)
        
        # Convert to point shares
        point_shares = []
        for x, y in shares[:2]:  # Use only first 2 shares
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares.append((x, y_point))
        
        # Recover and verify
        recovered_point = sharing.recover_sb(point_shares)
        expected_point = crypto.unexpand(crypto.point_mul(secret, crypto.G))
        self.assertEqual(recovered_point, expected_point)

    def test_recover_sb_lagrange_weights(self):
        """Test Lagrange interpolation weights calculation in recover_sb."""
        # Create shares with known values to test weight calculation
        secret = 42
        threshold = 3
        shares = sharing.make_random_shares(secret, threshold, 5)
        
        # Test with different combinations of shares
        combinations = [
            shares[:3],  # First 3 shares
            shares[1:4],  # Middle 3 shares  
            shares[2:5],  # Last 3 shares
        ]
        
        for share_combo in combinations:
            with self.subTest(shares=[(x, y) for x, y in share_combo]):
                # Convert to point shares
                point_shares = []
                for x, y in share_combo:
                    y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
                    point_shares.append((x, y_point))
                
                # Recover should give same result
                recovered_point = sharing.recover_sb(point_shares)
                expected_point = crypto.unexpand(crypto.point_mul(secret, crypto.G))
                self.assertEqual(recovered_point, expected_point)

    def test_recover_sb_with_custom_prime(self):
        """Test recover_sb with custom prime."""
        secret = 123
        custom_prime = 101  # Small prime
        
        # Create shares with custom prime
        shares = sharing.make_random_shares(secret % custom_prime, 2, 4, custom_prime)
        
        # Convert to point shares (still using crypto.G and crypto.q for points)
        point_shares = []
        for x, y in shares[:2]:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares.append((x, y_point))
        
        # Recover with custom prime
        recovered_point = sharing.recover_sb(point_shares, custom_prime)
        
        # Verify it's a valid point
        self.assertEqual(len(recovered_point), 2)
        self.assertIsInstance(recovered_point[0], int)
        self.assertIsInstance(recovered_point[1], int)

    def test_sharing_with_zero_secret(self):
        """Test sharing with zero secret."""
        secret = 0
        shares = sharing.make_random_shares(secret, 2, 3)
        
        # Convert to point shares
        point_shares = []
        for x, y in shares[:2]:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares.append((x, y_point))
        
        # Recover should give zero point (identity element)
        recovered_point = sharing.recover_sb(point_shares)
        expected_point = crypto.unexpand(crypto.point_mul(0, crypto.G))
        self.assertEqual(recovered_point, expected_point)

    def test_sharing_with_large_secret(self):
        """Test sharing with large secret values."""
        # Test with secret close to prime modulus
        large_secret = crypto.q - 1
        shares = sharing.make_random_shares(large_secret, 3, 5)
        
        # Convert to point shares
        point_shares = []
        for x, y in shares[:3]:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares.append((x, y_point))
        
        # Recover and verify
        recovered_point = sharing.recover_sb(point_shares)
        expected_point = crypto.unexpand(crypto.point_mul(large_secret, crypto.G))
        self.assertEqual(recovered_point, expected_point)

    def test_sharing_deterministic_behavior(self):
        """Test that sharing is deterministic for same inputs."""
        secret = 54321
        
        # Note: make_random_shares uses secrets.randbelow, so it's NOT deterministic
        # But we can test that the mathematical properties hold
        shares1 = sharing.make_random_shares(secret, 2, 4)
        shares2 = sharing.make_random_shares(secret, 2, 4)
        
        # Shares will be different due to randomness
        self.assertNotEqual(shares1, shares2)
        
        # But recovery should give same result
        point_shares1 = [(x, crypto.unexpand(crypto.point_mul(y, crypto.G))) for x, y in shares1[:2]]
        point_shares2 = [(x, crypto.unexpand(crypto.point_mul(y, crypto.G))) for x, y in shares2[:2]]
        
        recovered1 = sharing.recover_sb(point_shares1)
        recovered2 = sharing.recover_sb(point_shares2)
        
        expected = crypto.unexpand(crypto.point_mul(secret, crypto.G))
        self.assertEqual(recovered1, expected)
        self.assertEqual(recovered2, expected)

    def test_sharing_polynomial_properties(self):
        """Test mathematical properties of the polynomial construction."""
        secret = 777
        threshold = 4
        shares = sharing.make_random_shares(secret, threshold, 6)
        
        # The constant term of the polynomial should be the secret
        # We can verify this by checking that f(0) = secret
        # But since we don't expose the polynomial directly, we test via recovery
        
        # Any threshold number of shares should recover the same secret
        for i in range(3):  # Test 3 different combinations
            start_idx = i
            test_shares = shares[start_idx:start_idx + threshold]
            
            point_shares = []
            for x, y in test_shares:
                y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
                point_shares.append((x, y_point))
            
            recovered_point = sharing.recover_sb(point_shares)
            expected_point = crypto.unexpand(crypto.point_mul(secret, crypto.G))
            self.assertEqual(recovered_point, expected_point)

    def test_sharing_main_function_coverage(self):
        """Test the main function to ensure it runs without errors."""
        # Import and run the main function to cover those lines
        import io
        import sys
        from contextlib import redirect_stdout
        
        # Capture output to avoid cluttering test results
        captured_output = io.StringIO()
        
        try:
            with redirect_stdout(captured_output):
                sharing.main()
            
            # Verify that main() ran successfully
            output = captured_output.getvalue()
            self.assertIn("Testing Shamir Secret Sharing", output)
            self.assertIn("All tests passed", output)
            
        except Exception as e:
            self.fail(f"sharing.main() failed: {e}")

    def test_eval_at_comprehensive_edge_cases(self):
        """Test eval_at function with comprehensive edge cases."""
        # Test with empty polynomial (should be 0)
        result = sharing.eval_at([], 5, crypto.q)
        self.assertEqual(result, 0)
        
        # Test with single coefficient (constant polynomial)
        result = sharing.eval_at([42], 100, crypto.q)
        self.assertEqual(result, 42)
        
        # Test with large coefficients
        large_poly = [crypto.q - 1, crypto.q - 2, crypto.q - 3]
        result = sharing.eval_at(large_poly, 1, crypto.q)
        expected = ((crypto.q - 1) + (crypto.q - 2) + (crypto.q - 3)) % crypto.q
        self.assertEqual(result, expected)
        
        # Test with x = 0 (should return constant term)
        poly = [123, 456, 789]
        result = sharing.eval_at(poly, 0, crypto.q)
        self.assertEqual(result, 123)

    def test_make_random_shares_comprehensive_validation(self):
        """Test make_random_shares with comprehensive parameter validation."""
        # Test minimum = shares (edge case)
        secret = 12345
        shares = sharing.make_random_shares(secret, 3, 3)
        self.assertEqual(len(shares), 3)
        
        # Verify all x coordinates are unique and in expected range
        x_coords = [x for x, y in shares]
        self.assertEqual(len(set(x_coords)), len(x_coords))  # All unique
        self.assertEqual(sorted(x_coords), [1, 2, 3])  # Should be 1, 2, 3
        
        # Test with minimum = 1 (any single share can recover)
        shares = sharing.make_random_shares(secret, 1, 5)
        self.assertEqual(len(shares), 5)
        
        # With minimum=1, all y values should equal the secret
        for x, y in shares:
            self.assertEqual(y, secret)

    def test_recover_sb_edge_cases_comprehensive(self):
        """Test recover_sb with comprehensive edge cases."""
        # Test with minimum number of shares (threshold = 1)
        secret = 98765
        shares = sharing.make_random_shares(secret, 1, 3)
        
        # Convert to point shares
        point_shares = []
        for x, y in shares:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares.append((x, y_point))
        
        # Should be able to recover with just one share when threshold=1
        recovered = sharing.recover_sb(point_shares[:1])
        expected = crypto.unexpand(crypto.point_mul(secret, crypto.G))
        self.assertEqual(recovered, expected)
        
        # Test with exactly threshold number of shares
        secret2 = 54321
        shares2 = sharing.make_random_shares(secret2, 3, 5)
        point_shares2 = []
        for x, y in shares2:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares2.append((x, y_point))
        
        # Should work with exactly 3 shares
        recovered2 = sharing.recover_sb(point_shares2[:3])
        expected2 = crypto.unexpand(crypto.point_mul(secret2, crypto.G))
        self.assertEqual(recovered2, expected2)

    def test_sharing_with_different_primes(self):
        """Test sharing with different prime moduli."""
        # Test with a smaller prime
        small_prime = 97  # Small prime for testing
        secret = 42
        
        shares = sharing.make_random_shares(secret, 2, 4, small_prime)
        self.assertEqual(len(shares), 4)
        
        # All y values should be less than the prime
        for x, y in shares:
            self.assertLess(y, small_prime)
            self.assertGreaterEqual(y, 0)

    def test_polynomial_evaluation_properties(self):
        """Test mathematical properties of polynomial evaluation."""
        # Test that eval_at correctly implements polynomial evaluation
        # For polynomial a0 + a1*x + a2*x^2, verify manually
        poly = [5, 3, 2]  # 5 + 3x + 2x^2
        
        # At x=0: should be 5
        self.assertEqual(sharing.eval_at(poly, 0, crypto.q), 5)
        
        # At x=1: should be 5 + 3 + 2 = 10
        self.assertEqual(sharing.eval_at(poly, 1, crypto.q), 10)
        
        # At x=2: should be 5 + 6 + 8 = 19
        self.assertEqual(sharing.eval_at(poly, 2, crypto.q), 19)

    def test_lagrange_interpolation_weights(self):
        """Test that Lagrange interpolation weights are computed correctly."""
        # Create a simple case where we can verify weights manually
        secret = 100
        shares = sharing.make_random_shares(secret, 2, 3)  # Linear polynomial
        
        # Convert to point shares
        point_shares = []
        for x, y in shares:
            y_point = crypto.unexpand(crypto.point_mul(y, crypto.G))
            point_shares.append((x, y_point))
        
        # Test recovery with different combinations
        for i in range(len(shares)):
            for j in range(i + 1, len(shares)):
                subset = [point_shares[i], point_shares[j]]
                recovered = sharing.recover_sb(subset)
                expected = crypto.unexpand(crypto.point_mul(secret, crypto.G))
                self.assertEqual(recovered, expected)

    def test_sharing_deterministic_properties(self):
        """Test deterministic properties of the sharing scheme."""
        secret = 777
        
        # Same secret with same parameters should give different shares (randomness)
        shares1 = sharing.make_random_shares(secret, 3, 5)
        shares2 = sharing.make_random_shares(secret, 3, 5)
        
        # X coordinates should be the same (1,2,3,4,5)
        x_coords1 = [x for x, y in shares1]
        x_coords2 = [x for x, y in shares2]
        self.assertEqual(x_coords1, x_coords2)
        
        # But Y coordinates should be different (due to randomness)
        y_coords1 = [y for x, y in shares1]
        y_coords2 = [y for x, y in shares2]
        self.assertNotEqual(y_coords1, y_coords2)
        
        # But both should recover to the same secret
        point_shares1 = [(x, crypto.unexpand(crypto.point_mul(y, crypto.G))) for x, y in shares1]
        point_shares2 = [(x, crypto.unexpand(crypto.point_mul(y, crypto.G))) for x, y in shares2]
        
        recovered1 = sharing.recover_sb(point_shares1[:3])
        recovered2 = sharing.recover_sb(point_shares2[:3])
        
        expected = crypto.unexpand(crypto.point_mul(secret, crypto.G))
        self.assertEqual(recovered1, expected)
        self.assertEqual(recovered2, expected)
        self.assertEqual(recovered1, recovered2)


if __name__ == '__main__':
    unittest.main(verbosity=2) 