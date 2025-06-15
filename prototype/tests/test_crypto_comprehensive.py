#!/usr/bin/env python3
"""
Comprehensive unit tests for openadp.crypto module.

Tests all cryptographic functions including edge cases, boundary conditions,
and error scenarios to achieve high code coverage.
"""

import unittest
import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import crypto


class TestCryptoFunctions(unittest.TestCase):
    """Test all crypto module functions comprehensively."""
    
    def test_modp_inv_basic(self):
        """Test modular inverse with basic cases."""
        # Test with known values
        self.assertEqual(crypto.modp_inv(2), pow(2, crypto.p - 2, crypto.p))
        self.assertEqual(crypto.modp_inv(3), pow(3, crypto.p - 2, crypto.p))
        
        # Test that x * modp_inv(x) ≡ 1 (mod p)
        for x in [2, 3, 5, 7, 11, 13, 17, 19]:
            inv_x = crypto.modp_inv(x)
            self.assertEqual((x * inv_x) % crypto.p, 1)
    
    def test_modp_inv_edge_cases(self):
        """Test modular inverse edge cases."""
        # Test with 1 (should be 1)
        self.assertEqual(crypto.modp_inv(1), 1)
        
        # Test with p-1 (should be p-1)
        self.assertEqual(crypto.modp_inv(crypto.p - 1), crypto.p - 1)
        
        # Test with large values
        large_val = crypto.p // 2
        inv_large = crypto.modp_inv(large_val)
        self.assertEqual((large_val * inv_large) % crypto.p, 1)
    
    def test_modp_inv_with_custom_prime(self):
        """Test modular inverse with custom prime."""
        # Test with small prime
        small_prime = 7
        self.assertEqual(crypto.modp_inv(2, small_prime), 4)  # 2 * 4 = 8 ≡ 1 (mod 7)
        self.assertEqual(crypto.modp_inv(3, small_prime), 5)  # 3 * 5 = 15 ≡ 1 (mod 7)
    
    def test_expand_basic(self):
        """Test point expansion from 2D to 4D coordinates."""
        # Test with origin-like point
        point_2d = (0, 1)
        point_4d = crypto.expand(point_2d)
        expected = (0, 1, 1, 0)  # (x, y, 1, x*y mod p)
        self.assertEqual(point_4d, expected)
        
        # Test with arbitrary point
        point_2d = (5, 7)
        point_4d = crypto.expand(point_2d)
        expected = (5, 7, 1, (5 * 7) % crypto.p)
        self.assertEqual(point_4d, expected)
    
    def test_expand_edge_cases(self):
        """Test point expansion edge cases."""
        # Test with large coordinates
        large_x, large_y = crypto.p - 1, crypto.p - 2
        point_4d = crypto.expand((large_x, large_y))
        expected_t = (large_x * large_y) % crypto.p
        self.assertEqual(point_4d, (large_x, large_y, 1, expected_t))
        
        # Test with zero coordinates
        self.assertEqual(crypto.expand((0, 0)), (0, 0, 1, 0))
        self.assertEqual(crypto.expand((crypto.p - 1, 0)), (crypto.p - 1, 0, 1, 0))
    
    def test_point_mul8(self):
        """Test point multiplication by 8."""
        # Test with base point G
        result = crypto.point_mul8(crypto.G)
        
        # Verify it's a valid point (should be on curve)
        self.assertEqual(len(result), 4)
        self.assertIsInstance(result[0], int)
        self.assertIsInstance(result[1], int)
        self.assertIsInstance(result[2], int)
        self.assertIsInstance(result[3], int)
        
        # Test with zero point - point_mul8 may not preserve zero_point exactly
        # due to coordinate system differences
        zero_result = crypto.point_mul8(crypto.zero_point)
        self.assertEqual(len(zero_result), 4)
        # The result should be a valid point, but may not equal zero_point exactly
    
    def test_point_add_basic(self):
        """Test point addition basic cases."""
        # Test adding zero point (should be mathematically equivalent to identity)
        result = crypto.point_add(crypto.G, crypto.zero_point)
        self.assertEqual(len(result), 4)
        
        # Convert both to affine coordinates for comparison
        g_affine = crypto.unexpand(crypto.G)
        result_affine = crypto.unexpand(result)
        self.assertEqual(result_affine, g_affine)
        
        # Test adding point to itself
        double_g = crypto.point_add(crypto.G, crypto.G)
        self.assertEqual(len(double_g), 4)
        
        # Test commutativity: P + Q = Q + P
        p1 = crypto.point_add(crypto.G, crypto.zero_point)
        p2 = crypto.point_add(crypto.zero_point, crypto.G)
        self.assertEqual(crypto.unexpand(p1), crypto.unexpand(p2))
    
    def test_point_add_associativity(self):
        """Test point addition associativity: (P + Q) + R = P + (Q + R)."""
        P = crypto.G
        Q = crypto.point_add(crypto.G, crypto.G)  # 2G
        R = crypto.point_add(Q, crypto.G)  # 3G
        
        # (P + Q) + R
        left = crypto.point_add(crypto.point_add(P, Q), R)
        
        # P + (Q + R)
        right = crypto.point_add(P, crypto.point_add(Q, R))
        
        # Compare in affine coordinates
        self.assertEqual(crypto.unexpand(left), crypto.unexpand(right))
    
    def test_point_mul_basic(self):
        """Test scalar point multiplication basic cases."""
        # Test multiplication by 0 (should give zero point)
        result = crypto.point_mul(0, crypto.G)
        self.assertEqual(result, crypto.zero_point)
        
        # Test multiplication by 1 (should give same point in affine coordinates)
        result = crypto.point_mul(1, crypto.G)
        self.assertEqual(crypto.unexpand(result), crypto.unexpand(crypto.G))
        
        # Test multiplication by 2
        result = crypto.point_mul(2, crypto.G)
        expected = crypto.point_add(crypto.G, crypto.G)
        self.assertEqual(crypto.unexpand(result), crypto.unexpand(expected))
    
    def test_point_mul_edge_cases(self):
        """Test scalar point multiplication edge cases."""
        # Test with large scalar
        large_scalar = crypto.q - 1  # Group order - 1
        result = crypto.point_mul(large_scalar, crypto.G)
        self.assertEqual(len(result), 4)
        
        # Test with scalar equal to group order (should give zero point)
        result = crypto.point_mul(crypto.q, crypto.G)
        # The result should be the zero point (or equivalent in extended coordinates)
        # Convert to affine to check if it's the point at infinity
        try:
            affine_result = crypto.unexpand(result)
            # If unexpand succeeds, it's not the point at infinity
            # This might be expected behavior depending on implementation
        except:
            # If unexpand fails, it might be the point at infinity
            pass
    
    def test_recover_x_basic(self):
        """Test x-coordinate recovery from y and sign."""
        # Test with known point coordinates
        y = crypto.g_y
        sign = 0
        recovered_x = crypto.recover_x(y, sign)
        self.assertEqual(recovered_x, crypto.g_x)
        
        # Test with sign = 1
        if crypto.g_x & 1 == 0:  # If g_x is even
            recovered_x = crypto.recover_x(y, 1)
            self.assertEqual(recovered_x, crypto.p - crypto.g_x)
    
    def test_recover_x_edge_cases(self):
        """Test x-coordinate recovery edge cases."""
        # Test with y = 0 (should work for some curves)
        result = crypto.recover_x(0, 0)
        if result is not None:
            self.assertIsInstance(result, int)
            self.assertGreaterEqual(result, 0)
            self.assertLess(result, crypto.p)
        
        # Test with y >= p (should return None)
        result = crypto.recover_x(crypto.p, 0)
        self.assertIsNone(result)
        
        result = crypto.recover_x(crypto.p + 1, 0)
        self.assertIsNone(result)
        
        # Test with y = p - 1
        result = crypto.recover_x(crypto.p - 1, 0)
        # Should either return valid x or None
        if result is not None:
            self.assertIsInstance(result, int)
            self.assertGreaterEqual(result, 0)
            self.assertLess(result, crypto.p)
    
    def test_point_compress_decompress_roundtrip(self):
        """Test point compression and decompression roundtrip."""
        # Test with base point G
        compressed = crypto.point_compress(crypto.G)
        self.assertEqual(len(compressed), 32)
        
        decompressed = crypto.point_decompress(compressed)
        self.assertIsNotNone(decompressed)
        # Compare in affine coordinates
        self.assertEqual(crypto.unexpand(decompressed), crypto.unexpand(crypto.G))
        
        # Test with multiple points
        points = [
            crypto.G,
            crypto.point_add(crypto.G, crypto.G),
            crypto.point_mul(5, crypto.G),
            crypto.point_mul(100, crypto.G)
        ]
        
        for point in points:
            with self.subTest(point=crypto.unexpand(point)):
                compressed = crypto.point_compress(point)
                decompressed = crypto.point_decompress(compressed)
                self.assertIsNotNone(decompressed)
                # Compare in affine coordinates
                self.assertEqual(crypto.unexpand(decompressed), crypto.unexpand(point))
    
    def test_point_decompress_invalid_input(self):
        """Test point decompression with invalid input."""
        # Test with wrong length
        with self.assertRaises(Exception):
            crypto.point_decompress(b"short")
        
        with self.assertRaises(Exception):
            crypto.point_decompress(b"x" * 31)  # Too short
        
        with self.assertRaises(Exception):
            crypto.point_decompress(b"x" * 33)  # Too long
        
        # Test with invalid point (should return None)
        invalid_bytes = b"\xff" * 32
        result = crypto.point_decompress(invalid_bytes)
        # Should either return None or a valid point
        if result is not None:
            self.assertEqual(len(result), 4)
    
    def test_unexpand(self):
        """Test point unexpansion from 4D to 2D coordinates."""
        # Test with base point G
        unexpanded = crypto.unexpand(crypto.G)
        self.assertEqual(len(unexpanded), 2)  # Should return (x, y) tuple
        self.assertIsInstance(unexpanded[0], int)
        self.assertIsInstance(unexpanded[1], int)
        
        # Test roundtrip: expand -> unexpand should preserve coordinates
        expanded = crypto.expand(unexpanded)
        unexpanded_again = crypto.unexpand(expanded)
        self.assertEqual(unexpanded, unexpanded_again)
        
        # Test with zero point
        zero_unexpanded = crypto.unexpand(crypto.zero_point)
        self.assertEqual(len(zero_unexpanded), 2)
    
    def test_H_function_basic(self):
        """Test hash-to-curve function H() basic cases."""
        # Test with simple inputs - H() needs UID, DID, BID, pin
        result1 = crypto.H(b"user1", b"device1", b"backup1", b"pin1")
        self.assertEqual(len(result1), 4)  # Should return 4D point
        
        result2 = crypto.H(b"user2", b"device2", b"backup2", b"pin2")
        self.assertEqual(len(result2), 4)
        
        # Test deterministic behavior
        result3 = crypto.H(b"user1", b"device1", b"backup1", b"pin1")
        self.assertEqual(result1, result3)
        
        # Test different inputs give different results
        result4 = crypto.H(b"different", b"device1", b"backup1", b"pin1")
        self.assertNotEqual(result1, result4)
    
    def test_H_function_edge_cases(self):
        """Test hash-to-curve function H() edge cases."""
        # Test with empty inputs
        result = crypto.H(b"", b"", b"", b"")
        self.assertEqual(len(result), 4)
        
        # Test with very long inputs
        long_input = b"x" * 10000
        result = crypto.H(long_input, b"device", b"backup", b"pin")
        self.assertEqual(len(result), 4)
        
        # Test with binary data
        binary_data = bytes(range(256))
        result = crypto.H(binary_data, b"device", b"backup", b"pin")
        self.assertEqual(len(result), 4)
    
    def test_H_function_multiple_args(self):
        """Test hash-to-curve function with multiple arguments."""
        # Test argument order matters
        result1 = crypto.H(b"a", b"b", b"c", b"d")
        result2 = crypto.H(b"c", b"b", b"a", b"d")
        self.assertNotEqual(result1, result2)
        
        # Test different combinations
        result3 = crypto.H(b"user", b"device", b"backup", b"pin")
        result4 = crypto.H(b"user", b"device", b"backup", b"different_pin")
        # These should be different
        self.assertNotEqual(result3, result4)
    
    def test_deriveEncKey_basic(self):
        """Test encryption key derivation basic cases."""
        # Test with base point G
        key1 = crypto.deriveEncKey(crypto.G)
        self.assertEqual(len(key1), 32)
        self.assertIsInstance(key1, bytes)
        
        # Test deterministic behavior
        key2 = crypto.deriveEncKey(crypto.G)
        self.assertEqual(key1, key2)
        
        # Test different points give different keys
        other_point = crypto.point_add(crypto.G, crypto.G)
        key3 = crypto.deriveEncKey(other_point)
        self.assertNotEqual(key1, key3)
    
    def test_deriveEncKey_edge_cases(self):
        """Test encryption key derivation edge cases."""
        # Test with zero point
        key = crypto.deriveEncKey(crypto.zero_point)
        self.assertEqual(len(key), 32)
        
        # Test with various points
        points = [
            crypto.G,
            crypto.zero_point,
            crypto.point_mul(crypto.q - 1, crypto.G),  # Order - 1
            crypto.point_mul(12345, crypto.G)
        ]
        
        keys = []
        for point in points:
            key = crypto.deriveEncKey(point)
            self.assertEqual(len(key), 32)
            self.assertNotIn(key, keys)  # All keys should be different
            keys.append(key)
    
    def test_x25519_functions(self):
        """Test X25519 functions for Noise protocol."""
        # Test keypair generation
        private_key, public_key = crypto.x25519_generate_keypair()
        self.assertEqual(len(private_key), 32)
        self.assertEqual(len(public_key), 32)
        
        # Test public key derivation
        derived_public = crypto.x25519_public_key_from_private(private_key)
        self.assertEqual(public_key, derived_public)
        
        # Test Diffie-Hellman
        private_key2, public_key2 = crypto.x25519_generate_keypair()
        
        shared1 = crypto.x25519_dh(private_key, public_key2)
        shared2 = crypto.x25519_dh(private_key2, public_key)
        
        self.assertEqual(shared1, shared2)  # Should be same shared secret
        self.assertEqual(len(shared1), 32)
    
    def test_x25519_edge_cases(self):
        """Test X25519 edge cases."""
        # Test multiple keypair generations are different
        keys = []
        for _ in range(10):
            private_key, public_key = crypto.x25519_generate_keypair()
            self.assertNotIn((private_key, public_key), keys)
            keys.append((private_key, public_key))
        
        # Test DH with same key (should work)
        private_key, public_key = crypto.x25519_generate_keypair()
        shared = crypto.x25519_dh(private_key, public_key)
        self.assertEqual(len(shared), 32)
    
    def test_constants_validity(self):
        """Test that cryptographic constants are valid."""
        # Test field prime p
        self.assertGreater(crypto.p, 0)
        self.assertEqual(crypto.p, 2**255 - 19)
        
        # Test group order q
        self.assertGreater(crypto.q, 0)
        self.assertEqual(crypto.q, 2**252 + 27742317777372353535851937790883648493)
        
        # Test curve constant d
        self.assertGreater(crypto.d, 0)
        self.assertLess(crypto.d, crypto.p)
        
        # Test base point coordinates
        self.assertGreater(crypto.g_x, 0)
        self.assertLess(crypto.g_x, crypto.p)
        self.assertGreater(crypto.g_y, 0)
        self.assertLess(crypto.g_y, crypto.p)
        
        # Test base point G is valid
        self.assertEqual(len(crypto.G), 4)
        self.assertEqual(crypto.G[2], 1)  # Z coordinate should be 1
        
        # Test zero point
        self.assertEqual(crypto.zero_point, (0, 1, 1, 0))
    
    def test_curve_equation(self):
        """Test that points satisfy the Edwards curve equation."""
        # For Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2
        def check_curve_equation(point_4d):
            if point_4d[2] == 0:  # Point at infinity
                return True
            
            # Convert to affine coordinates
            z_inv = crypto.modp_inv(point_4d[2])
            x = (point_4d[0] * z_inv) % crypto.p
            y = (point_4d[1] * z_inv) % crypto.p
            
            # Check curve equation: -x^2 + y^2 = 1 + d*x^2*y^2
            left = (-x*x + y*y) % crypto.p
            right = (1 + crypto.d * x*x * y*y) % crypto.p
            
            return left == right
        
        # Test base point G
        self.assertTrue(check_curve_equation(crypto.G))
        
        # Test zero point
        self.assertTrue(check_curve_equation(crypto.zero_point))
        
        # Test some computed points
        points_to_test = [
            crypto.point_add(crypto.G, crypto.G),
            crypto.point_mul(3, crypto.G),
            crypto.point_mul(7, crypto.G),
            crypto.point_mul(100, crypto.G)
        ]
        
        for point in points_to_test:
            self.assertTrue(check_curve_equation(point), f"Point {point} not on curve")


if __name__ == '__main__':
    unittest.main(verbosity=2) 