"""
Unit tests for OpenADP authentication key management.

Tests key generation, serialization, and loading functionality.
"""

import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'prototype', 'src'))

from openadp.auth.keys import (
    generate_keypair, 
    save_private_key, 
    load_private_key,
    private_key_to_jwk
)


class TestKeys(unittest.TestCase):
    """Test cases for key management functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.key_path = os.path.join(self.temp_dir, "test_key.pem")
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.key_path):
            os.remove(self.key_path)
        os.rmdir(self.temp_dir)
    
    def test_generate_keypair(self):
        """Test EC P-256 keypair generation."""
        private_key, public_jwk = generate_keypair()
        
        # Verify private key type
        self.assertIsInstance(private_key, ec.EllipticCurvePrivateKey)
        
        # Verify curve type
        self.assertIsInstance(private_key.curve, ec.SECP256R1)
        
        # Verify JWK structure
        self.assertIsInstance(public_jwk, dict)
        required_fields = ['kty', 'crv', 'x', 'y', 'use', 'alg']
        for field in required_fields:
            self.assertIn(field, public_jwk)
        
        # Verify JWK values
        self.assertEqual(public_jwk['kty'], 'EC')
        self.assertEqual(public_jwk['crv'], 'P-256')
        self.assertEqual(public_jwk['use'], 'sig')
        self.assertEqual(public_jwk['alg'], 'ES256')
        
        # Verify coordinate lengths (base64url encoded 32-byte values)
        # 32 bytes = 256 bits, base64url without padding should be 43 chars
        self.assertGreaterEqual(len(public_jwk['x']), 42)
        self.assertLessEqual(len(public_jwk['x']), 43)
        self.assertGreaterEqual(len(public_jwk['y']), 42)
        self.assertLessEqual(len(public_jwk['y']), 43)
    
    def test_key_serialization_round_trip(self):
        """Test key serialization and loading round-trip."""
        # Generate keypair
        original_key, original_jwk = generate_keypair()
        
        # Save private key
        save_private_key(original_key, self.key_path)
        
        # Verify file exists and has correct permissions
        self.assertTrue(os.path.exists(self.key_path))
        file_stat = os.stat(self.key_path)
        # Check that only owner has read/write permissions (0o600)
        self.assertEqual(file_stat.st_mode & 0o777, 0o600)
        
        # Load private key
        loaded_key = load_private_key(self.key_path)
        
        # Verify loaded key type
        self.assertIsInstance(loaded_key, ec.EllipticCurvePrivateKey)
        
        # Convert loaded key to JWK
        loaded_jwk = private_key_to_jwk(loaded_key)
        
        # Verify JWKs match
        self.assertEqual(original_jwk, loaded_jwk)
        
        # Verify private key numbers match
        original_private_numbers = original_key.private_numbers()
        loaded_private_numbers = loaded_key.private_numbers()
        self.assertEqual(
            original_private_numbers.private_value,
            loaded_private_numbers.private_value
        )
    
    def test_save_private_key_creates_directory(self):
        """Test that save_private_key creates parent directories."""
        nested_path = os.path.join(self.temp_dir, "nested", "dir", "key.pem")
        private_key, _ = generate_keypair()
        
        # Save to nested path
        save_private_key(private_key, nested_path)
        
        # Verify file exists
        self.assertTrue(os.path.exists(nested_path))
        
        # Verify we can load it back
        loaded_key = load_private_key(nested_path)
        self.assertIsInstance(loaded_key, ec.EllipticCurvePrivateKey)
        
        # Clean up
        os.remove(nested_path)
        Path(nested_path).parent.rmdir()
        Path(nested_path).parent.parent.rmdir()
    
    def test_load_nonexistent_key(self):
        """Test loading a non-existent key file."""
        nonexistent_path = os.path.join(self.temp_dir, "nonexistent.pem")
        
        with self.assertRaises(FileNotFoundError):
            load_private_key(nonexistent_path)
    
    def test_load_invalid_key_file(self):
        """Test loading an invalid key file."""
        # Create invalid key file
        with open(self.key_path, 'w') as f:
            f.write("This is not a valid PEM key file")
        
        with self.assertRaises(ValueError):
            load_private_key(self.key_path)
    
    def test_private_key_to_jwk(self):
        """Test converting private key to JWK."""
        private_key, original_jwk = generate_keypair()
        
        # Convert using the function
        converted_jwk = private_key_to_jwk(private_key)
        
        # Should match original
        self.assertEqual(original_jwk, converted_jwk)
    
    def test_multiple_keypairs_are_different(self):
        """Test that multiple generated keypairs are different."""
        key1, jwk1 = generate_keypair()
        key2, jwk2 = generate_keypair()
        
        # Private keys should be different
        self.assertNotEqual(
            key1.private_numbers().private_value,
            key2.private_numbers().private_value
        )
        
        # JWKs should be different
        self.assertNotEqual(jwk1['x'], jwk2['x'])
        self.assertNotEqual(jwk1['y'], jwk2['y'])
    
    def test_jwk_base64url_encoding(self):
        """Test that JWK coordinates are properly base64url encoded."""
        _, jwk = generate_keypair()
        
        # Base64url should not contain padding characters
        self.assertNotIn('=', jwk['x'])
        self.assertNotIn('=', jwk['y'])
        
        # Should not contain standard base64 characters
        self.assertNotIn('+', jwk['x'])
        self.assertNotIn('/', jwk['x'])
        self.assertNotIn('+', jwk['y'])
        self.assertNotIn('/', jwk['y'])


if __name__ == '__main__':
    unittest.main() 