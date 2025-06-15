#!/usr/bin/env python3
"""
Simple focused tests for authentication modules to improve coverage.
"""

import unittest
import sys
import os
import base64
import hashlib
import secrets
from unittest.mock import Mock, patch
import requests

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp.auth.pkce_flow import generate_pkce_challenge, PKCEFlowError
from openadp.auth.dpop import make_dpop_header, extract_jti_from_dpop, validate_dpop_claims, calculate_jwk_thumbprint
from cryptography.hazmat.primitives.asymmetric import ec


class TestPKCEBasics(unittest.TestCase):
    """Test basic PKCE functionality."""
    
    def test_generate_pkce_challenge(self):
        """Test PKCE challenge generation."""
        code_verifier, code_challenge = generate_pkce_challenge()
        
        # Verify code verifier format
        self.assertIsInstance(code_verifier, str)
        self.assertGreaterEqual(len(code_verifier), 43)
        self.assertLessEqual(len(code_verifier), 128)
        
        # Verify code challenge format
        self.assertIsInstance(code_challenge, str)
        
        # Verify challenge is SHA256 hash of verifier
        expected_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('ascii')).digest()
        ).decode('ascii').rstrip('=')
        
        self.assertEqual(code_challenge, expected_challenge)

    def test_pkce_challenge_uniqueness(self):
        """Test that PKCE challenges are unique."""
        challenge1 = generate_pkce_challenge()
        challenge2 = generate_pkce_challenge()
        
        # Should be different
        self.assertNotEqual(challenge1[0], challenge2[0])  # verifier
        self.assertNotEqual(challenge1[1], challenge2[1])  # challenge


class TestDPoPBasics(unittest.TestCase):
    """Test basic DPoP functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.method = "POST"
        self.url = "https://example.com/token"
        self.access_token = "test-access-token"

    def test_make_dpop_header_basic(self):
        """Test basic DPoP header creation."""
        dpop_header = make_dpop_header(self.method, self.url, self.private_key)
        
        # Should be a JWT (3 parts separated by dots)
        parts = dpop_header.split('.')
        self.assertEqual(len(parts), 3)
        
        # Each part should be base64url encoded
        for part in parts:
            self.assertIsInstance(part, str)
            self.assertGreater(len(part), 0)

    def test_make_dpop_header_with_access_token(self):
        """Test DPoP header creation with access token."""
        dpop_header = make_dpop_header(self.method, self.url, self.private_key, self.access_token)
        
        # Should be a JWT
        parts = dpop_header.split('.')
        self.assertEqual(len(parts), 3)

    def test_extract_jti_from_dpop(self):
        """Test extracting JTI from DPoP header."""
        dpop_header = make_dpop_header(self.method, self.url, self.private_key)
        
        jti = extract_jti_from_dpop(dpop_header)
        
        # JTI should be a UUID string
        self.assertIsInstance(jti, str)
        self.assertGreater(len(jti), 0)

    def test_extract_jti_invalid_header(self):
        """Test extracting JTI from invalid DPoP header."""
        with self.assertRaises(ValueError):
            extract_jti_from_dpop("invalid.jwt")
        
        with self.assertRaises(ValueError):
            extract_jti_from_dpop("invalid")

    def test_validate_dpop_claims_basic(self):
        """Test basic DPoP claims validation."""
        dpop_header = make_dpop_header(self.method, self.url, self.private_key)
        
        # Should not raise exception for valid claims
        claims = validate_dpop_claims(dpop_header, self.method, self.url)
        
        # Should return claims dictionary
        self.assertIsInstance(claims, dict)
        self.assertIn('htm', claims)
        self.assertIn('htu', claims)
        self.assertEqual(claims['htm'], self.method)

    def test_validate_dpop_claims_wrong_method(self):
        """Test DPoP claims validation with wrong method."""
        dpop_header = make_dpop_header("POST", self.url, self.private_key)
        
        with self.assertRaises(ValueError):
            validate_dpop_claims(dpop_header, "GET", self.url)

    def test_validate_dpop_claims_wrong_url(self):
        """Test DPoP claims validation with wrong URL."""
        dpop_header = make_dpop_header(self.method, "https://example.com/token", self.private_key)
        
        with self.assertRaises(ValueError):
            validate_dpop_claims(dpop_header, self.method, "https://different.com/token")

    def test_calculate_jwk_thumbprint(self):
        """Test JWK thumbprint calculation."""
        jwk_dict = {
            'kty': 'EC',
            'crv': 'P-256',
            'x': 'test-x-coordinate-value-here',
            'y': 'test-y-coordinate-value-here'
        }
        
        thumbprint = calculate_jwk_thumbprint(jwk_dict)
        
        # Should be a base64url encoded string
        self.assertIsInstance(thumbprint, str)
        self.assertGreater(len(thumbprint), 0)
        
        # Should be deterministic
        thumbprint2 = calculate_jwk_thumbprint(jwk_dict)
        self.assertEqual(thumbprint, thumbprint2)

    def test_calculate_jwk_thumbprint_different_keys(self):
        """Test JWK thumbprint for different keys."""
        jwk1 = {
            'kty': 'EC',
            'crv': 'P-256',
            'x': 'test-x-coordinate-1',
            'y': 'test-y-coordinate-1'
        }
        
        jwk2 = {
            'kty': 'EC',
            'crv': 'P-256',
            'x': 'test-x-coordinate-2',
            'y': 'test-y-coordinate-2'
        }
        
        thumbprint1 = calculate_jwk_thumbprint(jwk1)
        thumbprint2 = calculate_jwk_thumbprint(jwk2)
        
        # Should be different
        self.assertNotEqual(thumbprint1, thumbprint2)


class TestDPoPEdgeCases(unittest.TestCase):
    """Test DPoP edge cases and error conditions."""
    
    def setUp(self):
        """Set up test environment."""
        self.private_key = ec.generate_private_key(ec.SECP256R1())

    def test_dpop_with_query_parameters(self):
        """Test DPoP header with URL containing query parameters."""
        url_with_query = "https://example.com/token?param=value"
        
        dpop_header = make_dpop_header("POST", url_with_query, self.private_key)
        
        # Should work and strip query parameters for htu claim
        claims = validate_dpop_claims(dpop_header, "POST", url_with_query)
        
        # htu should not include query parameters
        self.assertEqual(claims['htu'], "https://example.com/token")

    def test_dpop_with_fragment(self):
        """Test DPoP header with URL containing fragment."""
        url_with_fragment = "https://example.com/token#fragment"
        
        dpop_header = make_dpop_header("POST", url_with_fragment, self.private_key)
        
        # Should work and strip fragment for htu claim
        claims = validate_dpop_claims(dpop_header, "POST", url_with_fragment)
        
        # htu should not include fragment
        self.assertEqual(claims['htu'], "https://example.com/token")

    def test_dpop_case_insensitive_method(self):
        """Test DPoP header with different case methods."""
        dpop_header = make_dpop_header("post", "https://example.com/token", self.private_key)
        
        # Should normalize to uppercase
        claims = validate_dpop_claims(dpop_header, "POST", "https://example.com/token")
        self.assertEqual(claims['htm'], "POST")

    def test_validate_dpop_expired_token(self):
        """Test validation of expired DPoP token."""
        # Create a DPoP header
        dpop_header = make_dpop_header("POST", "https://example.com/token", self.private_key)
        
        # Mock time to make it appear expired
        with patch('time.time', return_value=9999999999):  # Far future
            with self.assertRaises(ValueError):
                validate_dpop_claims(dpop_header, "POST", "https://example.com/token")

    def test_validate_dpop_malformed_jwt(self):
        """Test validation of malformed JWT."""
        with self.assertRaises(ValueError):
            validate_dpop_claims("not.a.valid.jwt.with.too.many.parts", "POST", "https://example.com/token")
        
        with self.assertRaises(ValueError):
            validate_dpop_claims("not-a-jwt", "POST", "https://example.com/token")


if __name__ == '__main__':
    unittest.main(verbosity=2)
