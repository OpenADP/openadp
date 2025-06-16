"""
Unit tests for OpenADP DPoP header generation and validation.

Tests DPoP header creation, validation, and security properties.
"""

import json
import time
import unittest
from unittest.mock import patch
import base64

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'prototype', 'src'))

from openadp.auth.keys import generate_keypair
from openadp.auth.dpop import (
    make_dpop_header,
    extract_jti_from_dpop,
    validate_dpop_claims
)


class TestDPoP(unittest.TestCase):
    """Test cases for DPoP header functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.private_key, self.public_jwk = generate_keypair()
        self.test_url = "https://api.example.com/jsonrpc"
        self.test_method = "POST"
        self.test_token = "test_access_token_12345"
    
    def test_make_dpop_header_basic(self):
        """Test basic DPoP header generation."""
        dpop_header = make_dpop_header(
            self.test_method, 
            self.test_url, 
            self.private_key
        )
        
        # Should be a valid JWT format (3 parts separated by dots)
        parts = dpop_header.split('.')
        self.assertEqual(len(parts), 3)
        
        # Decode and verify header
        header_b64 = parts[0]
        # Add padding if needed
        padding = 4 - (len(header_b64) % 4)
        if padding != 4:
            header_b64 += '=' * padding
        
        header_bytes = base64.urlsafe_b64decode(header_b64)
        header = json.loads(header_bytes.decode('utf-8'))
        
        # Verify header structure
        self.assertEqual(header['typ'], 'dpop+jwt')
        self.assertEqual(header['alg'], 'ES256')
        self.assertIn('jwk', header)
        
        # Verify JWK in header matches our public key
        header_jwk = header['jwk']
        self.assertEqual(header_jwk['kty'], 'EC')
        self.assertEqual(header_jwk['crv'], 'P-256')
        self.assertEqual(header_jwk['x'], self.public_jwk['x'])
        self.assertEqual(header_jwk['y'], self.public_jwk['y'])
    
    def test_make_dpop_header_with_token(self):
        """Test DPoP header generation with access token."""
        dpop_header = make_dpop_header(
            self.test_method,
            self.test_url,
            self.private_key,
            self.test_token
        )
        
        # Decode payload
        parts = dpop_header.split('.')
        payload_b64 = parts[1]
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += '=' * padding
        
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        # Should contain ath claim (access token hash)
        self.assertIn('ath', payload)
        
        # Verify ath is base64url encoded (no padding)
        self.assertNotIn('=', payload['ath'])
    
    def test_dpop_payload_claims(self):
        """Test DPoP payload contains required claims."""
        with patch('time.time', return_value=1234567890):
            dpop_header = make_dpop_header(
                self.test_method,
                self.test_url,
                self.private_key
            )
        
        # Decode payload
        parts = dpop_header.split('.')
        payload_b64 = parts[1]
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += '=' * padding
        
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        # Verify required claims
        required_claims = ['jti', 'htm', 'htu', 'iat', 'exp']
        for claim in required_claims:
            self.assertIn(claim, payload)
        
        # Verify claim values
        self.assertEqual(payload['htm'], 'POST')
        self.assertEqual(payload['htu'], 'https://api.example.com/jsonrpc')
        self.assertEqual(payload['iat'], 1234567890)
        self.assertEqual(payload['exp'], 1234567890 + 60)  # 60 seconds later
        
        # jti should be a UUID string
        self.assertIsInstance(payload['jti'], str)
        self.assertGreater(len(payload['jti']), 30)  # UUIDs are longer than 30 chars
    
    def test_jti_uniqueness(self):
        """Test that jti values are unique across multiple headers."""
        headers = []
        jtis = set()
        
        # Generate multiple headers
        for _ in range(10):
            header = make_dpop_header(
                self.test_method,
                self.test_url,
                self.private_key
            )
            headers.append(header)
            
            # Extract jti
            jti = extract_jti_from_dpop(header)
            jtis.add(jti)
        
        # All jtis should be unique
        self.assertEqual(len(jtis), 10)
    
    def test_extract_jti_from_dpop(self):
        """Test extracting jti from DPoP header."""
        dpop_header = make_dpop_header(
            self.test_method,
            self.test_url,
            self.private_key
        )
        
        jti = extract_jti_from_dpop(dpop_header)
        
        # Should be a non-empty string
        self.assertIsInstance(jti, str)
        self.assertGreater(len(jti), 0)
    
    def test_extract_jti_invalid_header(self):
        """Test extracting jti from invalid DPoP header."""
        # Invalid JWT format
        with self.assertRaises(ValueError):
            extract_jti_from_dpop("invalid.jwt")
        
        # Missing jti claim
        header = {"typ": "dpop+jwt", "alg": "ES256"}
        payload = {"htm": "POST", "htu": "https://example.com"}
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode('utf-8')
        ).decode('ascii').rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode('utf-8')
        ).decode('ascii').rstrip('=')
        
        invalid_jwt = f"{header_b64}.{payload_b64}.fake_signature"
        
        with self.assertRaises(ValueError):
            extract_jti_from_dpop(invalid_jwt)
    
    def test_validate_dpop_claims_success(self):
        """Test successful DPoP claims validation."""
        dpop_header = make_dpop_header(
            self.test_method,
            self.test_url,
            self.private_key
        )
        
        # Should validate successfully
        claims = validate_dpop_claims(
            dpop_header,
            self.test_method,
            self.test_url
        )
        
        # Should return the claims
        self.assertIsInstance(claims, dict)
        self.assertIn('jti', claims)
        self.assertIn('htm', claims)
        self.assertIn('htu', claims)
        self.assertEqual(claims['htm'], 'POST')
        self.assertEqual(claims['htu'], 'https://api.example.com/jsonrpc')
    
    def test_validate_dpop_claims_wrong_method(self):
        """Test DPoP validation fails with wrong HTTP method."""
        dpop_header = make_dpop_header(
            "POST",
            self.test_url,
            self.private_key
        )
        
        # Should fail with wrong method
        with self.assertRaises(ValueError) as cm:
            validate_dpop_claims(dpop_header, "GET", self.test_url)
        
        self.assertIn("HTTP method mismatch", str(cm.exception))
    
    def test_validate_dpop_claims_wrong_url(self):
        """Test DPoP validation fails with wrong URL."""
        dpop_header = make_dpop_header(
            self.test_method,
            self.test_url,
            self.private_key
        )
        
        # Should fail with wrong URL
        with self.assertRaises(ValueError) as cm:
            validate_dpop_claims(
                dpop_header, 
                self.test_method, 
                "https://different.example.com/api"
            )
        
        self.assertIn("HTTP URI mismatch", str(cm.exception))
    
    def test_validate_dpop_claims_old_timestamp(self):
        """Test DPoP validation fails with old timestamp."""
        # Create header with old timestamp
        with patch('time.time', return_value=1000000000):  # Very old timestamp
            dpop_header = make_dpop_header(
                self.test_method,
                self.test_url,
                self.private_key
            )
        
        # Should fail due to old timestamp
        with self.assertRaises(ValueError) as cm:
            validate_dpop_claims(dpop_header, self.test_method, self.test_url)
        
        self.assertIn("timestamp too old", str(cm.exception))
    
    def test_validate_dpop_claims_future_timestamp(self):
        """Test DPoP validation fails with future timestamp."""
        # Create header with future timestamp
        future_time = int(time.time()) + 300  # 5 minutes in future
        with patch('time.time', return_value=future_time):
            dpop_header = make_dpop_header(
                self.test_method,
                self.test_url,
                self.private_key
            )
        
        # Should fail due to future timestamp
        with self.assertRaises(ValueError) as cm:
            validate_dpop_claims(dpop_header, self.test_method, self.test_url)
        
        self.assertIn("timestamp too old or too new", str(cm.exception))
    
    def test_validate_dpop_claims_expired(self):
        """Test DPoP validation fails with expired header."""
        # Create header with recent timestamp but short expiration
        current_time = int(time.time())
        with patch('time.time', return_value=current_time):
            dpop_header = make_dpop_header(
                self.test_method,
                self.test_url,
                self.private_key
            )
        
        # Wait for expiration (simulate time passing)
        with patch('time.time', return_value=current_time + 120):  # 2 minutes later
            # Should fail due to expiration
            with self.assertRaises(ValueError) as cm:
                validate_dpop_claims(dpop_header, self.test_method, self.test_url)
            
            self.assertIn("has expired", str(cm.exception))
    
    def test_url_normalization(self):
        """Test that URLs are properly normalized for htu claim."""
        # Test with query parameters and fragment
        url_with_query = "https://api.example.com/jsonrpc?param=value#fragment"
        
        dpop_header = make_dpop_header(
            self.test_method,
            url_with_query,
            self.private_key
        )
        
        # Should validate against base URL without query/fragment
        claims = validate_dpop_claims(
            dpop_header,
            self.test_method,
            "https://api.example.com/jsonrpc"
        )
        
        self.assertEqual(claims['htu'], 'https://api.example.com/jsonrpc')
    
    def test_case_insensitive_method(self):
        """Test that HTTP methods are case-insensitive."""
        dpop_header = make_dpop_header(
            "post",  # lowercase
            self.test_url,
            self.private_key
        )
        
        # Should validate against uppercase method
        claims = validate_dpop_claims(dpop_header, "POST", self.test_url)
        self.assertEqual(claims['htm'], 'POST')  # Should be normalized to uppercase
    
    def test_signature_format(self):
        """Test that DPoP signature is in correct format."""
        dpop_header = make_dpop_header(
            self.test_method,
            self.test_url,
            self.private_key
        )
        
        parts = dpop_header.split('.')
        signature_b64 = parts[2]
        
        # Should be base64url encoded (no padding)
        self.assertNotIn('=', signature_b64)
        self.assertNotIn('+', signature_b64)
        self.assertNotIn('/', signature_b64)
        
        # Should decode to 64 bytes (32 bytes r + 32 bytes s for P-256)
        signature_bytes = base64.urlsafe_b64decode(signature_b64 + '==')  # Add padding for decode
        self.assertEqual(len(signature_bytes), 64)


if __name__ == '__main__':
    unittest.main() 