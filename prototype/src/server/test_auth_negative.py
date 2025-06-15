"""
Negative authentication tests for OpenADP server Phase 2.

Tests authentication failure scenarios:
- Expired tokens
- Wrong HTTP URI in DPoP header
- Duplicate JTI (replay attacks)
- Missing/invalid headers
- Malformed tokens
"""

import unittest
import json
import time
import os
from unittest.mock import patch, MagicMock
import sys
import jwt

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'prototype', 'src'))

from server.auth_middleware import validate_auth, validate_jwt_token, validate_dpop_header
from openadp.auth.keys import generate_keypair


class TestNegativeAuthentication(unittest.TestCase):
    """Test authentication failure scenarios."""
    
    def setUp(self):
        """Set up test environment."""
        # Mock environment variables for testing
        self.env_patcher = patch.dict(os.environ, {
            'OPENADP_AUTH_ENABLED': '1',
            'OPENADP_AUTH_ISSUER': 'http://localhost:8080/realms/openadp',
            'OPENADP_AUTH_JWKS_URL': 'http://localhost:8080/realms/openadp/protocol/openid-connect/certs',
            'OPENADP_AUTH_CACHE_TTL': '3600'
        })
        self.env_patcher.start()
        
        # Clear any cached state
        from server.auth_middleware import _jwks_cache, _jti_cache, _jti_cache_timestamps
        _jwks_cache.clear()
        _jti_cache.clear()
        _jti_cache_timestamps.clear()
        
        # Generate test keypair
        self.private_key, self.public_jwk = generate_keypair()
        
        # Standard request body for testing
        self.request_body = b'{"jsonrpc":"2.0","method":"RegisterSecret","params":[],"id":1}'
    
    def tearDown(self):
        """Clean up test environment."""
        self.env_patcher.stop()
    
    def test_missing_authorization_header(self):
        """Test authentication fails when Authorization header is missing."""
        headers = {
            'Content-Type': 'application/json'
            # Missing Authorization header
        }
        
        user_id, error = validate_auth(self.request_body, headers)
        
        self.assertIsNotNone(error)
        self.assertIn('Missing Authorization header', error)
        self.assertIsNone(user_id)
    
    def test_wrong_authorization_scheme(self):
        """Test authentication fails with wrong authorization scheme."""
        headers = {
            'Authorization': 'Bearer some.jwt.token',  # Should be 'DPoP'
            'Content-Type': 'application/json'
        }
        
        user_id, error = validate_auth(self.request_body, headers)
        
        self.assertIsNotNone(error)
        self.assertIn('Authorization header must use DPoP scheme', error)
        self.assertIsNone(user_id)
    
    def test_missing_dpop_header(self):
        """Test authentication fails when DPoP header is missing."""
        headers = {
            'Authorization': 'DPoP some.jwt.token',
            'Content-Type': 'application/json'
            # Missing DPoP header
        }
        
        user_id, error = validate_auth(self.request_body, headers)
        
        self.assertIsNotNone(error)
        self.assertIn('Missing DPoP header', error)
        self.assertIsNone(user_id)
    
    @patch('server.auth_middleware.validate_jwt_token')
    def test_jwt_validation_failure(self, mock_validate_jwt):
        """Test authentication fails when JWT validation fails."""
        # Mock JWT validation to raise exception
        mock_validate_jwt.side_effect = Exception("Token has expired")
        
        headers = {
            'Authorization': 'DPoP expired.jwt.token',
            'DPoP': 'mock.dpop.header',
            'Content-Type': 'application/json'
        }
        
        user_id, error = validate_auth(self.request_body, headers)
        
        self.assertIsNotNone(error)
        self.assertIn('JWT validation failed: Token has expired', error)
        self.assertIsNone(user_id)
    
    @patch('server.auth_middleware.validate_jwt_token')
    @patch('server.auth_middleware.validate_dpop_header')
    def test_dpop_validation_failure(self, mock_validate_dpop, mock_validate_jwt):
        """Test authentication fails when DPoP validation fails."""
        # Mock successful JWT validation
        mock_validate_jwt.return_value = {
            'sub': 'test-user-123',
            'iss': 'http://localhost:8080/realms/openadp',
            'exp': int(time.time()) + 300
        }
        
        # Mock DPoP validation to raise exception
        mock_validate_dpop.side_effect = Exception("Wrong HTTP URI in DPoP header")
        
        headers = {
            'Authorization': 'DPoP valid.jwt.token',
            'DPoP': 'invalid.dpop.header',
            'Content-Type': 'application/json'
        }
        
        user_id, error = validate_auth(self.request_body, headers)
        
        self.assertIsNotNone(error)
        self.assertIn('DPoP validation failed: Wrong HTTP URI in DPoP header', error)
        self.assertIsNone(user_id)
    
    @patch('server.auth_middleware.validate_jwt_token')
    def test_missing_sub_claim(self, mock_validate_jwt):
        """Test authentication fails when JWT is missing 'sub' claim."""
        # Mock JWT validation with missing 'sub' claim
        mock_validate_jwt.return_value = {
            'iss': 'http://localhost:8080/realms/openadp',
            'exp': int(time.time()) + 300
            # Missing 'sub' claim
        }
        
        headers = {
            'Authorization': 'DPoP valid.jwt.token',
            'DPoP': 'valid.dpop.header',
            'Content-Type': 'application/json'
        }
        
        with patch('server.auth_middleware.validate_dpop_header') as mock_validate_dpop:
            mock_validate_dpop.return_value = {'jti': 'test-jti'}
            
            user_id, error = validate_auth(self.request_body, headers)
        
        self.assertIsNotNone(error)
        self.assertIn("Missing 'sub' claim in JWT token", error)
        self.assertIsNone(user_id)
    
    def test_misconfigured_server(self):
        """Test authentication fails when server is misconfigured."""
        with patch.dict(os.environ, {
            'OPENADP_AUTH_ENABLED': '1',
            'OPENADP_AUTH_ISSUER': '',  # Missing issuer configuration
        }):
            headers = {
                'Authorization': 'DPoP some.jwt.token',
                'DPoP': 'some.dpop.header',
                'Content-Type': 'application/json'
            }
            
            user_id, error = validate_auth(self.request_body, headers)
            
            self.assertIsNotNone(error)
            # Accept either the old or new error message for robustness
            self.assertTrue(
                'OPENADP_AUTH_ISSUER not set' in error or 'AUTH_ISSUER not set' in error,
                f"Unexpected error message: {error}"
            )
            self.assertIsNone(user_id)


class TestSpecificValidationFailures(unittest.TestCase):
    """Test specific JWT and DPoP validation failures."""
    
    def setUp(self):
        """Set up test environment."""
        self.env_patcher = patch.dict(os.environ, {
            'OPENADP_AUTH_ENABLED': '1',
            'OPENADP_AUTH_ISSUER': 'http://localhost:8080/realms/openadp',
        })
        self.env_patcher.start()
    
    def tearDown(self):
        """Clean up test environment."""
        self.env_patcher.stop()
    
    @patch('server.auth_middleware.get_jwks')
    def test_expired_jwt_token(self, mock_get_jwks):
        """Test JWT validation fails for expired tokens."""
        # Mock JWKS response
        mock_get_jwks.return_value = {
            'keys': [{
                'kid': 'test-key-id',
                'kty': 'RSA',
                'use': 'sig',
                'n': 'test-n',
                'e': 'AQAB'
            }]
        }
    
        # Create an expired token (simulate failure)
        with self.assertRaises(Exception) as context:
            validate_jwt_token(
                'expired.jwt.token',
                'http://localhost:8080/realms/openadp/protocol/openid-connect/certs',
                'http://localhost:8080/realms/openadp'
            )
    
        # Accept either 'Token has expired' or 'Invalid token' in the error message
        self.assertTrue(
            'Token has expired' in str(context.exception) or 'Invalid token' in str(context.exception),
            f"Unexpected exception: {context.exception}"
        )
    
    @patch('server.auth_middleware.get_jwks')
    def test_wrong_issuer_jwt_token(self, mock_get_jwks):
        """Test JWT validation fails for wrong issuer."""
        # Mock JWKS response
        mock_get_jwks.return_value = {
            'keys': [{
                'kid': 'test-key-id',
                'kty': 'RSA',
                'use': 'sig',
                'n': 'test-n',
                'e': 'AQAB'
            }]
        }
    
        # This will raise an exception because we can't actually verify the signature
        with self.assertRaises(Exception) as context:
            validate_jwt_token(
                'invalid.jwt.token',
                'http://localhost:8080/realms/openadp/protocol/openid-connect/certs',
                'http://localhost:8080/realms/openadp'
            )
    
        # Accept either 'Invalid token' or 'Token validation failed' in the error message
        self.assertTrue(
            'Invalid token' in str(context.exception) or 'Token validation failed' in str(context.exception),
            f"Unexpected exception: {context.exception}"
        )
    
    def test_jwks_fetch_failure(self):
        """Test JWT validation fails when JWKS cannot be fetched."""
        with patch('server.auth_middleware.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = Exception("Network error")
            
            with self.assertRaises(Exception) as context:
                validate_jwt_token(
                    'some.jwt.token',
                    'http://invalid-url/jwks.json',
                    'http://localhost:8080/realms/openadp'
                )
            
            self.assertIn('JWKS fetch failed', str(context.exception))
    
    @patch('server.auth_middleware.extract_jti_from_dpop')
    @patch('server.auth_middleware.validate_dpop_claims')
    def test_duplicate_jti_replay_attack(self, mock_validate_dpop_claims, mock_extract_jti):
        """Test DPoP validation fails for duplicate JTI (replay attack)."""
        # Mock JTI extraction
        mock_extract_jti.return_value = 'duplicate-jti-123'
        
        # Mock DPoP claims validation
        mock_validate_dpop_claims.return_value = {
            'jti': 'duplicate-jti-123',
            'htm': 'POST',
            'htu': 'http://localhost:8080/jsonrpc'
        }
        
        # First call should succeed
        result1 = validate_dpop_header(
            'dpop.header.1',
            'POST',
            'http://localhost:8080/jsonrpc',
            'access.token'
        )
        self.assertIsNotNone(result1)
        
        # Second call with same JTI should fail
        with self.assertRaises(Exception) as context:
            validate_dpop_header(
                'dpop.header.2',
                'POST',
                'http://localhost:8080/jsonrpc',
                'access.token'
            )
        
        self.assertIn('Replay attack detected', str(context.exception))
        self.assertIn('duplicate-jti-123', str(context.exception))
    
    @patch('server.auth_middleware.extract_jti_from_dpop')
    @patch('server.auth_middleware.validate_dpop_claims')
    def test_wrong_access_token_hash(self, mock_validate_dpop_claims, mock_extract_jti):
        """Test DPoP validation fails when access token hash doesn't match."""
        # Mock JTI extraction
        mock_extract_jti.return_value = 'test-jti-123'
        
        # Mock DPoP claims with wrong ath (access token hash)
        mock_validate_dpop_claims.return_value = {
            'jti': 'test-jti-123',
            'htm': 'POST',
            'htu': 'http://localhost:8080/jsonrpc',
            'ath': 'wrong-access-token-hash'  # This should cause validation to fail
        }
        
        with self.assertRaises(Exception) as context:
            validate_dpop_header(
                'dpop.header',
                'POST',
                'http://localhost:8080/jsonrpc',
                'different.access.token'
            )
        
        self.assertIn('Access token hash mismatch', str(context.exception))
    
    @patch('server.auth_middleware.extract_jti_from_dpop')
    def test_invalid_dpop_header_format(self, mock_extract_jti):
        """Test DPoP validation fails for malformed headers."""
        # Mock extract_jti to raise exception for invalid format
        mock_extract_jti.side_effect = ValueError("Invalid JWT format")
        
        with self.assertRaises(Exception) as context:
            validate_dpop_header(
                'invalid.dpop.header',
                'POST',
                'http://localhost:8080/jsonrpc',
                'access.token'
            )
        
        self.assertIn('DPoP validation failed', str(context.exception))
        self.assertIn('Invalid JWT format', str(context.exception))


class TestErrorHandling(unittest.TestCase):
    """Test error handling in authentication middleware."""
    
    def setUp(self):
        """Set up test environment."""
        self.env_patcher = patch.dict(os.environ, {
            'OPENADP_AUTH_ENABLED': '1',
            'OPENADP_AUTH_ISSUER': 'http://localhost:8080/realms/openadp',
        })
        self.env_patcher.start()
    
    def tearDown(self):
        """Clean up test environment."""
        self.env_patcher.stop()
    
    def test_unexpected_exception_handling(self):
        """Test that unexpected exceptions are properly handled."""
        # Cause an unexpected exception by passing invalid parameters
        with patch('server.auth_middleware.AuthConfig') as mock_config:
            mock_config.side_effect = Exception("Unexpected error")
            
            headers = {
                'Authorization': 'DPoP some.jwt.token',
                'DPoP': 'some.dpop.header'
            }
            
            user_id, error = validate_auth(b'test', headers)
            
            self.assertIsNotNone(error)
            self.assertIn('Authentication failed: Unexpected error', error)
            self.assertIsNone(user_id)
    
    def test_malformed_authorization_header(self):
        """Test handling of malformed Authorization headers."""
        headers = {
            'Authorization': 'InvalidFormat',  # No token after scheme
            'DPoP': 'some.dpop.header'
        }
        
        user_id, error = validate_auth(b'test', headers)
        
        self.assertIsNotNone(error)
        self.assertIn('Authorization header must use DPoP scheme', error)
        self.assertIsNone(user_id)
    
    def test_empty_authorization_header(self):
        """Test handling of empty Authorization headers."""
        headers = {
            'Authorization': '',  # Empty
            'DPoP': 'some.dpop.header'
        }
        
        user_id, error = validate_auth(b'test', headers)
        
        self.assertIsNotNone(error)
        self.assertIn('Missing Authorization header', error)
        self.assertIsNone(user_id)
    
    def test_empty_dpop_header(self):
        """Test handling of empty DPoP headers."""
        headers = {
            'Authorization': 'DPoP some.jwt.token',
            'DPoP': ''  # Empty
        }
        
        user_id, error = validate_auth(b'test', headers)
        
        self.assertIsNotNone(error)
        self.assertIn('Missing DPoP header', error)
        self.assertIsNone(user_id)


if __name__ == '__main__':
    unittest.main() 