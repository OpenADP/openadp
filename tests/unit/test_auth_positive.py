"""
Positive authentication tests for OpenADP server Phase 2.

Tests successful authentication scenarios:
- Valid JWT + DPoP header authentication
- Proper user identification
- Auth statistics functionality
"""

import unittest
import json
import time
import os
from unittest.mock import patch, MagicMock
import sys

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from server.auth_middleware import validate_auth, get_auth_stats, AuthConfig
from openadp.auth.dpop import make_dpop_header
from openadp.auth.keys import generate_keypair

class TestPositiveAuthentication(unittest.TestCase):
    """Test successful authentication scenarios."""
    
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
        
        # Mock JWT token
        self.mock_jwt_claims = {
            'sub': 'test-user-123',
            'iss': 'http://localhost:8080/realms/openadp',
            'aud': 'cli-test',
            'exp': int(time.time()) + 300,  # 5 minutes from now
            'iat': int(time.time()),
            'cnf': {
                'jkt': 'mock-jwk-thumbprint'
            }
        }
        
        # Mock access token
        self.mock_access_token = 'mock.jwt.token'
    
    def tearDown(self):
        """Clean up test environment."""
        self.env_patcher.stop()
    
    @patch('server.auth_middleware.validate_jwt_token')
    @patch('server.auth_middleware.validate_dpop_header')
    def test_successful_authentication(self, mock_validate_dpop, mock_validate_jwt):
        """Test successful authentication with valid JWT and DPoP."""
        # Mock successful JWT validation
        mock_validate_jwt.return_value = self.mock_jwt_claims
        
        # Mock successful DPoP validation
        mock_validate_dpop.return_value = {
            'jti': 'unique-jti-123',
            'htm': 'POST',
            'htu': 'http://localhost:8080/jsonrpc',
            'iat': int(time.time()),
            'exp': int(time.time()) + 60
        }
        
        # Create test request
        headers = {
            'Authorization': f'DPoP {self.mock_access_token}',
            'DPoP': 'mock.dpop.header',
            'Content-Type': 'application/json'
        }
        
        request_body = b'{"jsonrpc":"2.0","method":"RegisterSecret","params":[],"id":1}'
        
        # Validate authentication
        user_id, error = validate_auth(
            request_body,
            headers,
            'POST',
            'http://localhost:8080/jsonrpc'
        )
        
        # Verify successful authentication
        self.assertIsNone(error)
        self.assertEqual(user_id, 'test-user-123')
        
        # Verify JWT validation was called
        mock_validate_jwt.assert_called_once_with(
            self.mock_access_token,
            'http://localhost:8080/realms/openadp/protocol/openid-connect/certs',
            'http://localhost:8080/realms/openadp'
        )
        
        # Verify DPoP validation was called
        mock_validate_dpop.assert_called_once_with(
            'mock.dpop.header',
            'POST',
            'http://localhost:8080/jsonrpc',
            self.mock_access_token
        )
    
    def test_auth_disabled_bypass(self):
        """Test that authentication is bypassed when disabled."""
        with patch.dict(os.environ, {'OPENADP_AUTH_ENABLED': '0'}):
            headers = {}
            request_body = b'{"jsonrpc":"2.0","method":"RegisterSecret","params":[],"id":1}'
            
            user_id, error = validate_auth(request_body, headers)
            
            # Should bypass authentication
            self.assertIsNone(error)
            self.assertIsNone(user_id)
    
    def test_auth_config_initialization(self):
        """Test that authentication configuration is properly initialized."""
        config = AuthConfig()
        
        self.assertTrue(config.enabled)
        self.assertEqual(config.issuer, 'http://localhost:8080/realms/openadp')
        self.assertEqual(config.jwks_url, 'http://localhost:8080/realms/openadp/protocol/openid-connect/certs')
        self.assertEqual(config.cache_ttl, 3600)
    
    def test_auth_config_auto_jwks_url(self):
        """Test that JWKS URL is auto-derived from issuer."""
        with patch.dict(os.environ, {
            'OPENADP_AUTH_ENABLED': '1',
            'OPENADP_AUTH_ISSUER': 'https://example.com/auth',
            'OPENADP_AUTH_JWKS_URL': ''  # Empty, should be auto-derived
        }):
            config = AuthConfig()
            
            self.assertEqual(config.jwks_url, 'https://example.com/auth/.well-known/jwks.json')
    
    def test_get_auth_stats(self):
        """Test authentication statistics functionality."""
        stats = get_auth_stats()
        
        self.assertIn('jti_cache_size', stats)
        self.assertIn('jwks_cache_expired', stats)
        self.assertIn('jwks_cache_ttl_remaining', stats)
        self.assertIn('config', stats)
        
        # Check config in stats
        config = stats['config']
        self.assertIn('enabled', config)
        self.assertIn('issuer', config)
        self.assertIn('jwks_url', config)
    
    @patch('server.auth_middleware.validate_jwt_token')
    @patch('server.auth_middleware.extract_jti_from_dpop')
    @patch('server.auth_middleware.validate_dpop_claims')
    def test_jti_replay_protection(self, mock_validate_dpop_claims, mock_extract_jti, mock_validate_jwt):
        """Test that JTI replay protection works correctly."""
        # Mock successful JWT validation
        mock_validate_jwt.return_value = self.mock_jwt_claims
        
        # Mock JTI extraction
        mock_extract_jti.return_value = 'test-jti-123'
        
        # Mock DPoP claims validation
        mock_validate_dpop_claims.return_value = {
            'jti': 'test-jti-123',
            'htm': 'POST',
            'htu': 'http://localhost:8080/jsonrpc',
            'iat': int(time.time()),
            'exp': int(time.time()) + 60
        }
        
        headers = {
            'Authorization': f'DPoP {self.mock_access_token}',
            'DPoP': 'mock.dpop.header'
        }
        request_body = b'{"jsonrpc":"2.0","method":"RegisterSecret","params":[],"id":1}'
        
        # First request should succeed
        user_id, error = validate_auth(request_body, headers)
        self.assertIsNone(error)
        self.assertEqual(user_id, 'test-user-123')
        
        # Second request with same JTI should fail (replay attack)
        user_id, error = validate_auth(request_body, headers)
        self.assertIsNotNone(error)
        self.assertIn('Replay attack detected', error)


class TestDPoPIntegration(unittest.TestCase):
    """Test DPoP integration with real key generation."""
    
    def setUp(self):
        """Set up test environment with real keys."""
        self.env_patcher = patch.dict(os.environ, {
            'OPENADP_AUTH_ENABLED': '1',
            'OPENADP_AUTH_ISSUER': 'http://localhost:8080/realms/openadp',
        })
        self.env_patcher.start()
        
        # Generate real keypair
        self.private_key, self.public_jwk = generate_keypair()
    
    def tearDown(self):
        """Clean up test environment."""
        self.env_patcher.stop()
    
    def test_real_dpop_header_generation(self):
        """Test DPoP header generation with real keys."""
        # Generate a real DPoP header
        access_token = 'test.access.token'
        dpop_header = make_dpop_header(
            method='POST',
            url='http://localhost:8080/jsonrpc',
            private_key=self.private_key,
            access_token=access_token
        )
        
        # Verify header is properly formatted
        self.assertIsInstance(dpop_header, str)
        parts = dpop_header.split('.')
        self.assertEqual(len(parts), 3)  # JWT format: header.payload.signature
        
        # Verify we can extract JTI
        from server.auth_middleware import extract_jti_from_dpop
        jti = extract_jti_from_dpop(dpop_header)
        self.assertIsInstance(jti, str)
        self.assertTrue(len(jti) > 0)


if __name__ == '__main__':
    unittest.main() 