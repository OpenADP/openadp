#!/usr/bin/env python3
"""
Comprehensive unit tests for openadp.auth.device_flow module.

Tests OAuth 2.0 Device Code flow implementation including security-critical
authentication paths, error handling, and edge cases.
"""

import unittest
import sys
import os
import json
import time
from unittest.mock import Mock, patch, MagicMock
from unittest.mock import call
import requests

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from openadp.auth import device_flow
from openadp.auth.device_flow import DeviceFlowError, run_device_flow, refresh_access_token, validate_token_response, get_userinfo
from cryptography.hazmat.primitives.asymmetric import ec


class TestDeviceFlow(unittest.TestCase):
    """Test device flow authentication comprehensively."""
    
    def setUp(self):
        """Set up test environment."""
        self.issuer_url = "https://auth.example.com/realms/test"
        self.client_id = "test-client"
        self.scopes = "openid email profile"
        
        # Mock discovery document
        self.discovery_doc = {
            'device_authorization_endpoint': 'https://auth.example.com/device',
            'token_endpoint': 'https://auth.example.com/token',
            'authorization_endpoint': 'https://auth.example.com/auth',
            'userinfo_endpoint': 'https://auth.example.com/userinfo'
        }
        
        # Mock device authorization response
        self.device_auth_response = {
            'device_code': 'test-device-code-12345',
            'user_code': 'ABCD-EFGH',
            'verification_uri': 'https://auth.example.com/device',
            'verification_uri_complete': 'https://auth.example.com/device?user_code=ABCD-EFGH',
            'expires_in': 600,
            'interval': 5
        }
        
        # Mock successful token response
        self.token_response = {
            'access_token': 'test-access-token-12345',
            'refresh_token': 'test-refresh-token-12345',
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': 'openid email profile'
        }

    @patch('openadp.auth.device_flow.requests.get')
    @patch('openadp.auth.device_flow.requests.post')
    @patch('openadp.auth.device_flow.generate_keypair')
    @patch('builtins.input', return_value='')
    @patch('builtins.print')
    @patch('time.sleep')
    def test_successful_device_flow(self, mock_sleep, mock_print, mock_input, mock_generate_keypair, mock_post, mock_get):
        """Test successful device flow completion."""
        # Mock keypair generation
        mock_private_key = Mock()
        mock_public_jwk = {'kty': 'EC', 'crv': 'P-256', 'x': 'test-x', 'y': 'test-y'}
        mock_generate_keypair.return_value = (mock_private_key, mock_public_jwk)
        
        # Mock discovery request
        mock_discovery_response = Mock()
        mock_discovery_response.json.return_value = self.discovery_doc
        mock_discovery_response.raise_for_status.return_value = None
        mock_get.return_value = mock_discovery_response
        
        # Mock device authorization request
        mock_device_auth_response = Mock()
        mock_device_auth_response.json.return_value = self.device_auth_response
        mock_device_auth_response.raise_for_status.return_value = None
        
        # Mock token request (success on first try)
        mock_token_response = Mock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = self.token_response
        mock_token_response.raise_for_status.return_value = None
        
        mock_post.side_effect = [mock_device_auth_response, mock_token_response]
        
        # Run device flow
        result = run_device_flow(self.issuer_url, self.client_id, self.scopes)
        
        # Verify result
        self.assertEqual(result['access_token'], 'test-access-token-12345')
        self.assertEqual(result['refresh_token'], 'test-refresh-token-12345')
        self.assertEqual(result['token_type'], 'Bearer')
        self.assertEqual(result['expires_in'], 3600)
        self.assertEqual(result['scope'], 'openid email profile')
        self.assertEqual(result['jwk_public'], mock_public_jwk)
        self.assertEqual(result['private_key'], mock_private_key)
        
        # Verify API calls
        mock_get.assert_called_once()
        self.assertEqual(mock_post.call_count, 2)

    @patch('openadp.auth.device_flow.requests.get')
    def test_discovery_failure(self, mock_get):
        """Test failure during endpoint discovery."""
        # Mock failed discovery request
        mock_get.side_effect = requests.RequestException("Connection failed")
        
        with self.assertRaises(DeviceFlowError) as context:
            run_device_flow(self.issuer_url, self.client_id)
        
        self.assertIn("Failed to discover OAuth endpoints", str(context.exception))

    @patch('openadp.auth.device_flow.requests.get')
    def test_missing_device_endpoint(self, mock_get):
        """Test missing device authorization endpoint in discovery."""
        # Mock discovery response without device endpoint
        incomplete_discovery = {
            'token_endpoint': 'https://auth.example.com/token'
        }
        
        mock_response = Mock()
        mock_response.json.return_value = incomplete_discovery
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        with self.assertRaises(DeviceFlowError) as context:
            run_device_flow(self.issuer_url, self.client_id)
        
        self.assertIn("Device authorization endpoint not found", str(context.exception))

    @patch('openadp.auth.device_flow.requests.get')
    def test_missing_token_endpoint(self, mock_get):
        """Test missing token endpoint in discovery."""
        # Mock discovery response without token endpoint
        incomplete_discovery = {
            'device_authorization_endpoint': 'https://auth.example.com/device'
        }
        
        mock_response = Mock()
        mock_response.json.return_value = incomplete_discovery
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        with self.assertRaises(DeviceFlowError) as context:
            run_device_flow(self.issuer_url, self.client_id)
        
        self.assertIn("Token endpoint not found", str(context.exception))

    @patch('openadp.auth.device_flow.requests.get')
    @patch('openadp.auth.device_flow.requests.post')
    @patch('openadp.auth.device_flow.generate_keypair')
    def test_device_authorization_failure(self, mock_generate_keypair, mock_post, mock_get):
        """Test failure during device authorization request."""
        # Mock keypair generation
        mock_private_key = Mock()
        mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
        mock_generate_keypair.return_value = (mock_private_key, mock_public_jwk)
        
        # Mock successful discovery
        mock_discovery_response = Mock()
        mock_discovery_response.json.return_value = self.discovery_doc
        mock_discovery_response.raise_for_status.return_value = None
        mock_get.return_value = mock_discovery_response
        
        # Mock failed device authorization
        mock_post.side_effect = requests.RequestException("Device auth failed")
        
        with self.assertRaises(DeviceFlowError) as context:
            run_device_flow(self.issuer_url, self.client_id)
        
        self.assertIn("Device authorization request failed", str(context.exception))

    @patch('openadp.auth.device_flow.requests.get')
    @patch('openadp.auth.device_flow.requests.post')
    @patch('openadp.auth.device_flow.generate_keypair')
    def test_incomplete_device_response(self, mock_generate_keypair, mock_post, mock_get):
        """Test incomplete device authorization response."""
        # Mock keypair generation
        mock_private_key = Mock()
        mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
        mock_generate_keypair.return_value = (mock_private_key, mock_public_jwk)
        
        # Mock successful discovery
        mock_discovery_response = Mock()
        mock_discovery_response.json.return_value = self.discovery_doc
        mock_discovery_response.raise_for_status.return_value = None
        mock_get.return_value = mock_discovery_response
        
        # Mock incomplete device authorization response
        incomplete_response = {
            'device_code': 'test-device-code',
            # Missing user_code and verification_uri
        }
        
        mock_device_response = Mock()
        mock_device_response.json.return_value = incomplete_response
        mock_device_response.raise_for_status.return_value = None
        mock_post.return_value = mock_device_response
        
        with self.assertRaises(DeviceFlowError) as context:
            run_device_flow(self.issuer_url, self.client_id)
        
        self.assertIn("Incomplete device authorization response", str(context.exception))

    @patch('openadp.auth.device_flow.requests.get')
    @patch('openadp.auth.device_flow.requests.post')
    @patch('openadp.auth.device_flow.generate_keypair')
    @patch('builtins.input', return_value='')
    @patch('builtins.print')
    @patch('time.sleep')
    def test_authorization_pending_then_success(self, mock_sleep, mock_print, mock_input, mock_generate_keypair, mock_post, mock_get):
        """Test authorization pending followed by success."""
        # Mock keypair generation
        mock_private_key = Mock()
        mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
        mock_generate_keypair.return_value = (mock_private_key, mock_public_jwk)
        
        # Mock successful discovery
        mock_discovery_response = Mock()
        mock_discovery_response.json.return_value = self.discovery_doc
        mock_discovery_response.raise_for_status.return_value = None
        mock_get.return_value = mock_discovery_response
        
        # Mock device authorization
        mock_device_auth_response = Mock()
        mock_device_auth_response.json.return_value = self.device_auth_response
        mock_device_auth_response.raise_for_status.return_value = None
        
        # Mock token requests - first pending, then success
        mock_pending_response = Mock()
        mock_pending_response.status_code = 400
        mock_pending_response.json.return_value = {'error': 'authorization_pending'}
        
        mock_success_response = Mock()
        mock_success_response.status_code = 200
        mock_success_response.json.return_value = self.token_response
        
        mock_post.side_effect = [mock_device_auth_response, mock_pending_response, mock_success_response]
        
        # Run device flow
        result = run_device_flow(self.issuer_url, self.client_id, timeout=30)
        
        # Verify success
        self.assertEqual(result['access_token'], 'test-access-token-12345')
        
        # Verify polling occurred
        self.assertEqual(mock_post.call_count, 3)
        mock_sleep.assert_called()

    @patch('openadp.auth.device_flow.requests.get')
    @patch('openadp.auth.device_flow.requests.post')
    @patch('openadp.auth.device_flow.generate_keypair')
    @patch('builtins.input', return_value='')
    @patch('builtins.print')
    def test_expired_token_error(self, mock_print, mock_input, mock_generate_keypair, mock_post, mock_get):
        """Test expired token error."""
        # Mock keypair generation
        mock_private_key = Mock()
        mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
        mock_generate_keypair.return_value = (mock_private_key, mock_public_jwk)
        
        # Mock successful discovery
        mock_discovery_response = Mock()
        mock_discovery_response.json.return_value = self.discovery_doc
        mock_discovery_response.raise_for_status.return_value = None
        mock_get.return_value = mock_discovery_response
        
        # Mock device authorization
        mock_device_auth_response = Mock()
        mock_device_auth_response.json.return_value = self.device_auth_response
        mock_device_auth_response.raise_for_status.return_value = None
        
        # Mock expired token response
        mock_expired_response = Mock()
        mock_expired_response.status_code = 400
        mock_expired_response.json.return_value = {'error': 'expired_token'}
        
        mock_post.side_effect = [mock_device_auth_response, mock_expired_response]
        
        with self.assertRaises(DeviceFlowError) as context:
            run_device_flow(self.issuer_url, self.client_id)
        
        self.assertIn("Device code expired", str(context.exception))

    @patch('openadp.auth.device_flow.requests.get')
    @patch('openadp.auth.device_flow.requests.post')
    @patch('openadp.auth.device_flow.generate_keypair')
    @patch('builtins.input', return_value='')
    @patch('builtins.print')
    def test_access_denied_error(self, mock_print, mock_input, mock_generate_keypair, mock_post, mock_get):
        """Test access denied error."""
        # Mock keypair generation
        mock_private_key = Mock()
        mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
        mock_generate_keypair.return_value = (mock_private_key, mock_public_jwk)
        
        # Mock successful discovery
        mock_discovery_response = Mock()
        mock_discovery_response.json.return_value = self.discovery_doc
        mock_discovery_response.raise_for_status.return_value = None
        mock_get.return_value = mock_discovery_response
        
        # Mock device authorization
        mock_device_auth_response = Mock()
        mock_device_auth_response.json.return_value = self.device_auth_response
        mock_device_auth_response.raise_for_status.return_value = None
        
        # Mock access denied response
        mock_denied_response = Mock()
        mock_denied_response.status_code = 400
        mock_denied_response.json.return_value = {'error': 'access_denied'}
        
        mock_post.side_effect = [mock_device_auth_response, mock_denied_response]
        
        with self.assertRaises(DeviceFlowError) as context:
            run_device_flow(self.issuer_url, self.client_id)
        
        self.assertIn("User denied authorization", str(context.exception))

    def test_with_existing_private_key(self):
        """Test device flow with existing private key."""
        # Generate a real private key
        private_key = ec.generate_private_key(ec.SECP256R1())
        
        with patch('openadp.auth.device_flow.requests.get') as mock_get, \
             patch('openadp.auth.device_flow.requests.post') as mock_post, \
             patch('openadp.auth.device_flow.private_key_to_jwk') as mock_private_key_to_jwk, \
             patch('builtins.input', return_value=''), \
             patch('builtins.print'):
            
            # Mock private_key_to_jwk
            mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
            mock_private_key_to_jwk.return_value = mock_public_jwk
            
            # Mock successful discovery
            mock_discovery_response = Mock()
            mock_discovery_response.json.return_value = self.discovery_doc
            mock_discovery_response.raise_for_status.return_value = None
            mock_get.return_value = mock_discovery_response
            
            # Mock device authorization and token responses
            mock_device_auth_response = Mock()
            mock_device_auth_response.json.return_value = self.device_auth_response
            mock_device_auth_response.raise_for_status.return_value = None
            
            mock_token_response = Mock()
            mock_token_response.status_code = 200
            mock_token_response.json.return_value = self.token_response
            
            mock_post.side_effect = [mock_device_auth_response, mock_token_response]
            
            # Run device flow with existing key
            result = run_device_flow(self.issuer_url, self.client_id, private_key=private_key)
            
            # Verify the same private key is returned
            self.assertEqual(result['private_key'], private_key)
            self.assertEqual(result['jwk_public'], mock_public_jwk)
            
            # Verify private_key_to_jwk was called instead of generate_keypair
            mock_private_key_to_jwk.assert_called_once_with(private_key)


class TestRefreshToken(unittest.TestCase):
    """Test refresh token functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.issuer_url = "https://auth.example.com/realms/test"
        self.client_id = "test-client"
        self.refresh_token = "test-refresh-token"
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        
        self.discovery_doc = {
            'token_endpoint': 'https://auth.example.com/token'
        }
        
        self.refresh_response = {
            'access_token': 'new-access-token',
            'refresh_token': 'new-refresh-token',
            'token_type': 'Bearer',
            'expires_in': 3600
        }

    @patch('openadp.auth.device_flow.requests.get')
    @patch('openadp.auth.device_flow.requests.post')
    def test_successful_refresh(self, mock_post, mock_get):
        """Test successful token refresh."""
        # Mock discovery
        mock_discovery_response = Mock()
        mock_discovery_response.json.return_value = self.discovery_doc
        mock_discovery_response.raise_for_status.return_value = None
        mock_get.return_value = mock_discovery_response
        
        # Mock refresh response
        mock_refresh_response = Mock()
        mock_refresh_response.json.return_value = self.refresh_response
        mock_refresh_response.raise_for_status.return_value = None
        mock_post.return_value = mock_refresh_response
        
        # Test refresh
        result = refresh_access_token(self.issuer_url, self.client_id, self.refresh_token, self.private_key)
        
        # Verify result
        self.assertEqual(result['access_token'], 'new-access-token')
        self.assertEqual(result['refresh_token'], 'new-refresh-token')

    @patch('openadp.auth.device_flow.requests.get')
    def test_refresh_discovery_failure(self, mock_get):
        """Test refresh with discovery failure."""
        mock_get.side_effect = requests.RequestException("Discovery failed")
        
        with self.assertRaises(DeviceFlowError) as context:
            refresh_access_token(self.issuer_url, self.client_id, self.refresh_token, self.private_key)
        
        self.assertIn("Failed to discover OAuth endpoints", str(context.exception))


class TestTokenValidation(unittest.TestCase):
    """Test token validation functionality."""
    
    def test_valid_token_response(self):
        """Test validation of valid token response."""
        valid_token = {
            'access_token': 'test-token',
            'token_type': 'Bearer',
            'expires_in': 3600
        }
        
        # Should not raise exception
        validate_token_response(valid_token)

    def test_missing_access_token(self):
        """Test validation with missing access token."""
        invalid_token = {
            'token_type': 'Bearer',
            'expires_in': 3600
        }
        
        with self.assertRaises(DeviceFlowError) as context:
            validate_token_response(invalid_token)
        
        self.assertIn("access_token", str(context.exception))


class TestUserInfo(unittest.TestCase):
    """Test userinfo endpoint functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.issuer_url = "https://auth.example.com/realms/test"
        self.access_token = "test-access-token"
        
        self.discovery_doc = {
            'userinfo_endpoint': 'https://auth.example.com/userinfo'
        }
        
        self.userinfo_response = {
            'sub': '12345',
            'email': 'test@example.com',
            'name': 'Test User'
        }

    @patch('openadp.auth.device_flow.requests.get')
    def test_successful_userinfo(self, mock_get):
        """Test successful userinfo retrieval."""
        # Mock discovery
        mock_discovery_response = Mock()
        mock_discovery_response.json.return_value = self.discovery_doc
        mock_discovery_response.raise_for_status.return_value = None
        
        # Mock userinfo response
        mock_userinfo_response = Mock()
        mock_userinfo_response.json.return_value = self.userinfo_response
        mock_userinfo_response.raise_for_status.return_value = None
        
        mock_get.side_effect = [mock_discovery_response, mock_userinfo_response]
        
        # Test userinfo
        result = get_userinfo(self.issuer_url, self.access_token)
        
        # Verify result
        self.assertEqual(result['sub'], '12345')
        self.assertEqual(result['email'], 'test@example.com')
        self.assertEqual(result['name'], 'Test User')

    @patch('openadp.auth.device_flow.requests.get')
    def test_missing_userinfo_endpoint(self, mock_get):
        """Test missing userinfo endpoint."""
        # Mock discovery without userinfo endpoint
        incomplete_discovery = {
            'token_endpoint': 'https://auth.example.com/token'
        }
        
        mock_response = Mock()
        mock_response.json.return_value = incomplete_discovery
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        with self.assertRaises(DeviceFlowError) as context:
            get_userinfo(self.issuer_url, self.access_token)
        
        self.assertIn("Userinfo endpoint not found", str(context.exception))


if __name__ == '__main__':
    unittest.main(verbosity=2)
