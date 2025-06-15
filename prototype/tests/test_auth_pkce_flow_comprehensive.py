#!/usr/bin/env python3
"""
Comprehensive unit tests for openadp.auth.pkce_flow module.

Tests OAuth 2.0 Authorization Code flow with PKCE and DPoP support.
"""

import unittest
import sys
import os
import base64
import hashlib
import secrets
from unittest.mock import Mock, patch, MagicMock
from http.server import HTTPServer
import requests

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp.auth.pkce_flow import PKCEFlowError, generate_pkce_challenge, run_pkce_flow, CallbackHandler, refresh_access_token_pkce
from cryptography.hazmat.primitives.asymmetric import ec


class TestPKCEChallenge(unittest.TestCase):
    """Test PKCE challenge generation."""
    
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


class TestCallbackHandler(unittest.TestCase):
    """Test OAuth callback handler."""
    
    def setUp(self):
        """Set up test environment."""
        self.server = Mock()
        self.server.auth_code = None
        self.server.auth_state = None
        self.server.auth_error = None
        
    def test_callback_handler_success(self):
        """Test successful callback handling."""
        handler = CallbackHandler(Mock(), ('127.0.0.1', 12345), self.server)
        handler.path = '/callback?code=test-code&state=test-state'
        
        # Mock response methods
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.wfile = Mock()
        handler.wfile.write = Mock()
        
        # Process request
        handler.do_GET()
        
        # Verify code and state were captured
        self.assertEqual(self.server.auth_code, 'test-code')
        self.assertEqual(self.server.auth_state, 'test-state')
        self.assertIsNone(self.server.auth_error)
        
        # Verify response was sent
        handler.send_response.assert_called_with(200)
        handler.wfile.write.assert_called()

    def test_callback_handler_error(self):
        """Test error callback handling."""
        handler = CallbackHandler(Mock(), ('127.0.0.1', 12345), self.server)
        handler.path = '/callback?error=access_denied&error_description=User+denied'
        
        # Mock response methods
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.wfile = Mock()
        handler.wfile.write = Mock()
        
        # Process request
        handler.do_GET()
        
        # Verify error was captured
        self.assertEqual(self.server.auth_error, 'access_denied')
        self.assertIsNone(self.server.auth_code)
        
        # Verify error response was sent
        handler.send_response.assert_called_with(200)
        handler.wfile.write.assert_called()


class TestPKCEFlow(unittest.TestCase):
    """Test PKCE flow functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.issuer_url = "https://auth.example.com/realms/test"
        self.client_id = "test-client"
        self.scopes = "openid email profile"
        
        self.discovery_doc = {
            'authorization_endpoint': 'https://auth.example.com/auth',
            'token_endpoint': 'https://auth.example.com/token'
        }
        
        self.token_response = {
            'access_token': 'test-access-token',
            'refresh_token': 'test-refresh-token',
            'token_type': 'DPoP',
            'expires_in': 3600,
            'scope': 'openid email profile'
        }

    @patch('openadp.auth.pkce_flow.requests.get')
    @patch('openadp.auth.pkce_flow.webbrowser.open')
    @patch('openadp.auth.pkce_flow.HTTPServer')
    @patch('openadp.auth.pkce_flow.generate_keypair')
    def test_discovery_failure_with_fallback(self, mock_generate_keypair, mock_http_server, mock_webbrowser, mock_get):
        """Test discovery failure with fallback to direct endpoints."""
        # Mock keypair generation
        mock_private_key = Mock()
        mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
        mock_generate_keypair.return_value = (mock_private_key, mock_public_jwk)
        
        # Mock failed discovery
        mock_get.side_effect = requests.RequestException("Discovery failed")
        
        # Mock HTTP server with timeout (no auth code received)
        mock_server_instance = Mock()
        mock_server_instance.auth_code = None
        mock_server_instance.auth_state = None
        mock_server_instance.auth_error = None
        mock_server_instance.timeout = 1
        mock_http_server.return_value = mock_server_instance
        
        # Mock time to trigger timeout quickly
        with patch('time.time', side_effect=[0, 10, 20]):
            with self.assertRaises(PKCEFlowError) as context:
                run_pkce_flow(self.issuer_url, self.client_id, timeout=5)
            
            # Should timeout since no auth code received
            self.assertIn("Authorization timed out", str(context.exception))
            
            # Verify webbrowser.open was called (fallback endpoints work)
            mock_webbrowser.assert_called_once()

    @patch('openadp.auth.pkce_flow.requests.get')
    @patch('openadp.auth.pkce_flow.webbrowser.open')
    @patch('openadp.auth.pkce_flow.HTTPServer')
    @patch('openadp.auth.pkce_flow.generate_keypair')
    def test_successful_pkce_flow_with_discovery(self, mock_generate_keypair, mock_http_server, mock_webbrowser, mock_get):
        """Test successful PKCE flow with discovery."""
        # Mock keypair generation
        mock_private_key = Mock()
        mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
        mock_generate_keypair.return_value = (mock_private_key, mock_public_jwk)
        
        # Mock discovery
        mock_discovery_response = Mock()
        mock_discovery_response.json.return_value = self.discovery_doc
        mock_discovery_response.raise_for_status.return_value = None
        mock_get.return_value = mock_discovery_response
        
        # Mock HTTP server
        mock_server_instance = Mock()
        mock_server_instance.auth_code = 'test-auth-code'
        mock_server_instance.auth_state = 'test-state'
        mock_server_instance.auth_error = None
        mock_server_instance.timeout = 1
        mock_http_server.return_value = mock_server_instance
        
        # Mock token request
        with patch('openadp.auth.pkce_flow.requests.post') as mock_post:
            mock_token_response = Mock()
            mock_token_response.json.return_value = self.token_response
            mock_token_response.raise_for_status.return_value = None
            mock_post.return_value = mock_token_response
            
            # Mock time to avoid infinite loop
            with patch('time.time', side_effect=[0, 1, 2]):
                result = run_pkce_flow(self.issuer_url, self.client_id, timeout=1)
                
                # Verify result
                self.assertEqual(result['access_token'], 'test-access-token')
                self.assertEqual(result['private_key'], mock_private_key)

    @patch('openadp.auth.pkce_flow.requests.get')
    @patch('openadp.auth.pkce_flow.webbrowser.open')
    @patch('openadp.auth.pkce_flow.HTTPServer')
    @patch('openadp.auth.pkce_flow.generate_keypair')
    def test_pkce_flow_with_fallback_endpoints(self, mock_generate_keypair, mock_http_server, mock_webbrowser, mock_get):
        """Test PKCE flow with fallback endpoint construction."""
        # Mock keypair generation
        mock_private_key = Mock()
        mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
        mock_generate_keypair.return_value = (mock_private_key, mock_public_jwk)
        
        # Mock failed discovery
        mock_get.side_effect = requests.RequestException("Discovery failed")
        
        # Mock HTTP server
        mock_server_instance = Mock()
        mock_server_instance.auth_code = 'test-auth-code'
        mock_server_instance.auth_state = 'test-state'
        mock_server_instance.auth_error = None
        mock_server_instance.timeout = 1
        mock_http_server.return_value = mock_server_instance
        
        # Mock token request
        with patch('openadp.auth.pkce_flow.requests.post') as mock_post:
            mock_token_response = Mock()
            mock_token_response.json.return_value = self.token_response
            mock_token_response.raise_for_status.return_value = None
            mock_post.return_value = mock_token_response
            
            # Mock time to avoid infinite loop
            with patch('time.time', side_effect=[0, 1, 2]):
                result = run_pkce_flow(self.issuer_url, self.client_id, timeout=1)
                
                # Verify result
                self.assertEqual(result['access_token'], 'test-access-token')

    @patch('openadp.auth.pkce_flow.requests.get')
    @patch('openadp.auth.pkce_flow.webbrowser.open')
    @patch('openadp.auth.pkce_flow.HTTPServer')
    @patch('openadp.auth.pkce_flow.generate_keypair')
    def test_pkce_flow_auth_error(self, mock_generate_keypair, mock_http_server, mock_webbrowser, mock_get):
        """Test PKCE flow with authorization error."""
        # Mock keypair generation
        mock_private_key = Mock()
        mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
        mock_generate_keypair.return_value = (mock_private_key, mock_public_jwk)
        
        # Mock discovery
        mock_discovery_response = Mock()
        mock_discovery_response.json.return_value = self.discovery_doc
        mock_discovery_response.raise_for_status.return_value = None
        mock_get.return_value = mock_discovery_response
        
        # Mock HTTP server with error
        mock_server_instance = Mock()
        mock_server_instance.auth_code = None
        mock_server_instance.auth_state = None
        mock_server_instance.auth_error = 'access_denied'
        mock_server_instance.timeout = 1
        mock_http_server.return_value = mock_server_instance
        
        # Mock time to avoid infinite loop
        with patch('time.time', side_effect=[0, 1, 2]):
            with self.assertRaises(PKCEFlowError) as context:
                run_pkce_flow(self.issuer_url, self.client_id, timeout=1)
            
            self.assertIn("Authorization failed: access_denied", str(context.exception))

    @patch('openadp.auth.pkce_flow.requests.get')
    @patch('openadp.auth.pkce_flow.webbrowser.open')
    @patch('openadp.auth.pkce_flow.HTTPServer')
    @patch('openadp.auth.pkce_flow.generate_keypair')
    def test_pkce_flow_timeout(self, mock_generate_keypair, mock_http_server, mock_webbrowser, mock_get):
        """Test PKCE flow timeout."""
        # Mock keypair generation
        mock_private_key = Mock()
        mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
        mock_generate_keypair.return_value = (mock_private_key, mock_public_jwk)
        
        # Mock discovery
        mock_discovery_response = Mock()
        mock_discovery_response.json.return_value = self.discovery_doc
        mock_discovery_response.raise_for_status.return_value = None
        mock_get.return_value = mock_discovery_response
        
        # Mock HTTP server with no response
        mock_server_instance = Mock()
        mock_server_instance.auth_code = None
        mock_server_instance.auth_state = None
        mock_server_instance.auth_error = None
        mock_server_instance.timeout = 1
        mock_http_server.return_value = mock_server_instance
        
        # Mock time to trigger timeout
        with patch('time.time', side_effect=[0, 10, 20]):
            with self.assertRaises(PKCEFlowError) as context:
                run_pkce_flow(self.issuer_url, self.client_id, timeout=5)
            
            self.assertIn("Authorization timed out", str(context.exception))

    def test_with_existing_private_key(self):
        """Test PKCE flow with existing private key."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        
        with patch('openadp.auth.pkce_flow.requests.get') as mock_get, \
             patch('openadp.auth.pkce_flow.private_key_to_jwk') as mock_private_key_to_jwk, \
             patch('openadp.auth.pkce_flow.webbrowser.open'), \
             patch('openadp.auth.pkce_flow.HTTPServer') as mock_http_server:
            
            # Mock private_key_to_jwk
            mock_public_jwk = {'kty': 'EC', 'crv': 'P-256'}
            mock_private_key_to_jwk.return_value = mock_public_jwk
            
            # Mock discovery
            mock_discovery_response = Mock()
            mock_discovery_response.json.return_value = self.discovery_doc
            mock_discovery_response.raise_for_status.return_value = None
            mock_get.return_value = mock_discovery_response
            
            # Mock HTTP server
            mock_server_instance = Mock()
            mock_server_instance.auth_code = 'test-auth-code'
            mock_server_instance.auth_state = 'test-state'
            mock_server_instance.auth_error = None
            mock_server_instance.timeout = 1
            mock_http_server.return_value = mock_server_instance
            
            # Mock token request
            with patch('openadp.auth.pkce_flow.requests.post') as mock_post:
                mock_token_response = Mock()
                mock_token_response.json.return_value = self.token_response
                mock_token_response.raise_for_status.return_value = None
                mock_post.return_value = mock_token_response
                
                # Mock time to avoid infinite loop
                with patch('time.time', side_effect=[0, 1, 2]):
                    result = run_pkce_flow(self.issuer_url, self.client_id, private_key=private_key, timeout=1)
                    
                    # Verify the same private key is returned
                    self.assertEqual(result['private_key'], private_key)
                    
                    # Verify private_key_to_jwk was called
                    mock_private_key_to_jwk.assert_called_once_with(private_key)


class TestPKCERefresh(unittest.TestCase):
    """Test PKCE refresh token functionality."""
    
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
            'token_type': 'DPoP',
            'expires_in': 3600
        }

    @patch('openadp.auth.pkce_flow.requests.get')
    @patch('openadp.auth.pkce_flow.requests.post')
    def test_successful_refresh_pkce(self, mock_post, mock_get):
        """Test successful PKCE token refresh."""
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
        result = refresh_access_token_pkce(self.issuer_url, self.client_id, self.refresh_token, self.private_key)
        
        # Verify result
        self.assertEqual(result['access_token'], 'new-access-token')
        self.assertEqual(result['refresh_token'], 'new-refresh-token')

    @patch('openadp.auth.pkce_flow.requests.get')
    def test_refresh_discovery_failure_pkce(self, mock_get):
        """Test PKCE refresh with discovery failure."""
        mock_get.side_effect = requests.RequestException("Discovery failed")
        
        with self.assertRaises(PKCEFlowError) as context:
            refresh_access_token_pkce(self.issuer_url, self.client_id, self.refresh_token, self.private_key)
        
        self.assertIn("Failed to discover OAuth endpoints", str(context.exception))


if __name__ == '__main__':
    unittest.main(verbosity=2)
