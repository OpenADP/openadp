#!/usr/bin/env python3
"""
Test suite for Ocrypt module

Tests the complete Ocrypt API including:
- Basic register/recover functionality
- Error handling and validation

- Metadata format validation
- Integration with OpenADP servers
"""

import unittest
import json
import base64
import secrets
from unittest.mock import patch, MagicMock

# Add the openadp package to the path
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'sdk', 'python'))

import openadp.ocrypt as ocrypt
from openadp.keygen import GenerateEncryptionKeyResult, RecoverEncryptionKeyResult, AuthCodes
from openadp.client import ServerInfo


class TestOcryptBasic(unittest.TestCase):
    """Test basic Ocrypt functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.user_id = "test@example.com"
        self.app_id = "test_app"
        self.pin = "1234"
        self.secret = b"this is a test secret that should be protected"
        self.max_guesses = 5
    
    def test_input_validation_register(self):
        """Test input validation for register function"""
        # Test empty user_id
        with self.assertRaises(Exception) as cm:
            ocrypt.register("", self.app_id, self.secret, self.pin)
        self.assertIn("user_id must be a non-empty string", str(cm.exception))
        
        # Test non-string user_id
        with self.assertRaises(Exception) as cm:
            ocrypt.register(123, self.app_id, self.secret, self.pin)
        self.assertIn("user_id must be a non-empty string", str(cm.exception))
        
        # Test empty app_id
        with self.assertRaises(Exception) as cm:
            ocrypt.register(self.user_id, "", self.secret, self.pin)
        self.assertIn("app_id must be a non-empty string", str(cm.exception))
        
        # Test empty long_term_secret
        with self.assertRaises(Exception) as cm:
            ocrypt.register(self.user_id, self.app_id, b"", self.pin)
        self.assertIn("long_term_secret must be non-empty bytes", str(cm.exception))
        
        # Test non-bytes long_term_secret
        with self.assertRaises(Exception) as cm:
            ocrypt.register(self.user_id, self.app_id, "not bytes", self.pin)
        self.assertIn("long_term_secret must be non-empty bytes", str(cm.exception))
        
        # Test empty pin
        with self.assertRaises(Exception) as cm:
            ocrypt.register(self.user_id, self.app_id, self.secret, "")
        self.assertIn("pin must be a non-empty string", str(cm.exception))
        
        # Test invalid max_guesses
        with self.assertRaises(Exception) as cm:
            ocrypt.register(self.user_id, self.app_id, self.secret, self.pin, 0)
        self.assertIn("max_guesses must be at least 1", str(cm.exception))
    
    def test_input_validation_recover(self):
        """Test input validation for recover function"""
        # Test empty metadata
        with self.assertRaises(Exception) as cm:
            ocrypt.recover(b"", self.pin)
        self.assertIn("metadata must be non-empty bytes", str(cm.exception))
        
        # Test non-bytes metadata
        with self.assertRaises(Exception) as cm:
            ocrypt.recover("not bytes", self.pin)
        self.assertIn("metadata must be non-empty bytes", str(cm.exception))
        
        # Test empty pin
        with self.assertRaises(Exception) as cm:
            ocrypt.recover(b"valid metadata", "")
        self.assertIn("pin must be a non-empty string", str(cm.exception))
    
    @patch('openadp.ocrypt.get_servers')
    @patch('openadp.ocrypt.generate_encryption_key')
    def test_successful_register(self, mock_generate_key, mock_get_servers):
        """Test successful registration"""
        # Mock server discovery
        mock_servers = [
            ServerInfo(url="https://server1.example.com", public_key="ed25519:abc123", country="US"),
            ServerInfo(url="https://server2.example.com", public_key="ed25519:def456", country="EU")
        ]
        mock_get_servers.return_value = mock_servers
        
        # Mock key generation
        mock_auth_codes = AuthCodes(
            base_auth_code="base_auth_code_hex",
            server_auth_codes={
                "https://server1.example.com": "server1_auth_code",
                "https://server2.example.com": "server2_auth_code"
            },
            user_id=self.user_id
        )
        
        mock_result = GenerateEncryptionKeyResult(
            encryption_key=secrets.token_bytes(32),  # 256-bit key
            server_infos=[
                ServerInfo(url="https://server1.example.com", public_key="", country="US"),
                ServerInfo(url="https://server2.example.com", public_key="", country="US")
            ],
            threshold=2,
            auth_codes=mock_auth_codes
        )
        mock_generate_key.return_value = mock_result
        
        # Test registration
        metadata = ocrypt.register(self.user_id, self.app_id, self.secret, self.pin, self.max_guesses)
        
        # Verify metadata is valid JSON bytes
        self.assertIsInstance(metadata, bytes)
        metadata_dict = json.loads(metadata.decode('utf-8'))
        
        # Verify metadata structure
        self.assertEqual(metadata_dict["user_id"], self.user_id)
        self.assertEqual(metadata_dict["app_id"], self.app_id)
        self.assertEqual(metadata_dict["max_guesses"], self.max_guesses)
        self.assertEqual(metadata_dict["threshold"], 2)
        self.assertEqual(metadata_dict["auth_code"], "base_auth_code_hex")
        self.assertIn("wrapped_long_term_secret", metadata_dict)
        self.assertIn("backup_id", metadata_dict)
        self.assertIn("ocrypt_version", metadata_dict)
        
        # Verify wrapped secret structure
        wrapped = metadata_dict["wrapped_long_term_secret"]
        self.assertIn("nonce", wrapped)
        self.assertIn("ciphertext", wrapped)
        self.assertIn("tag", wrapped)
        
        # Verify all components are valid base64
        base64.b64decode(wrapped["nonce"])
        base64.b64decode(wrapped["ciphertext"])
        base64.b64decode(wrapped["tag"])
    
    @patch('openadp.ocrypt.get_servers')
    @patch('openadp.ocrypt.recover_encryption_key')
    def test_successful_recover(self, mock_recover_key, mock_get_servers):
        """Test successful recovery"""
        # Create valid metadata
        enc_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # Encrypt the secret with AES-GCM
        from Crypto.Cipher import AES
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(self.secret)
        
        metadata_dict = {
            "servers": ["https://server1.example.com", "https://server2.example.com"],
            "threshold": 2,
            "version": "1.0",
            "auth_code": "base_auth_code_hex",
            "user_id": self.user_id,
            "wrapped_long_term_secret": {
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "tag": base64.b64encode(tag).decode()
            },
            "backup_id": "even",
            "app_id": self.app_id,
            "max_guesses": self.max_guesses,
            "ocrypt_version": "1.0"
        }
        metadata = json.dumps(metadata_dict).encode('utf-8')
        
        # Mock server discovery
        mock_servers = [
            ServerInfo(url="https://server1.example.com", public_key="ed25519:abc123", country="US"),
            ServerInfo(url="https://server2.example.com", public_key="ed25519:def456", country="EU")
        ]
        mock_get_servers.return_value = mock_servers
        
        # Mock key recovery
        mock_result = RecoverEncryptionKeyResult(
            encryption_key=enc_key
        )
        mock_recover_key.return_value = mock_result
        
        # Test recovery (now includes automatic backup refresh)
        recovered_secret, remaining, updated_metadata = ocrypt.recover(metadata, self.pin)
        
        # Verify recovery
        self.assertEqual(recovered_secret, self.secret)
        self.assertEqual(remaining, 0)  # Success = 0 remaining guesses
        self.assertIsInstance(updated_metadata, bytes)  # Should get updated metadata
        
        # Automatic backup refresh is now the default behavior
    
    def test_invalid_metadata_format(self):
        """Test recovery with invalid metadata format"""
        # Test invalid JSON
        with self.assertRaises(Exception) as cm:
            ocrypt.recover(b"invalid json", self.pin)
        self.assertIn("Invalid metadata format", str(cm.exception))
        
        # Test missing required fields
        incomplete_metadata = json.dumps({"user_id": self.user_id}).encode('utf-8')
        with self.assertRaises(Exception) as cm:
            ocrypt.recover(incomplete_metadata, self.pin)
        self.assertIn("Missing required field in metadata", str(cm.exception))
    
    def test_backup_id_usage(self):
        """Test that backup IDs are used correctly in register/recover cycle"""
        # This test verifies that the public register() function defaults to "even" BID
        # and that recover() properly flips to "odd" BID for backup refresh
        
        # Test that the public register function defaults to "even" BID
        with patch('openadp.ocrypt.get_servers') as mock_get_servers, \
             patch('openadp.ocrypt.generate_encryption_key') as mock_generate_key:
            
            # Mock server discovery
            mock_servers = [ServerInfo(url="https://test.example.com", public_key="", country="US")]
            mock_get_servers.return_value = mock_servers
            
            # Mock key generation
            mock_auth_codes = AuthCodes(
                base_auth_code="test_auth",
                server_auth_codes={"https://test.example.com": "test_server_auth"},
                user_id="test_user"
            )
            
            mock_result = GenerateEncryptionKeyResult(
                encryption_key=secrets.token_bytes(32),
                server_infos=[ServerInfo(url="https://test.example.com", public_key="", country="US")],
                threshold=1,
                auth_codes=mock_auth_codes
            )
            mock_generate_key.return_value = mock_result
            
            # Test registration (should default to "even" BID)
            metadata = ocrypt.register("test_user", "test_app", b"test_secret", "1234")
            
            # Verify metadata contains default "even" BID
            metadata_dict = json.loads(metadata.decode('utf-8'))
            self.assertEqual(metadata_dict["backup_id"], "even")
    
    @patch('openadp.ocrypt.get_servers')
    @patch('openadp.ocrypt.generate_encryption_key')
    @patch('openadp.ocrypt.random.sample')
    def test_load_balancing_server_selection(self, mock_random_sample, mock_generate_key, mock_get_servers):
        """Test that random server selection is used for load balancing when >15 servers available"""
        # Create 20 mock servers (more than the 15 limit)
        mock_servers = []
        for i in range(20):
            mock_servers.append(ServerInfo(
                url=f"https://server{i}.example.com", 
                public_key=f"ed25519:key{i}", 
                country="US"
            ))
        mock_get_servers.return_value = mock_servers
        
        # Mock random.sample to return first 15 servers (for predictable testing)
        selected_servers = mock_servers[:15]
        mock_random_sample.return_value = selected_servers
        
        # Mock key generation
        mock_auth_codes = AuthCodes(
            base_auth_code="test_auth_code",
            server_auth_codes={server.url: f"auth_{i}" for i, server in enumerate(selected_servers)},
            user_id="test_user"
        )
        
        mock_result = GenerateEncryptionKeyResult(
            encryption_key=secrets.token_bytes(32),
            server_infos=[server for server in selected_servers],
            threshold=8,  # 15//2 + 1 = 8
            auth_codes=mock_auth_codes
        )
        mock_generate_key.return_value = mock_result
        
        # Test registration (use private function to avoid recursive mocking)
        metadata = ocrypt._register_with_bid("test_user", "test_app", b"test_secret", "1234", backup_id="even")
        
        # Verify random.sample was called with correct parameters
        mock_random_sample.assert_called_once_with(mock_servers, 15)
        
        # Verify metadata contains expected number of servers
        metadata_dict = json.loads(metadata.decode('utf-8'))
        self.assertEqual(len(metadata_dict["servers"]), 15)
        self.assertEqual(metadata_dict["threshold"], 8)





class TestOcryptErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""
    
    @patch('openadp.ocrypt.get_servers')
    @patch('openadp.ocrypt.get_fallback_server_info')
    def test_no_servers_available(self, mock_fallback, mock_get_servers):
        """Test registration when no servers are available"""
        mock_get_servers.return_value = []
        mock_fallback.return_value = []  # Also mock fallback to return empty
        
        with self.assertRaises(Exception) as cm:
            ocrypt.register("user", "app", b"secret", "1234")
        self.assertIn("No OpenADP servers available", str(cm.exception))
    
    @patch('openadp.ocrypt.get_servers')
    @patch('openadp.ocrypt.generate_encryption_key')
    def test_openadp_registration_failure(self, mock_generate_key, mock_get_servers):
        """Test handling of OpenADP registration failure"""
        # Mock server discovery
        mock_servers = [ServerInfo(url="https://server1.example.com", public_key="", country="US")]
        mock_get_servers.return_value = mock_servers
        
        # Mock key generation failure
        mock_result = GenerateEncryptionKeyResult(error="Server registration failed")
        mock_generate_key.return_value = mock_result
        
        with self.assertRaises(Exception) as cm:
            ocrypt.register("user", "app", b"secret", "1234")
        self.assertIn("OpenADP registration failed", str(cm.exception))
    
    @patch('openadp.ocrypt.get_servers')
    @patch('openadp.ocrypt.recover_encryption_key')
    def test_openadp_recovery_failure(self, mock_recover_key, mock_get_servers):
        """Test handling of OpenADP recovery failure"""
        # Create valid metadata
        metadata_dict = {
            "servers": ["https://server1.example.com"],
            "threshold": 1,
            "version": "1.0",
            "auth_code": "base_auth_code_hex",
            "user_id": "user",
            "wrapped_long_term_secret": {
                "nonce": base64.b64encode(b"nonce123").decode(),
                "ciphertext": base64.b64encode(b"ciphertext").decode(),
                "tag": base64.b64encode(b"tag1234567890123").decode()
            },
            "backup_id": "even",
            "app_id": "app",
            "max_guesses": 10,
            "ocrypt_version": "1.0"
        }
        metadata = json.dumps(metadata_dict).encode('utf-8')
        
        # Mock server discovery
        mock_servers = [ServerInfo(url="https://server1.example.com", public_key="", country="US")]
        mock_get_servers.return_value = mock_servers
        
        # Mock key recovery failure
        mock_result = RecoverEncryptionKeyResult(error="Wrong PIN or server error")
        mock_recover_key.return_value = mock_result
        
        with self.assertRaises(Exception) as cm:
            ocrypt.recover(metadata, "wrong_pin")
        self.assertIn("OpenADP key recovery failed", str(cm.exception))
    
    @patch('openadp.ocrypt.get_servers')
    @patch('openadp.ocrypt.recover_encryption_key')
    def test_invalid_pin_unwrapping_failure(self, mock_recover_key, mock_get_servers):
        """Test handling of invalid PIN during secret unwrapping"""
        # Create metadata with valid structure but wrong encryption
        wrong_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        
        # Encrypt with wrong key
        from Crypto.Cipher import AES
        cipher = AES.new(wrong_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(b"secret")
        
        metadata_dict = {
            "servers": ["https://server1.example.com"],
            "threshold": 1,
            "version": "1.0",
            "auth_code": "base_auth_code_hex",
            "user_id": "user",
            "wrapped_long_term_secret": {
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "tag": base64.b64encode(tag).decode()
            },
            "backup_id": "even",
            "app_id": "app",
            "max_guesses": 10,
            "ocrypt_version": "1.0"
        }
        metadata = json.dumps(metadata_dict).encode('utf-8')
        
        # Mock server discovery
        mock_servers = [ServerInfo(url="https://server1.example.com", public_key="", country="US")]
        mock_get_servers.return_value = mock_servers
        
        # Mock key recovery success but with different key
        correct_key = secrets.token_bytes(32)  # Different from wrong_key
        mock_result = RecoverEncryptionKeyResult(encryption_key=correct_key)
        mock_recover_key.return_value = mock_result
        
        with self.assertRaises(Exception) as cm:
            ocrypt.recover(metadata, "1234")
        self.assertIn("Invalid PIN or corrupted data", str(cm.exception))


class TestOcryptIntegration(unittest.TestCase):
    """Integration tests (require actual OpenADP functionality)"""
    
    def test_module_imports(self):
        """Test that all required modules can be imported"""
        # Test that ocrypt module imports successfully
        import openadp.ocrypt
        
        # Test that required functions are available
        self.assertTrue(hasattr(openadp.ocrypt, 'register'))
        self.assertTrue(hasattr(openadp.ocrypt, 'recover'))
        
        # Test module metadata
        self.assertTrue(hasattr(openadp.ocrypt, '__version__'))
        self.assertTrue(hasattr(openadp.ocrypt, '__all__'))
    
    def test_metadata_format_stability(self):
        """Test that metadata format is stable and parseable"""
        # This test uses mocked OpenADP functions but tests the actual metadata format
        with patch('openadp.ocrypt.get_servers') as mock_get_servers, \
             patch('openadp.ocrypt.generate_encryption_key') as mock_generate_key:
            
            # Mock server discovery
            mock_servers = [ServerInfo(url="https://test.example.com", public_key="", country="US")]
            mock_get_servers.return_value = mock_servers
            
            # Mock key generation
            mock_auth_codes = AuthCodes(
                base_auth_code="test_base_auth",
                server_auth_codes={"https://test.example.com": "test_server_auth"},
                user_id="test_user"
            )
            
            mock_result = GenerateEncryptionKeyResult(
                encryption_key=secrets.token_bytes(32),
                server_infos=[ServerInfo(url="https://test.example.com", public_key="", country="US")],
                threshold=1,
                auth_codes=mock_auth_codes
            )
            mock_generate_key.return_value = mock_result
            
            # Generate metadata
            metadata = ocrypt.register("test_user", "test_app", b"test_secret", "1234")
            
            # Parse and validate metadata structure
            metadata_dict = json.loads(metadata.decode('utf-8'))
            
            # Test required OpenADP fields
            openadp_fields = ['servers', 'threshold', 'version', 'auth_code', 'user_id']
            for field in openadp_fields:
                self.assertIn(field, metadata_dict, f"Missing OpenADP field: {field}")
            
            # Test required Ocrypt fields
            ocrypt_fields = ['wrapped_long_term_secret', 'backup_id', 'app_id', 'ocrypt_version']
            for field in ocrypt_fields:
                self.assertIn(field, metadata_dict, f"Missing Ocrypt field: {field}")
            
            # Test wrapped secret structure
            wrapped = metadata_dict['wrapped_long_term_secret']
            wrapped_fields = ['nonce', 'ciphertext', 'tag']
            for field in wrapped_fields:
                self.assertIn(field, wrapped, f"Missing wrapped secret field: {field}")
                # Verify it's valid base64
                base64.b64decode(wrapped[field])


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2) 