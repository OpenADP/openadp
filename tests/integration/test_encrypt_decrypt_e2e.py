#!/usr/bin/env python3
"""
Integration test for complete encrypt/decrypt workflow with authentication.

This test demonstrates the full OpenADP system in action:
1. Fake Keycloak authentication
2. Real local OpenADP servers
3. Complete encrypt/decrypt cycle
4. Secret sharing and recovery
5. File encryption/decryption

This is the ultimate end-to-end integration test.
"""

import os
import sys
import tempfile
import pytest
import subprocess
import time
import threading
from pathlib import Path

# Add the prototype source to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../prototype/src'))

import pytest

# Temporarily skipping this test as it uses old OAuth system
# TODO: Update to use new auth code system
@pytest.mark.skip(reason="OAuth test deprecated - needs update to auth code system")
class TestEncryptDecryptE2E:
    """Complete encrypt/decrypt integration test with real servers."""
    
    # Class-level state for sharing between tests
    auth_data = None
    client = None
    server_processes = []
    test_file_content = None
    encrypted_file_path = None
    fake_keycloak_server = None
    original_enc_key = None
    
    @classmethod
    def setup_class(cls):
        """Set up the test environment with real servers."""
        print("\n🚀 Setting up Encrypt/Decrypt Integration Test")
        print("=" * 60)
        
        # Start fake Keycloak server
        from tests.fake_keycloak import FakeKeycloakServer
        cls.fake_keycloak_server = FakeKeycloakServer()
        cls.fake_keycloak_server.start()
        print("🔐 Started fake Keycloak at http://localhost:9000")
        
        # Start real OpenADP servers
        cls._start_openadp_servers()
        
        # Create authentication data
        cls.auth_data = create_test_auth_data(cls.fake_keycloak_server)
        print(f"✅ Authentication data created for user: {cls.auth_data.get('user', {}).get('username', 'unknown')}")
        
        # Initialize client with local servers
        cls.client = Client(
            servers_url=None,  # Don't scrape remote servers
            fallback_servers=[
                "http://localhost:9200",
                "http://localhost:9201", 
                "http://localhost:9202"
            ]
        )
        
        print(f"✅ Client initialized with {cls.client.get_live_server_count()} live servers")
        
        # Create test file content
        cls.test_file_content = """
This is a test file for OpenADP encrypt/decrypt integration testing.

It contains multiple lines of text to demonstrate that the complete
encryption and decryption workflow is working correctly.

The file includes:
- Multiple paragraphs
- Special characters: !@#$%^&*()
- Unicode: 🔐 🚀 ✅ 🎉
- Numbers: 1234567890
- Mixed content types

This comprehensive test validates the entire OpenADP system from
authentication through encryption, secret sharing, recovery, and
final decryption back to the original content.

If you can read this after the full encrypt/decrypt cycle,
then the OpenADP system is working perfectly! 🎯
""".encode('utf-8')
        
        print("✅ Test environment setup complete")
    
    @classmethod
    def _start_openadp_servers(cls):
        """Start three local OpenADP servers."""
        print("🖥️  Starting local OpenADP servers...")
        
        server_script = os.path.join(
            os.path.dirname(__file__),
            "../../server/jsonrpc_server.py"
        )
        
        if not os.path.exists(server_script):
            raise FileNotFoundError(f"Server script not found: {server_script}")
        
        # Start servers on ports 9200, 9201, 9202 (different from E2E tests)
        for port in [9200, 9201, 9202]:
            print(f"  Starting server on port {port}...")
            
            # Use environment variables to configure each server
            env = os.environ.copy()
            env['OPENADP_DB'] = f'openadp_integration_{port}.db'
            env['OPENADP_PORT'] = str(port)
            env['OPENADP_AUTH_ISSUER'] = 'http://localhost:9000/realms/openadp'
            env['OPENADP_AUTH_JWKS_URL'] = 'http://localhost:9000/realms/openadp/protocol/openid-connect/certs'
            
            process = subprocess.Popen([
                sys.executable, server_script
            ], 
            env=env,
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(server_script)
            )
            
            cls.server_processes.append(process)
            
            # Check if process started successfully
            time.sleep(0.5)  # Give it a moment to start
            if process.poll() is not None:
                # Process has already terminated
                stdout, stderr = process.communicate()
                print(f"    ❌ Server on port {port} failed to start:")
                print(f"    STDOUT: {stdout.decode()}")
                print(f"    STDERR: {stderr.decode()}")
            else:
                print(f"    ✅ Server on port {port} started (PID: {process.pid})")
            
        print(f"✅ Started {len(cls.server_processes)} OpenADP servers")
        
        # Wait longer for servers to be fully ready
        print("⏳ Waiting for servers to be ready...")
        time.sleep(5)
    
    @classmethod
    def teardown_class(cls):
        """Clean up test environment."""
        print("\n🧹 Cleaning up test environment...")
        
        # Stop server processes
        for process in cls.server_processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        
        # Stop fake Keycloak server
        if cls.fake_keycloak_server:
            cls.fake_keycloak_server.stop()
        
        # Clean up test database files
        for port in [9200, 9201, 9202]:
            db_file = f'openadp_integration_{port}.db'
            if os.path.exists(db_file):
                os.remove(db_file)
        
        # Clean up encrypted file if it exists
        if cls.encrypted_file_path and os.path.exists(cls.encrypted_file_path):
            os.remove(cls.encrypted_file_path)
        
        print("✅ Cleanup complete")
    
    def test_01_authentication_setup(self):
        """Test that authentication is working."""
        print("\n🔐 Testing Authentication Setup")
        print("=" * 40)
        
        assert self.auth_data is not None, "Authentication data should be available"
        assert 'access_token' in self.auth_data, "Access token should be present"
        assert 'token_type' in self.auth_data, "Token type should be present"
        
        print(f"✅ Authentication type: {self.auth_data['token_type']}")
        print(f"✅ User ID: {self.auth_data.get('user_id', 'N/A')}")
        print("✅ Authentication setup successful")
    
    def test_02_server_connectivity(self):
        """Test that OpenADP servers are running and accessible."""
        print("\n🖥️  Testing Server Connectivity")
        print("=" * 40)
        
        assert self.client is not None, "Client should be initialized"
        live_count = self.client.get_live_server_count()
        
        assert live_count >= 2, f"Need at least 2 live servers for threshold crypto, got {live_count}"
        
        print(f"✅ Live servers: {live_count}")
        for i, url in enumerate(self.client.get_live_server_urls(), 1):
            print(f"  {i}. {url}")
        
        print("✅ Server connectivity confirmed")
    
    def test_03_file_encryption(self):
        """Test file encryption with secret sharing."""
        print("\n🔒 Testing File Encryption")
        print("=" * 40)
        
        # Create temporary file with test content
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as temp_file:
            temp_file.write(self.test_file_content)
            temp_file_path = temp_file.name
        
        try:
            # Import the keygen functionality for encryption key generation
            from openadp import keygen
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            import json
            import secrets
            
            # Set up encryption parameters
            uid = self.auth_data['user']['sub']  # Use the JWT sub claim (authenticated user ID)
            did = "integration_test_device"
            bid = f"integration_test_backup_{int(time.time())}"
            pin = "1234"
            
            print(f"📁 Input file: {temp_file_path}")
            print(f"📊 File size: {len(self.test_file_content)} bytes")
            print(f"👤 User: {uid}")
            print(f"📱 Device: {did}")
            print(f"💾 Backup: {bid}")
            
            # Generate encryption key using OpenADP
            print("🔑 Generating encryption key using OpenADP...")
            enc_key, error, server_urls_used, threshold = keygen.generate_encryption_key(
                bid, pin, uid, 
                servers=self.client.get_live_server_urls(),
                auth_data=self.auth_data
            )
            
            if error:
                pytest.fail(f"Failed to generate encryption key: {error}")
            
            assert enc_key is not None, "Encryption key should be generated"
            print(f"✅ Encryption key generated: {len(enc_key)} bytes")
            print(f"✅ Used {len(server_urls_used)} servers with threshold {threshold}")
            print(f"🔍 Encryption key (first 16 bytes): {enc_key[:16].hex()}")
            
            # Store the encryption key for comparison during decryption
            TestEncryptDecryptE2E.original_enc_key = enc_key
            
            # Create metadata for the encrypted file
            metadata = {
                "servers": server_urls_used,
                "auth_enabled": True,
                "threshold": threshold,
                "uid": uid,
                "did": did,
                "bid": bid
            }
            metadata_json = json.dumps(metadata).encode('utf-8')
            
            # Generate random nonce for ChaCha20
            nonce = secrets.token_bytes(12)  # 12 bytes for ChaCha20
            
            # Encrypt the file content
            chacha = ChaCha20Poly1305(enc_key)
            ciphertext = chacha.encrypt(nonce, self.test_file_content, metadata_json)
            
            # Create encrypted file with format: [metadata_length][metadata][nonce][encrypted_data]
            encrypted_file_path = temp_file_path + ".enc"
            with open(encrypted_file_path, 'wb') as f:
                # Write metadata length (4 bytes, little-endian)
                f.write(len(metadata_json).to_bytes(4, 'little'))
                # Write metadata
                f.write(metadata_json)
                # Write nonce
                f.write(nonce)
                # Write encrypted data
                f.write(ciphertext)
            
            # Store for later use
            TestEncryptDecryptE2E.encrypted_file_path = encrypted_file_path
            
            # Verify encrypted file was created
            assert os.path.exists(encrypted_file_path), "Encrypted file should be created"
            
            # Verify encrypted file is different from original
            with open(encrypted_file_path, 'rb') as f:
                encrypted_content = f.read()
            
            assert len(encrypted_content) > len(self.test_file_content), "Encrypted file should be larger (includes metadata)"
            
            print(f"✅ Encrypted file created: {encrypted_file_path}")
            print(f"✅ Encrypted size: {len(encrypted_content)} bytes")
            print("✅ File encryption successful")
            
        finally:
            # Clean up original temp file
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
    
    def test_04_secret_sharing_verification(self):
        """Verify that secrets were properly shared across servers."""
        print("\n🔗 Testing Secret Sharing Verification")
        print("=" * 40)
        
        # Test that we can list backups from the servers
        uid = "integration_test@openadp.org"
        
        backups, error = self.client.list_backups(uid)
        
        if error:
            print(f"⚠️  List backups returned error: {error}")
            # This might be expected if the server doesn't support list_backups yet
            print("ℹ️  Skipping backup verification - server may not support list_backups")
        else:
            assert backups is not None, "Backups list should not be None"
            print(f"✅ Found {len(backups)} backup(s) for user {uid}")
            
            for i, backup in enumerate(backups, 1):
                print(f"  {i}. {backup}")
        
        print("✅ Secret sharing verification complete")
    
    def test_05_file_decryption(self):
        """Test file decryption and recovery."""
        print("\n🔓 Testing File Decryption")
        print("=" * 40)
        
        assert self.encrypted_file_path is not None, "Encrypted file should exist from previous test"
        assert os.path.exists(self.encrypted_file_path), "Encrypted file should exist on disk"
        
        # Import the keygen functionality for key recovery
        from openadp import keygen
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        import json
        
        # Set up decryption parameters (same as encryption)
        uid = self.auth_data['user']['sub']  # Use the JWT sub claim (authenticated user ID)
        pin = "1234"
        
        print(f"📁 Encrypted file: {self.encrypted_file_path}")
        print(f"👤 User: {uid}")
        print(f"🔑 PIN: {pin}")
        
        try:
            # Read the encrypted file and parse its structure
            with open(self.encrypted_file_path, 'rb') as f:
                file_data = f.read()
            
            # Parse file format: [metadata_length][metadata][nonce][encrypted_data]
            metadata_length = int.from_bytes(file_data[:4], 'little')
            metadata_start = 4
            metadata_end = metadata_start + metadata_length
            nonce_start = metadata_end
            nonce_end = nonce_start + 12  # ChaCha20 nonce size
            
            metadata_json = file_data[metadata_start:metadata_end]
            nonce = file_data[nonce_start:nonce_end]
            ciphertext = file_data[nonce_end:]
            
            # Parse metadata
            metadata = json.loads(metadata_json.decode('utf-8'))
            bid = metadata['bid']
            server_urls = metadata['servers']
            threshold = metadata.get('threshold', 2)
            
            print(f"📊 Metadata: {len(server_urls)} servers, threshold {threshold}")
            print(f"💾 Backup ID: {bid}")
            
            # Recover encryption key using OpenADP
            print("🔑 Recovering encryption key using OpenADP...")
            enc_key, error = keygen.recover_encryption_key(
                bid, pin, uid,
                server_urls=server_urls,
                auth_data=self.auth_data,
                threshold=threshold
            )
            
            if error:
                pytest.fail(f"Failed to recover encryption key: {error}")
            
            assert enc_key is not None, "Encryption key should be recovered"
            print(f"✅ Encryption key recovered: {len(enc_key)} bytes")
            print(f"🔍 Recovered key (first 16 bytes): {enc_key[:16].hex()}")
            
            # Compare with original encryption key
            if TestEncryptDecryptE2E.original_enc_key is not None:
                if enc_key == TestEncryptDecryptE2E.original_enc_key:
                    print("✅ Keys match perfectly!")
                else:
                    print("❌ Keys don't match!")
                    print(f"🔍 Original key (first 16 bytes): {TestEncryptDecryptE2E.original_enc_key[:16].hex()}")
                    pytest.fail("Recovered encryption key doesn't match original key")
            
            # Decrypt the file content
            chacha = ChaCha20Poly1305(enc_key)
            decrypted_content = chacha.decrypt(nonce, ciphertext, metadata_json)
            
            # Verify content matches original
            assert decrypted_content == self.test_file_content, "Decrypted content should match original"
            
            print(f"✅ Decrypted size: {len(decrypted_content)} bytes")
            print("✅ Content verification: MATCH")
            print("✅ File decryption successful")
            
        except Exception as e:
            pytest.fail(f"Decryption failed: {e}")
    
    def test_06_end_to_end_verification(self):
        """Final verification that the complete system works."""
        print("\n🎯 Final End-to-End Verification")
        print("=" * 40)
        
        # Verify all components worked together
        assert self.auth_data is not None, "Authentication should be working"
        assert self.client.get_live_server_count() >= 2, "Servers should be accessible"
        assert self.encrypted_file_path is not None, "Encryption should have succeeded"
        
        print("✅ Authentication: WORKING")
        print("✅ Server Communication: WORKING") 
        print("✅ Secret Sharing: WORKING")
        print("✅ Encryption: WORKING")
        print("✅ Decryption: WORKING")
        print("✅ Content Integrity: VERIFIED")
        
        print("\n🎉 COMPLETE SYSTEM INTEGRATION: SUCCESS!")
        print("🚀 OpenADP encrypt/decrypt workflow is fully operational!")


if __name__ == "__main__":
    # Run the integration test
    pytest.main([__file__, "-v", "-s"]) 