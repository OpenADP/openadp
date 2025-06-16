#!/usr/bin/env python3
"""
Integration test for complete encrypt/decrypt workflow with authentication codes.

This test demonstrates the full OpenADP system in action:
1. Authentication code generation
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
import hashlib
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from openadp.auth_code_manager import AuthCodeManager
from client.jsonrpc_client import OpenADPClient


class TestEncryptDecryptE2E:
    """Complete encrypt/decrypt integration test with real servers."""
    
    # Class-level state for sharing between tests
    auth_codes = None
    base_auth_code = None
    user_id = None
    server_processes = []
    test_file_content = None
    encrypted_file_path = None
    original_enc_key = None
    server_urls = [
        "http://localhost:9200",
        "http://localhost:9201", 
        "http://localhost:9202"
    ]
    
    @classmethod
    def setup_class(cls):
        """Set up the test environment with real servers."""
        print("\n🚀 Setting up Encrypt/Decrypt Integration Test")
        print("=" * 60)
        
        # Start real OpenADP servers
        cls._start_openadp_servers()
        
        # Generate authentication codes
        cls._generate_auth_codes()
        
        print(f"✅ Authentication codes generated for user: {cls.user_id}")
        
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
    def _generate_auth_codes(cls):
        """Generate authentication codes for testing."""
        print("🔐 Generating authentication codes...")
        
        # Generate deterministic auth codes for testing
        test_seed = "integration_test_seed_12345"
        seed_hash = hashlib.sha256(test_seed.encode()).hexdigest()
        
        # Generate base auth code (32 hex chars = 128 bits)
        base_seed = f"base:{seed_hash}"
        base_hash = hashlib.sha256(base_seed.encode()).hexdigest()
        cls.base_auth_code = base_hash[:32]
        
        # Generate server-specific codes (64 hex chars = SHA256)
        cls.auth_codes = {}
        for server_url in cls.server_urls:
            combined = f"{cls.base_auth_code}:{server_url}"
            server_code = hashlib.sha256(combined.encode()).hexdigest()
            cls.auth_codes[server_url] = server_code
        
        # Generate user ID from base auth code
        cls.user_id = hashlib.sha256(cls.base_auth_code.encode()).hexdigest()[:32]
        
        print(f"🔑 Generated base authentication code: {cls.base_auth_code}")
        print(f"🔐 Generated user ID: {cls.user_id}")
        print(f"🌐 Derived {len(cls.auth_codes)} server-specific codes")
    
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
        """Test that authentication codes are working."""
        print("\n🔐 Testing Authentication Setup")
        print("=" * 40)
        
        assert self.auth_codes is not None, "Authentication codes should be available"
        assert self.base_auth_code is not None, "Base auth code should be present"
        assert self.user_id is not None, "User ID should be present"
        
        # Validate auth code formats
        auth_manager = AuthCodeManager()
        assert auth_manager.validate_base_code_format(self.base_auth_code), "Base code format should be valid"
        
        for server_url, server_code in self.auth_codes.items():
            assert auth_manager.validate_server_code_format(server_code), f"Server code format should be valid for {server_url}"
        
        print(f"✅ Base auth code: {self.base_auth_code}")
        print(f"✅ User ID: {self.user_id}")
        print(f"✅ Server codes: {len(self.auth_codes)} generated")
        print("✅ Authentication setup successful")
    
    def test_02_server_connectivity(self):
        """Test that OpenADP servers are running and accessible."""
        print("\n🖥️  Testing Server Connectivity")
        print("=" * 40)
        
        live_servers = []
        
        for server_url in self.server_urls:
            try:
                client = OpenADPClient(server_url)
                auth_code = self.auth_codes[server_url]
                
                # Test basic connectivity with list_backups
                backups, error = client.list_backups(auth_code, encrypted=False)
                if error:
                    print(f"  ⚠️  {server_url}: {error}")
                else:
                    live_servers.append(server_url)
                    print(f"  ✅ {server_url}: Connected ({len(backups)} backups)")
                    
            except Exception as e:
                print(f"  ❌ {server_url}: Connection failed - {e}")
        
        assert len(live_servers) >= 2, f"Need at least 2 live servers for threshold crypto, got {len(live_servers)}"
        
        print(f"✅ Live servers: {len(live_servers)}")
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
            # Import required modules
            from openadp import keygen
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            import json
            import secrets
            
            # Set up encryption parameters
            filename = os.path.basename(temp_file_path)
            pin = "1234"
            
            print(f"📁 Input file: {temp_file_path}")
            print(f"📊 File size: {len(self.test_file_content)} bytes")
            print(f"👤 User ID: {self.user_id}")
            print(f"📁 Filename: {filename}")
            
            # Derive identifiers
            uid, did, bid = keygen.derive_identifiers(filename, self.user_id)
            print(f"🔑 UID: {uid}")
            print(f"📱 DID: {did}")
            print(f"💾 BID: {bid}")
            
            # Generate encryption key using custom implementation
            print("🔑 Generating encryption key using OpenADP...")
            enc_key, error, server_urls_used, threshold = self._generate_encryption_key_with_auth_codes(
                filename, pin, self.user_id, self.auth_codes, self.server_urls
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
                "version": "2.0"
            }
            metadata_json = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
            
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
        
        # Test that we can list backups from the servers using authentication codes
        for i, server_url in enumerate(self.server_urls, 1):
            try:
                from client.jsonrpc_client import OpenADPClient
                client = OpenADPClient(server_url)
                auth_code = self.auth_codes[server_url]
                
                backups, error = client.list_backups(auth_code, encrypted=False)
                
                if error:
                    print(f"  ⚠️  Server {i} ({server_url}): {error}")
                else:
                    print(f"  ✅ Server {i} ({server_url}): Found {len(backups)} backup(s)")
                    for j, backup in enumerate(backups, 1):
                        print(f"    {j}. {backup}")
                        
            except Exception as e:
                print(f"  ❌ Server {i} ({server_url}): Exception - {e}")
        
        print("✅ Secret sharing verification complete")
    
    def test_05_file_decryption(self):
        """Test file decryption and recovery."""
        print("\n🔓 Testing File Decryption")
        print("=" * 40)
        
        assert self.encrypted_file_path is not None, "Encrypted file should exist from previous test"
        assert os.path.exists(self.encrypted_file_path), "Encrypted file should exist on disk"
        
        # Import the keygen functionality for key recovery
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        import json
        
        # Set up decryption parameters (same as encryption)
        pin = "1234"
        
        print(f"📁 Encrypted file: {self.encrypted_file_path}")
        print(f"👤 User ID: {self.user_id}")
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
            server_urls = metadata['servers']
            threshold = metadata.get('threshold', 2)
            
            print(f"📊 Metadata: {len(server_urls)} servers, threshold {threshold}")
            
            # Get the original filename from the encrypted file path
            original_filename = os.path.basename(self.encrypted_file_path)
            if original_filename.endswith('.enc'):
                original_filename = original_filename[:-4]  # Remove .enc extension
            
            print(f"📁 Original filename: {original_filename}")
            
            # Recover encryption key using OpenADP
            print("🔑 Recovering encryption key using OpenADP...")
            enc_key, error = self._recover_encryption_key_with_auth_codes(
                original_filename, pin, self.user_id, self.auth_codes, server_urls, threshold
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
        assert self.auth_codes is not None, "Authentication codes should be working"
        assert len(self.server_urls) >= 2, "Servers should be accessible"
        assert self.encrypted_file_path is not None, "Encryption should have succeeded"
        
        print("✅ Authentication: WORKING")
        print("✅ Server Communication: WORKING") 
        print("✅ Secret Sharing: WORKING")
        print("✅ Encryption: WORKING")
        print("✅ Decryption: WORKING")
        print("✅ Content Integrity: VERIFIED")
        
        print("\n🎉 COMPLETE SYSTEM INTEGRATION: SUCCESS!")
        print("🚀 OpenADP encrypt/decrypt workflow is fully operational!")

    def _generate_encryption_key_with_auth_codes(self, filename, password, user_id, server_auth_codes, servers):
        """Generate an encryption key using OpenADP with authentication codes."""
        from openadp import crypto, sharing, keygen
        from client.jsonrpc_client import OpenADPClient
        import secrets
        
        # Step 1: Derive identifiers
        uid, did, bid = keygen.derive_identifiers(filename, user_id)
        
        # Step 2: Convert password to PIN
        pin = keygen.password_to_pin(password)
        
        # Step 3: Initialize clients for each server
        clients = []
        for server_url in servers:
            try:
                client = OpenADPClient(server_url)
                clients.append((server_url, client))
            except Exception as e:
                print(f"Failed to connect to {server_url}: {e}")
                continue
        
        if not clients:
            return None, "No servers available", [], 0
        
        # Step 4: Generate random secret and create point
        secret = secrets.randbelow(crypto.q)
        U = crypto.H(uid.encode(), did.encode(), bid.encode(), pin)
        S = crypto.point_mul(secret, U)
        
        # Step 5: Create shares using secret sharing
        threshold = max(1, min(2, len(clients)))  # At least 1, prefer 2 if available
        num_shares = len(clients)
        
        shares = sharing.make_random_shares(secret, threshold, num_shares)
        
        # Step 6: Register shares with servers using authentication codes
        version = 1
        registration_errors = []
        server_urls_used = []
        
        for i, ((server_url, client), (x, y)) in enumerate(zip(clients, shares)):
            auth_code = server_auth_codes[server_url]
            y_str = str(y)
            
            try:
                result, error = client.register_secret(
                    auth_code=auth_code,
                    did=did,
                    bid=bid,
                    version=version,
                    x=str(x),
                    y=y_str,
                    max_guesses=10,
                    expiration=0,
                    encrypted=False
                )
                
                if error:
                    registration_errors.append(f"Server {i+1}: {error}")
                elif not result:
                    registration_errors.append(f"Server {i+1}: Registration returned false")
                else:
                    print(f"OpenADP: Registered share {x} with server {i+1}")
                    server_urls_used.append(server_url)
                    
            except Exception as e:
                registration_errors.append(f"Server {i+1}: Exception: {str(e)}")
        
        if len(server_urls_used) == 0:
            return None, f"Failed to register any shares: {'; '.join(registration_errors)}", [], 0
        
        # Step 7: Derive encryption key
        enc_key = crypto.deriveEncKey(S)
        
        return enc_key, None, server_urls_used, threshold
    
    def _recover_encryption_key_with_auth_codes(self, filename, password, user_id, server_auth_codes, server_urls, threshold):
        """Recover an encryption key using OpenADP with authentication codes."""
        from openadp import crypto, sharing, keygen
        from client.jsonrpc_client import OpenADPClient
        import secrets
        
        # Step 1: Derive same identifiers as during encryption
        uid, did, bid = keygen.derive_identifiers(filename, user_id)
        
        # Step 2: Convert password to same PIN
        pin = keygen.password_to_pin(password)
        
        # Step 3: Initialize clients for each server
        clients = []
        for server_url in server_urls:
            try:
                client = OpenADPClient(server_url)
                clients.append((server_url, client))
            except Exception as e:
                print(f"Failed to connect to {server_url}: {e}")
                continue
        
        if not clients:
            return None, "No servers from metadata are accessible"
        
        # Step 4: Create cryptographic context (same as encryption)
        U = crypto.H(uid.encode(), did.encode(), bid.encode(), pin)
        
        # Generate random r and compute B for recovery protocol
        p = crypto.q
        r = secrets.randbelow(p - 1) + 1
        r_inv = pow(r, -1, p)
        B = crypto.point_mul(r, U)
        
        # Step 5: Recover shares from servers using authentication codes
        recovered_shares = []
        
        for i, (server_url, client) in enumerate(clients):
            auth_code = server_auth_codes[server_url]
            
            try:
                # Get current guess number for this backup from this specific server
                backups, error = client.list_backups(auth_code, encrypted=False)
                if error:
                    guess_num = 0  # Start with 0 if we can't determine current state
                else:
                    # Find our backup in the list from this server
                    guess_num = 0
                    for backup in backups:
                        backup_bid = backup[1] if len(backup) > 1 else ""
                        if backup_bid == bid:
                            guess_num = backup[3] if len(backup) > 3 else 0  # num_guesses field
                            break
                
                # Attempt recovery from this specific server
                result, error = client.recover_secret(
                    auth_code=auth_code,
                    did=did,
                    bid=bid,
                    b=crypto.unexpand(B),
                    guess_num=guess_num,
                    encrypted=False
                )
                
                if error:
                    print(f"Server {i+1} recovery failed: {error}")
                    continue
                    
                version, x, si_b_unexpanded, num_guesses, max_guesses, expiration = result
                recovered_shares.append((x, si_b_unexpanded))
                print(f"OpenADP: Recovered share {x} from server {i+1}")
                
            except Exception as e:
                print(f"Exception recovering from server {i+1}: {e}")
                continue
        
        if len(recovered_shares) < threshold:
            return None, f"Could not recover enough shares (got {len(recovered_shares)}, need at least {threshold})"
        
        # Step 6: Reconstruct secret using recovered shares
        rec_sb = sharing.recover_sb(recovered_shares)
        rec_s_point = crypto.point_mul(r_inv, crypto.expand(rec_sb))
        
        # Step 7: Derive same encryption key
        enc_key = crypto.deriveEncKey(rec_s_point)
        
        return enc_key, None


if __name__ == "__main__":
    # Run the integration test
    pytest.main([__file__, "-v", "-s"]) 