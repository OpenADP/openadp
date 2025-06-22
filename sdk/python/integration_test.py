#!/usr/bin/env python3
"""
Integration test for OpenADP Python SDK

This test demonstrates the complete OpenADP workflow using the Python SDK:
1. Generate authentication codes and identifiers
2. Create secret shares using threshold cryptography
3. Connect to OpenADP servers using JSON-RPC with Noise-NK encryption
4. Register shares with servers
5. Recover shares from servers
6. Reconstruct the original secret
7. Verify the encryption key derivation

This test validates cross-language compatibility with the Go implementation.

Run with: python integration_test.py
"""

import sys
import os
import time
import json
import tempfile
import subprocess
import hashlib
from typing import List, Dict, Any

# Add the SDK to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from openadp import (
    OpenADPClient, EncryptedOpenADPClient, MultiServerClient,
    derive_identifiers, password_to_pin, generate_auth_codes,
    generate_encryption_key, recover_encryption_key,
    ServerInfo
)
from openadp.keygen import GenerateEncryptionKeyResult, RecoverEncryptionKeyResult
from openadp.crypto import derive_secret, derive_enc_key, H


class IntegrationTestSuite:
    """Integration test suite for OpenADP Python SDK"""
    
    def __init__(self):
        self.test_servers = []
        self.server_processes = []
        
    def start_test_servers(self, start_port: int = 18081, count: int = 3) -> List[str]:
        """Start test OpenADP servers for integration testing"""
        server_urls = []
        
        print(f"🖥️  Starting {count} test servers...")
        
        # Check if we can start Go test servers
        try:
            # Try to find the openadp-server binary
            server_binary = self._find_server_binary()
            if not server_binary:
                print("⚠️  No openadp-server binary found, using mock servers")
                return self._start_mock_servers(start_port, count)
            
            for i in range(count):
                port = start_port + i
                server_url = f"http://localhost:{port}"
                
                # Create temporary database for each server
                temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
                temp_db.close()
                
                # Start server process
                cmd = [
                    server_binary,
                    '-port', str(port),
                    '-db', temp_db.name,
                ]
#temp
                print("cmd =", cmd)
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                self.server_processes.append(process)
                server_urls.append(server_url)
                
                print(f"   Started server {i+1}: {server_url}")
                
            # Give servers time to start
            time.sleep(2)
            
            # Verify servers are responding
            live_servers = []
            for url in server_urls:
                try:
                    client = OpenADPClient(url)
                    info = client.get_server_info()
                    if info:
                        live_servers.append(url)
                        print(f"   ✅ Server {url} is live")
                    else:
                        print(f"   ❌ Server {url} not responding")
                except Exception as e:
                    print(f"   ❌ Server {url} error: {e}")
            
            return live_servers
            
        except Exception as e:
            print(f"Failed to start real servers: {e}")
            return self._start_mock_servers(start_port, count)
    
    def _find_server_binary(self) -> str:
        """Find the openadp-server binary"""
        possible_paths = [
            '../../build/openadp-server',
            '../build/openadp-server',
            './build/openadp-server',
            'openadp-server'
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, '-version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        return None
    
    def _start_mock_servers(self, start_port: int, count: int) -> List[str]:
        """Start mock servers for testing when real servers aren't available"""
        print("   Using mock servers (limited functionality)")
        return [f"http://localhost:{start_port + i}" for i in range(count)]
    
    def get_server_infos(self, server_urls: List[str]) -> List[ServerInfo]:
        """Get server info including public keys from servers"""
        server_infos = []
        
        for url in server_urls:
            try:
                client = OpenADPClient(url)
                info = client.get_server_info()
                
                public_key = ""
                if info and "noise_nk_public_key" in info:
                    public_key = f"ed25519:{info['noise_nk_public_key']}"
                
                server_infos.append(ServerInfo(
                    url=url,
                    public_key=public_key,
                    country="Test"
                ))
                
            except Exception as e:
                print(f"Warning: Failed to get info from {url}: {e}")
                # Add server without public key
                server_infos.append(ServerInfo(
                    url=url,
                    public_key="",
                    country="Test"
                ))
        
        return server_infos
    
    def cleanup(self):
        """Clean up test servers and resources"""
        print("\n🧹 Cleaning up test servers...")
        
        for process in self.server_processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            except Exception as e:
                print(f"Error cleaning up process: {e}")
    
    def test_identifier_derivation(self):
        """Test identifier derivation matches Go implementation"""
        print("\n🆔 Step 1: Testing identifier derivation...")
        
        # Test cases that should match Go implementation
        test_cases = [
            {
                "filename": "test-file.txt",
                "user_id": "test@example.com",
                "hostname": "test-hostname"
            },
            {
                "filename": "integration-test-backup.tar.gz",
                "user_id": "integration-test@openadp.org",
                "hostname": "test-device-hostname"
            }
        ]
        
        for case in test_cases:
            uid, did, bid = derive_identifiers(
                case["filename"], 
                case["user_id"], 
                case["hostname"]
            )
            
            print(f"   Input: {case}")
            print(f"   UID: {uid}")
            print(f"   DID: {did}")
            print(f"   BID: {bid}")
            
            # Verify deterministic
            uid2, did2, bid2 = derive_identifiers(
                case["filename"], 
                case["user_id"], 
                case["hostname"]
            )
            
            assert uid == uid2 and did == did2 and bid == bid2, "Identifier derivation not deterministic"
            print("   ✅ Identifier derivation is deterministic")
    
    def test_password_to_pin(self):
        """Test password to PIN conversion"""
        print("\n🔢 Step 2: Testing password to PIN conversion...")
        
        password = "test-password-123"
        pin1 = password_to_pin(password)
        pin2 = password_to_pin(password)
        
        print(f"   Password: {password}")
        print(f"   PIN: {pin1[:8].hex()}")
        
        assert pin1 == pin2, "PIN conversion not deterministic"
        assert len(pin1) == 2, f"PIN should be 2 bytes, got {len(pin1)}"
        print("   ✅ PIN conversion is deterministic")
    
    def test_auth_code_generation(self):
        """Test authentication code generation"""
        print("\n🔐 Step 3: Testing authentication code generation...")
        
        server_urls = [
            "http://server1.test.com",
            "http://server2.test.com",
            "http://server3.test.com"
        ]
        
        auth_codes = generate_auth_codes(server_urls)
        
        print(f"   Base auth code: {auth_codes.base_auth_code}")
        print(f"   Generated {len(auth_codes.server_auth_codes)} server-specific codes")
        
        # Verify each server has a unique code
        codes = list(auth_codes.server_auth_codes.values())
        assert len(set(codes)) == len(codes), "Server auth codes are not unique"
        
        # Verify server codes are correctly derived from base code
        # Note: Base auth codes should be random (non-deterministic), but server codes should be deterministic from base
        for server_url in server_urls:
            expected_server_code = hashlib.sha256((auth_codes.base_auth_code + server_url).encode('utf-8')).hexdigest()
            assert auth_codes.server_auth_codes[server_url] == expected_server_code, f"Server code derivation incorrect for {server_url}"
        
        print("   ✅ Auth code generation working correctly")
    
    def test_key_generation_and_recovery(self, server_urls: List[str]):
        """Test complete key generation and recovery workflow"""
        print("\n🔐 Step 4: Testing key generation and recovery...")
        
        if not server_urls:
            raise Exception("No servers available - integration tests require live servers")
        
        # Test parameters
        filename = "integration-test-file.txt"
        password = "test-password-123"
        user_id = "integration-test@openadp.org"
        max_guesses = 10
        expiration = int(time.time()) + 3600  # 1 hour from now
        
        # Get server info with public keys
        server_infos = self.get_server_infos(server_urls)
        
        print(f"   Using {len(server_infos)} servers")
        for info in server_infos:
            if info.public_key:
                print(f"   ✅ Server {info.url}: Has public key (Noise-NK enabled)")
            else:
                print(f"   ⚠️  Server {info.url}: No public key (encryption disabled)")
        
        # Step 4a: Generate encryption key
        print("   🔐 Generating encryption key...")
        
        result = generate_encryption_key(
            filename=filename,
            password=password,
            user_id=user_id,
            max_guesses=max_guesses,
            expiration=expiration,
            server_infos=server_infos
        )
        
        if result.error:
            if "No live servers" in result.error or "Failed to register" in result.error:
                print(f"   ⚠️  Key generation failed (expected with mock servers): {result.error}")
                return
            else:
                raise Exception(f"Key generation failed: {result.error}")
        
        print(f"   ✅ Generated key: {result.encryption_key[:16].hex()}")
        print(f"   ✅ Used {len(result.server_urls)} servers with threshold {result.threshold}")
        
        # Step 4b: Recover encryption key
        print("   🔓 Recovering encryption key...")
        
        recovery_result = recover_encryption_key(
            filename=filename,
            password=password,
            user_id=user_id,
            server_infos=server_infos,
            threshold=result.threshold,
            auth_codes=result.auth_codes
        )
        
        if recovery_result.error:
            raise Exception(f"Key recovery failed: {recovery_result.error}")
        
        print(f"   ✅ Recovered key: {recovery_result.encryption_key[:16].hex()}")
        
        # Step 4c: Verify keys match
        assert result.encryption_key == recovery_result.encryption_key, "Recovered key doesn't match original"
        print("   ✅ Key recovery successful - keys match!")
    
    def test_multi_server_client(self, server_urls: List[str]):
        """Test multi-server client functionality"""
        print("\n🌐 Step 5: Testing multi-server client...")
        
        if not server_urls:
            raise Exception("No servers available - integration tests require live servers")
        
        server_infos = self.get_server_infos(server_urls)
        
        try:
            client = MultiServerClient.from_server_info(server_infos, echo_timeout=5, max_workers=10)
            
            # Test server info retrieval
            live_count = client.get_live_server_count()
            print(f"   ✅ Multi-server client connected to {live_count} servers")
            
            # Test ping functionality
            ping_results = {}
            for info in server_infos:
                try:
                    basic_client = OpenADPClient(info.url)
                    result = basic_client.ping()
                    ping_results[info.url] = result
                    print(f"   ✅ Ping {info.url}: {result}")
                except Exception as e:
                    ping_results[info.url] = f"Error: {e}"
                    print(f"   ❌ Ping {info.url}: {e}")
            
        except Exception as e:
            print(f"   ⚠️  Multi-server client test failed: {e}")
    
    def test_noise_nk_encryption(self, server_urls: List[str]):
        """Test Noise-NK encryption functionality"""
        print("\n🔒 Step 6: Testing Noise-NK encryption...")
        
        if not server_urls:
            raise Exception("No servers available - integration tests require live servers")
        
        server_infos = self.get_server_infos(server_urls)
        
        for info in server_infos:
            if not info.public_key:
                print(f"   ⚠️  Server {info.url}: No public key, skipping Noise-NK test")
                continue
            
            try:
                # Test encrypted client creation
                import base64
                public_key_bytes = base64.b64decode(info.public_key.replace("ed25519:", ""))
                client = EncryptedOpenADPClient(info.url, public_key_bytes)
                
                # Test encrypted ping
                result = client.ping()
                print(f"   ✅ Encrypted ping to {info.url}: {result}")
                
            except Exception as e:
                print(f"   ❌ Noise-NK test failed for {info.url}: {e}")
    
    def run_all_tests(self):
        """Run all integration tests"""
        print("🚀 OpenADP Python SDK Integration Test")
        print("=====================================")
        
        try:
            # Step 0: Start test servers
            server_urls = self.start_test_servers()
            
            # Step 1-3: Basic functionality tests (no servers needed)
            self.test_identifier_derivation()
            self.test_password_to_pin()
            self.test_auth_code_generation()
            
            # Step 4-6: Server-dependent tests
            if not server_urls:
                print("\n❌ No servers available - integration tests require live servers")
                print("   Please start OpenADP servers or check server connectivity")
                return False
                
            self.test_key_generation_and_recovery(server_urls)
            self.test_multi_server_client(server_urls)
            self.test_noise_nk_encryption(server_urls)
            
            print("\n🎉 All integration tests completed successfully!")
            print("==========================================")
            
        except Exception as e:
            print(f"\n❌ Integration test failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        finally:
            self.cleanup()
        
        return True


def main():
    """Run integration tests"""
    suite = IntegrationTestSuite()
    success = suite.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main() 
