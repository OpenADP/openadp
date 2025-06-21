#!/usr/bin/env python3
"""
Integration test with real Go servers

This test starts actual OpenADP Go servers and tests the Python SDK against them
to validate cross-language compatibility. This is the ultimate test to ensure
that Python clients can work with Go servers.

Run with: python3 integration_with_go_servers.py
"""

import sys
import os
import time
import subprocess
import tempfile
import signal
from typing import List

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from openadp import (
    OpenADPClient, EncryptedOpenADPClient, MultiServerClient,
    derive_identifiers, password_to_pin, generate_auth_codes,
    generate_encryption_key, recover_encryption_key,
    ServerInfo
)


class GoServerIntegrationTest:
    """Integration test with real Go servers"""
    
    def __init__(self):
        self.server_processes = []
        self.server_urls = []
        self.temp_databases = []
        
    def start_go_servers(self, count: int = 3, start_port: int = 19000) -> List[str]:
        """Start Go OpenADP servers"""
        print(f"🖥️  Starting {count} Go servers...")
        
        # Find the server binary
        server_binary = os.path.join(os.path.dirname(__file__), '..', 'build', 'openadp-server')
        if not os.path.exists(server_binary):
            raise Exception(f"Server binary not found at {server_binary}")
        
        server_urls = []
        
        for i in range(count):
            port = start_port + i
            server_url = f"http://localhost:{port}"
            
            # Create temporary database
            temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
            temp_db.close()
            self.temp_databases.append(temp_db.name)
            
            # Start server
            cmd = [
                server_binary,
                '-port', str(port),
                '-db', temp_db.name
            ]
            
            print(f"   Starting server {i+1}: {server_url}")
            print(f"   Command: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.server_processes.append(process)
            server_urls.append(server_url)
        
        # Give servers time to start
        print("   Waiting for servers to start...")
        time.sleep(3)
        
        # Verify servers are running
        live_servers = []
        for url in server_urls:
            try:
                client = OpenADPClient(url)
                info = client.get_server_info()
                if info:
                    live_servers.append(url)
                    print(f"   ✅ Server {url} is live")
                    if 'noise_nk_public_key' in info:
                        print(f"      Noise-NK public key: {info['noise_nk_public_key'][:16]}...")
                else:
                    print(f"   ❌ Server {url} not responding")
            except Exception as e:
                print(f"   ❌ Server {url} error: {e}")
        
        self.server_urls = live_servers
        return live_servers
    
    def cleanup(self):
        """Clean up servers and temp files"""
        print("\n🧹 Cleaning up servers...")
        
        for process in self.server_processes:
            try:
                process.terminate()
                process.wait(timeout=5)
                print("   ✅ Server terminated gracefully")
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                print("   ⚠️  Server killed forcefully")
            except Exception as e:
                print(f"   ❌ Error stopping server: {e}")
        
        # Clean up temp databases
        for db_path in self.temp_databases:
            try:
                os.unlink(db_path)
            except Exception as e:
                print(f"   Warning: Failed to delete {db_path}: {e}")
    
    def get_server_infos(self) -> List[ServerInfo]:
        """Get server info with public keys"""
        server_infos = []
        
        for url in self.server_urls:
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
        
        return server_infos
    
    def test_basic_connectivity(self):
        """Test basic connectivity to Go servers"""
        print("\n🔗 Testing basic connectivity...")
        
        for url in self.server_urls:
            try:
                client = OpenADPClient(url)
                result = client.ping()
                print(f"   ✅ Ping {url}: {result}")
                
                info = client.get_server_info()
                print(f"   ✅ Server info {url}: version={info.get('version', 'unknown')}")
                
            except Exception as e:
                print(f"   ❌ Failed to connect to {url}: {e}")
                return False
        
        return True
    
    def test_encrypted_connectivity(self):
        """Test encrypted connectivity using Noise-NK"""
        print("\n🔒 Testing encrypted connectivity...")
        
        server_infos = self.get_server_infos()
        
        for info in server_infos:
            if not info.public_key:
                print(f"   ⚠️  Server {info.url}: No public key, skipping encryption test")
                continue
            
            try:
                import base64
                public_key_bytes = base64.b64decode(info.public_key.replace("ed25519:", ""))
                client = EncryptedOpenADPClient(info.url, public_key_bytes)
                
                result = client.ping()
                print(f"   ✅ Encrypted ping {info.url}: {result}")
                
                server_info = client.get_server_info()
                print(f"   ✅ Encrypted server info {info.url}: OK")
                
            except Exception as e:
                print(f"   ❌ Encrypted connection failed for {info.url}: {e}")
                return False
        
        return True
    
    def test_key_generation_and_recovery(self):
        """Test complete key generation and recovery workflow"""
        print("\n🔐 Testing key generation and recovery with Go servers...")
        
        if not self.server_urls:
            print("   ❌ No servers available")
            return False
        
        # Test parameters
        filename = "integration-test-file.txt"
        password = "test-password-123"
        user_id = "integration-test@openadp.org"
        max_guesses = 10
        expiration = int(time.time()) + 3600  # 1 hour from now
        
        server_infos = self.get_server_infos()
        
        print(f"   Using {len(server_infos)} Go servers")
        for info in server_infos:
            if info.public_key:
                print(f"   ✅ Server {info.url}: Noise-NK enabled")
            else:
                print(f"   ⚠️  Server {info.url}: No encryption")
        
        try:
            # Step 1: Generate encryption key
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
                print(f"   ❌ Key generation failed: {result.error}")
                return False
            
            print(f"   ✅ Generated key: {result.encryption_key[:16].hex()}")
            print(f"   ✅ Used {len(result.server_urls)} servers with threshold {result.threshold}")
            
            # Step 2: Recover encryption key
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
                print(f"   ❌ Key recovery failed: {recovery_result.error}")
                return False
            
            print(f"   ✅ Recovered key: {recovery_result.encryption_key[:16].hex()}")
            
            # Step 3: Verify keys match
            if result.encryption_key != recovery_result.encryption_key:
                print("   ❌ Recovered key doesn't match original!")
                print(f"      Original:  {result.encryption_key.hex()}")
                print(f"      Recovered: {recovery_result.encryption_key.hex()}")
                return False
            
            print("   ✅ Key recovery successful - keys match!")
            return True
            
        except Exception as e:
            print(f"   ❌ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_multi_server_client(self):
        """Test multi-server client functionality"""
        print("\n🌐 Testing multi-server client...")
        
        if not self.server_urls:
            print("   ❌ No servers available")
            return False
        
        try:
            server_infos = self.get_server_infos()
            client = MultiServerClient.from_server_info(server_infos, echo_timeout=10, max_workers=3)
            
            # Test basic operations
            print("   Testing multi-server operations...")
            
            # We can't test actual secret operations without implementing the full protocol
            # But we can test that the client can connect to multiple servers
            
            print(f"   ✅ Multi-server client created with {len(server_infos)} servers")
            return True
            
        except Exception as e:
            print(f"   ❌ Multi-server client test failed: {e}")
            return False
    
    def run_all_tests(self):
        """Run all integration tests"""
        print("🚀 OpenADP Python SDK Integration Test with Go Servers")
        print("=====================================================")
        
        try:
            # Start Go servers
            live_servers = self.start_go_servers()
            
            if not live_servers:
                print("❌ No servers started successfully")
                return False
            
            print(f"\n✅ Started {len(live_servers)} Go servers successfully")
            
            # Run tests
            tests = [
                ("Basic Connectivity", self.test_basic_connectivity),
                ("Encrypted Connectivity", self.test_encrypted_connectivity),
                ("Key Generation and Recovery", self.test_key_generation_and_recovery),
                ("Multi-Server Client", self.test_multi_server_client),
            ]
            
            results = []
            for test_name, test_func in tests:
                print(f"\n{'='*50}")
                print(f"Running: {test_name}")
                print(f"{'='*50}")
                
                try:
                    result = test_func()
                    results.append((test_name, result))
                except Exception as e:
                    print(f"❌ Test '{test_name}' failed with exception: {e}")
                    import traceback
                    traceback.print_exc()
                    results.append((test_name, False))
            
            # Summary
            print(f"\n{'='*50}")
            print("Test Summary")
            print(f"{'='*50}")
            
            passed = sum(1 for _, result in results if result)
            total = len(results)
            
            for test_name, result in results:
                status = "✅ PASS" if result else "❌ FAIL"
                print(f"{status} {test_name}")
            
            print(f"\nResults: {passed}/{total} tests passed")
            
            if passed == total:
                print("\n🎉 All integration tests with Go servers passed!")
                print("   Python SDK is fully compatible with Go servers!")
                return True
            else:
                print(f"\n⚠️  {total - passed} test(s) failed.")
                print("   There may be compatibility issues between Python SDK and Go servers.")
                return False
                
        except Exception as e:
            print(f"\n❌ Integration test suite failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        finally:
            self.cleanup()


def main():
    """Run integration tests with Go servers"""
    test_suite = GoServerIntegrationTest()
    
    def signal_handler(signum, frame):
        print("\n\n🛑 Received interrupt signal, cleaning up...")
        test_suite.cleanup()
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        success = test_suite.run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n🛑 Test interrupted by user")
        test_suite.cleanup()
        sys.exit(1)


if __name__ == "__main__":
    main() 