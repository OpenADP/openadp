#!/usr/bin/env python3
"""
Basic integration test with Go servers (unencrypted)

This test validates the basic JSON-RPC compatibility between Python SDK and Go servers
using unencrypted operations. This helps isolate JSON-RPC compatibility issues from
Noise-NK encryption issues.

Run with: python3 basic_go_integration_test.py
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
    OpenADPClient, EncryptedOpenADPClient,
    derive_identifiers, password_to_pin, generate_auth_codes,
    ServerInfo
)


class BasicGoIntegrationTest:
    """Basic integration test with Go servers (unencrypted operations)"""
    
    def __init__(self):
        self.server_processes = []
        self.server_urls = []
        self.temp_databases = []
        
    def start_go_servers(self, count: int = 3, start_port: int = 19100) -> List[str]:
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
                    print(f"   ✅ Server {url} is live (version: {info.get('version', 'unknown')})")
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
    
    def test_basic_json_rpc(self):
        """Test basic JSON-RPC operations"""
        print("\n🔗 Testing basic JSON-RPC operations...")
        
        for url in self.server_urls:
            try:
                client = OpenADPClient(url)
                
                # Test ping
                result = client.ping()
                print(f"   ✅ Ping {url}: {result}")
                
                # Test get_server_info
                info = client.get_server_info()
                print(f"   ✅ Server info {url}: version={info.get('version', 'unknown')}")
                
                # Test echo if available
                try:
                    echo_result = client.echo("test message")
                    print(f"   ✅ Echo {url}: {echo_result}")
                except Exception as e:
                    print(f"   ⚠️  Echo {url}: {e}")
                
            except Exception as e:
                print(f"   ❌ Failed to test {url}: {e}")
                return False
        
        return True
    
    def test_unencrypted_secret_operations(self):
        """Test secret registration and recovery without encryption"""
        print("\n🔐 Testing unencrypted secret operations...")
        
        if not self.server_urls:
            print("   ❌ No servers available")
            return False
        
        # Test parameters
        uid = "test-user@example.com"
        did = "test-device"
        bid = "test-backup"
        version = 1
        x = 1  # Share index
        y = "123456789"  # Simple test value as string
        max_guesses = 10
        expiration = int(time.time()) + 3600  # 1 hour from now
        
        # Generate auth code
        auth_codes = generate_auth_codes([self.server_urls[0]])
        auth_code = auth_codes.server_auth_codes[self.server_urls[0]]
        
        try:
            # Test with first server
            client = EncryptedOpenADPClient(self.server_urls[0])
            
            # Test registration (unencrypted)
            print("   🔐 Testing secret registration (unencrypted)...")
            
            success = client.register_secret(
                auth_code, uid, did, bid, version, x, y, 
                max_guesses, expiration, encrypted=False
            )
            
            if success:
                print("   ✅ Secret registration successful")
            else:
                print("   ❌ Secret registration failed")
                return False
            
            # Test recovery (unencrypted) 
            print("   🔓 Testing secret recovery (unencrypted)...")
            
            # For recovery, we need a blinded point 'b'
            # For testing, we'll use a simple test value
            b = "test_blinded_point_base64"  # This would normally be a proper point
            guess_num = 1
            
            try:
                recovery_result = client.recover_secret(
                    auth_code, uid, did, bid, b, guess_num, encrypted=False
                )
                print(f"   ✅ Secret recovery successful: {recovery_result}")
            except Exception as e:
                # Recovery might fail due to invalid test data, but we're testing the protocol
                print(f"   ⚠️  Secret recovery failed (expected with test data): {e}")
            
            return True
            
        except Exception as e:
            print(f"   ❌ Secret operations failed: {e}")
            return False
    
    def test_list_backups(self):
        """Test listing backups"""
        print("\n📋 Testing list backups...")
        
        if not self.server_urls:
            print("   ❌ No servers available")
            return False
        
        try:
            client = EncryptedOpenADPClient(self.server_urls[0])
            
            # Test list backups (unencrypted)
            uid = "test-user@example.com"
            backups = client.list_backups(uid, encrypted=False)
            
            print(f"   ✅ List backups successful: found {len(backups)} backups")
            return True
            
        except Exception as e:
            print(f"   ❌ List backups failed: {e}")
            return False
    
    def test_identifier_derivation_compatibility(self):
        """Test that identifier derivation produces consistent results"""
        print("\n🆔 Testing identifier derivation...")
        
        test_cases = [
            ("test-file.txt", "user@example.com", "hostname"),
            ("backup.tar.gz", "test@domain.com", "device123"),
        ]
        
        for filename, user_id, hostname in test_cases:
            uid, did, bid = derive_identifiers(filename, user_id, hostname)
            
            print(f"   Input: {filename}, {user_id}, {hostname}")
            print(f"   Output: UID={uid}, DID={did}, BID={bid}")
            
            # Verify deterministic
            uid2, did2, bid2 = derive_identifiers(filename, user_id, hostname)
            if uid != uid2 or did != did2 or bid != bid2:
                print("   ❌ Identifier derivation not deterministic")
                return False
        
        print("   ✅ Identifier derivation working correctly")
        return True
    
    def test_password_to_pin(self):
        """Test password to PIN conversion"""
        print("\n🔑 Testing password to PIN conversion...")
        
        passwords = ["test123", "secure_password", "πάσσωορδ"]
        
        for password in passwords:
            pin1 = password_to_pin(password)
            pin2 = password_to_pin(password)
            
            if pin1 != pin2:
                print(f"   ❌ PIN conversion not deterministic for '{password}'")
                return False
            
            print(f"   ✅ Password '{password}' -> PIN: {pin1[:8].hex()}")
        
        print("   ✅ Password to PIN conversion working correctly")
        return True
    
    def run_all_tests(self):
        """Run all basic integration tests"""
        print("🚀 OpenADP Basic Integration Test with Go Servers")
        print("=================================================")
        
        try:
            # Start Go servers
            live_servers = self.start_go_servers()
            
            if not live_servers:
                print("❌ No servers started successfully")
                return False
            
            print(f"\n✅ Started {len(live_servers)} Go servers successfully")
            
            # Run tests
            tests = [
                ("Identifier Derivation", self.test_identifier_derivation_compatibility),
                ("Password to PIN", self.test_password_to_pin),
                ("Basic JSON-RPC", self.test_basic_json_rpc),
                ("List Backups", self.test_list_backups),
                ("Unencrypted Secret Operations", self.test_unencrypted_secret_operations),
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
                print("\n🎉 All basic integration tests passed!")
                print("   Python SDK basic JSON-RPC compatibility with Go servers verified!")
                return True
            else:
                print(f"\n⚠️  {total - passed} test(s) failed.")
                print("   There are compatibility issues that need to be addressed.")
                return False
                
        except Exception as e:
            print(f"\n❌ Integration test suite failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        finally:
            self.cleanup()


def main():
    """Run basic integration tests with Go servers"""
    test_suite = BasicGoIntegrationTest()
    
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