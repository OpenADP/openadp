#!/usr/bin/env python3
"""
Integration test for complete encrypt/decrypt workflow using actual tools.

This test demonstrates the full OpenADP system in action by actually running
the encrypt.py and decrypt.py tools that users would use:
1. Real local OpenADP servers
2. Actual encrypt.py tool execution
3. Actual decrypt.py tool execution
4. Complete file integrity verification

This is the ultimate end-to-end integration test that validates the actual
user experience.
"""

import os
import sys
import tempfile
import pytest
import subprocess
import time
import json
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))


class TestEncryptDecryptE2E:
    """Complete encrypt/decrypt integration test using actual tools."""
    
    # Class-level state for sharing between tests
    server_processes = []
    test_file_content = None
    test_file_path = None
    encrypted_file_path = None
    tools_dir = None
    server_urls = [
        "http://localhost:9200",
        "http://localhost:9201", 
        "http://localhost:9202"
    ]
    
    @classmethod
    def setup_class(cls):
        """Set up the test environment with real servers."""
        print("\n🚀 Setting up Encrypt/Decrypt Tools Integration Test")
        print("=" * 60)
        
        # Find tools directory
        cls.tools_dir = os.path.join(os.path.dirname(__file__), '../../tools')
        if not os.path.exists(cls.tools_dir):
            raise FileNotFoundError(f"Tools directory not found: {cls.tools_dir}")
        
        # Verify tools exist
        encrypt_tool = os.path.join(cls.tools_dir, 'encrypt.py')
        decrypt_tool = os.path.join(cls.tools_dir, 'decrypt.py')
        
        if not os.path.exists(encrypt_tool):
            raise FileNotFoundError(f"encrypt.py not found: {encrypt_tool}")
        if not os.path.exists(decrypt_tool):
            raise FileNotFoundError(f"decrypt.py not found: {decrypt_tool}")
            
        print(f"✅ Found tools directory: {cls.tools_dir}")
        print(f"✅ Found encrypt.py: {encrypt_tool}")
        print(f"✅ Found decrypt.py: {decrypt_tool}")
        
        # Start real OpenADP servers
        cls._start_openadp_servers()
        
        # Create test file content
        cls.test_file_content = """
This is a test file for OpenADP encrypt/decrypt tools integration testing.

It contains multiple lines of text to demonstrate that the complete
encryption and decryption workflow is working correctly with the actual
tools that users would run.

The file includes:
- Multiple paragraphs
- Special characters: !@#$%^&*()
- Unicode: 🔐 🚀 ✅ 🎉
- Numbers: 1234567890
- Mixed content types

This comprehensive test validates the entire OpenADP system from
the actual command-line tools through encryption, secret sharing, 
recovery, and final decryption back to the original content.

If you can read this after the full encrypt/decrypt cycle using
the real tools, then the OpenADP system is working perfectly! 🎯
""".strip()
        
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(cls.test_file_content)
            cls.test_file_path = f.name
        
        print(f"✅ Created test file: {cls.test_file_path}")
        print(f"✅ Test file size: {len(cls.test_file_content)} bytes")
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
        
        # Start servers on ports 9200, 9201, 9202
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
        
        # Clean up test files
        if cls.test_file_path and os.path.exists(cls.test_file_path):
            os.remove(cls.test_file_path)
        if cls.encrypted_file_path and os.path.exists(cls.encrypted_file_path):
            os.remove(cls.encrypted_file_path)
        
        print("✅ Cleanup complete")
    
    def test_01_tools_availability(self):
        """Test that the encrypt/decrypt tools are available and show help."""
        print("\n🔧 Testing Tools Availability")
        print("=" * 40)
        
        encrypt_tool = os.path.join(self.tools_dir, 'encrypt.py')
        decrypt_tool = os.path.join(self.tools_dir, 'decrypt.py')
        
        # Test encrypt.py --help
        result = subprocess.run([
            sys.executable, encrypt_tool, '--help'
        ], capture_output=True, text=True, cwd=self.tools_dir)
        
        assert result.returncode == 0, f"encrypt.py --help failed: {result.stderr}"
        assert "encrypt files using openadp" in result.stdout.lower(), "encrypt.py help text missing"
        print("✅ encrypt.py --help working")
        
        # Test decrypt.py --help
        result = subprocess.run([
            sys.executable, decrypt_tool, '--help'
        ], capture_output=True, text=True, cwd=self.tools_dir)
        
        assert result.returncode == 0, f"decrypt.py --help failed: {result.stderr}"
        assert "decrypt files" in result.stdout.lower(), "decrypt.py help text missing"
        print("✅ decrypt.py --help working")
        
        print("✅ Tools availability confirmed")
    
    def test_02_server_connectivity(self):
        """Test that OpenADP servers are running and accessible."""
        print("\n🖥️  Testing Server Connectivity")
        print("=" * 40)
        
        # Test server connectivity by trying to connect
        live_servers = 0
        for i, server_url in enumerate(self.server_urls, 1):
            try:
                import requests
                response = requests.get(f"{server_url}/", timeout=2)
                # Accept any HTTP response as "server is up" - 501 is "Not Implemented" which is fine
                if response.status_code in [200, 404, 405, 501]:
                    print(f"  ✅ Server {i} ({server_url}): Responding (status {response.status_code})")
                    live_servers += 1
                else:
                    print(f"  ⚠️  Server {i} ({server_url}): Unexpected status {response.status_code}")
            except Exception as e:
                print(f"  ❌ Server {i} ({server_url}): Not responding - {e}")
        
        assert live_servers >= 2, f"Need at least 2 live servers for threshold crypto, got {live_servers}"
        
        print(f"✅ Live servers: {live_servers}")
        print("✅ Server connectivity confirmed")
    
    def test_03_file_encryption(self):
        """Test file encryption using the actual encrypt.py tool."""
        print("\n🔒 Testing File Encryption with Real Tool")
        print("=" * 40)
        
        encrypt_tool = os.path.join(self.tools_dir, 'encrypt.py')
        password = "integration_test_password_123"
        
        print(f"📁 Input file: {self.test_file_path}")
        print(f"📊 File size: {len(self.test_file_content)} bytes")
        print(f"🔑 Password: {password}")
        print(f"🛠️  Tool: {encrypt_tool}")
        
        # Run encrypt.py tool
        print("🔑 Running encrypt.py tool...")
        result = subprocess.run([
            sys.executable, encrypt_tool,
            self.test_file_path,
            '--password', password,
            '--servers'] + self.server_urls,
        capture_output=True, text=True, cwd=self.tools_dir)
        
        print(f"📤 Encrypt tool output:")
        print(result.stdout)
        if result.stderr:
            print(f"📤 Encrypt tool stderr:")
            print(result.stderr)
        
        assert result.returncode == 0, f"encrypt.py failed with exit code {result.returncode}: {result.stderr}"
        
        # Check that encrypted file was created and store in class variable
        TestEncryptDecryptE2E.encrypted_file_path = self.test_file_path + '.enc'
        assert os.path.exists(TestEncryptDecryptE2E.encrypted_file_path), f"Encrypted file not created: {TestEncryptDecryptE2E.encrypted_file_path}"
        
        # Verify encrypted file is different and larger
        with open(TestEncryptDecryptE2E.encrypted_file_path, 'rb') as f:
            encrypted_content = f.read()
        
        assert len(encrypted_content) > len(self.test_file_content), "Encrypted file should be larger"
        
        # Verify success message in output
        assert "✅ File encrypted successfully!" in result.stdout, "Success message not found in output"
        assert "Authentication: Enabled (Authentication Codes)" in result.stdout, "Auth codes not mentioned"
        
        print(f"✅ Encrypted file created: {TestEncryptDecryptE2E.encrypted_file_path}")
        print(f"✅ Encrypted size: {len(encrypted_content)} bytes")
        print("✅ File encryption successful")
    
    def test_04_encrypted_file_metadata(self):
        """Verify the encrypted file contains proper metadata."""
        print("\n🔍 Testing Encrypted File Metadata")
        print("=" * 40)
        
        assert TestEncryptDecryptE2E.encrypted_file_path is not None, "Encrypted file should exist from previous test"
        assert os.path.exists(TestEncryptDecryptE2E.encrypted_file_path), "Encrypted file should exist on disk"
        
        # Read and parse the encrypted file metadata
        with open(TestEncryptDecryptE2E.encrypted_file_path, 'rb') as f:
            file_data = f.read()
        
        # Parse file format: [metadata_length][metadata][nonce][encrypted_data]
        metadata_length = int.from_bytes(file_data[:4], 'little')
        metadata_start = 4
        metadata_end = metadata_start + metadata_length
        
        metadata_json = file_data[metadata_start:metadata_end]
        metadata = json.loads(metadata_json.decode('utf-8'))
        
        print(f"📊 Metadata length: {metadata_length} bytes")
        print(f"📊 Metadata keys: {list(metadata.keys())}")
        
        # Verify required metadata fields
        assert 'servers' in metadata, "servers field missing from metadata"
        assert 'threshold' in metadata, "threshold field missing from metadata"
        assert 'auth_codes' in metadata, "auth_codes field missing from metadata"
        assert 'user_id' in metadata, "user_id field missing from metadata"
        assert 'version' in metadata, "version field missing from metadata"
        
        # Verify auth_codes structure
        auth_codes = metadata['auth_codes']
        assert 'base_auth_code' in auth_codes, "base_auth_code missing from auth_codes"
        assert 'server_auth_codes' in auth_codes, "server_auth_codes missing from auth_codes"
        
        # Verify auth code formats
        base_auth_code = auth_codes['base_auth_code']
        assert len(base_auth_code) == 32, f"base_auth_code should be 32 chars, got {len(base_auth_code)}"
        assert all(c in '0123456789abcdef' for c in base_auth_code), "base_auth_code should be hex"
        
        server_auth_codes = auth_codes['server_auth_codes']
        assert len(server_auth_codes) >= 2, f"Should have at least 2 server auth codes, got {len(server_auth_codes)}"
        
        for server_url, server_code in server_auth_codes.items():
            assert len(server_code) == 64, f"server auth code should be 64 chars, got {len(server_code)}"
            assert all(c in '0123456789abcdef' for c in server_code), "server auth code should be hex"
        
        print(f"✅ Servers: {len(metadata['servers'])}")
        print(f"✅ Threshold: {metadata['threshold']}")
        print(f"✅ Version: {metadata['version']}")
        print(f"✅ Base auth code: {base_auth_code}")
        print(f"✅ Server auth codes: {len(server_auth_codes)}")
        print("✅ Metadata validation successful")
    
    def test_05_file_decryption(self):
        """Test file decryption using the actual decrypt.py tool."""
        print("\n🔓 Testing File Decryption with Real Tool")
        print("=" * 40)
        
        assert TestEncryptDecryptE2E.encrypted_file_path is not None, "Encrypted file should exist from previous test"
        assert os.path.exists(TestEncryptDecryptE2E.encrypted_file_path), "Encrypted file should exist on disk"
        
        decrypt_tool = os.path.join(self.tools_dir, 'decrypt.py')
        password = "integration_test_password_123"
        
        print(f"📁 Encrypted file: {TestEncryptDecryptE2E.encrypted_file_path}")
        print(f"🔑 Password: {password}")
        print(f"🛠️  Tool: {decrypt_tool}")
        
        # Run decrypt.py tool
        print("🔓 Running decrypt.py tool...")
        result = subprocess.run([
            sys.executable, decrypt_tool,
            TestEncryptDecryptE2E.encrypted_file_path,
            '--password', password
        ], capture_output=True, text=True, cwd=self.tools_dir)
        
        print(f"📥 Decrypt tool output:")
        print(result.stdout)
        if result.stderr:
            print(f"📥 Decrypt tool stderr:")
            print(result.stderr)
        
        assert result.returncode == 0, f"decrypt.py failed with exit code {result.returncode}: {result.stderr}"
        
        # Check that decrypted file was created
        decrypted_file_path = self.test_file_path  # Should restore original filename
        assert os.path.exists(decrypted_file_path), f"Decrypted file not created: {decrypted_file_path}"
        
        # Verify decrypted content matches original
        with open(decrypted_file_path, 'r') as f:
            decrypted_content = f.read()
        
        assert decrypted_content == self.test_file_content, "Decrypted content doesn't match original"
        
        # Verify success message in output
        assert "✅ File decrypted successfully!" in result.stdout, "Success message not found in output"
        assert "Authentication: Enabled (Authentication Codes)" in result.stdout, "Auth codes not mentioned"
        assert "Reading authentication codes from metadata" in result.stdout, "Metadata reading not mentioned"
        
        print(f"✅ Decrypted file: {decrypted_file_path}")
        print(f"✅ Decrypted size: {len(decrypted_content)} bytes")
        print("✅ Content verification: MATCH")
        print("✅ File decryption successful")
    
    def test_06_end_to_end_verification(self):
        """Final verification that the complete tools workflow works."""
        print("\n🎯 Final End-to-End Tools Verification")
        print("=" * 40)
        
        # Verify all components worked together
        assert self.test_file_path is not None, "Test file should be available"
        assert TestEncryptDecryptE2E.encrypted_file_path is not None, "Encryption should have succeeded"
        assert os.path.exists(self.test_file_path), "Decrypted file should exist"
        assert os.path.exists(TestEncryptDecryptE2E.encrypted_file_path), "Encrypted file should exist"
        
        # Verify file sizes make sense
        original_size = len(self.test_file_content)
        
        with open(TestEncryptDecryptE2E.encrypted_file_path, 'rb') as f:
            encrypted_size = len(f.read())
        
        with open(self.test_file_path, 'r') as f:
            final_size = len(f.read())
        
        assert encrypted_size > original_size, "Encrypted file should be larger than original"
        assert final_size == original_size, "Final decrypted file should match original size"
        
        print("✅ Tools Integration: WORKING")
        print("✅ Server Communication: WORKING") 
        print("✅ Secret Sharing: WORKING")
        print("✅ Encryption Tool: WORKING")
        print("✅ Decryption Tool: WORKING")
        print("✅ Content Integrity: VERIFIED")
        print("✅ Authentication Codes: WORKING")
        print("✅ Metadata Storage: WORKING")
        
        print(f"\n📊 File Size Summary:")
        print(f"   Original:  {original_size} bytes")
        print(f"   Encrypted: {encrypted_size} bytes")
        print(f"   Decrypted: {final_size} bytes")
        
        print("\n🎉 COMPLETE TOOLS INTEGRATION: SUCCESS!")
        print("🚀 OpenADP encrypt/decrypt tools are fully operational!")


if __name__ == "__main__":
    # Run the integration test
    pytest.main([__file__, "-v", "-s"]) 