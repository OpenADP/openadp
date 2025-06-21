#!/usr/bin/env python3
"""
Debug script to verify public key retrieval from Go servers

This script starts a Go server and checks that the Python client
can correctly retrieve and parse the server's public key.
"""

import sys
import os
import subprocess
import time
import tempfile
import base64

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from openadp import OpenADPClient, EncryptedOpenADPClient, ServerInfo


def start_go_server(port=19300):
    """Start a single Go server for testing"""
    server_binary = os.path.join(os.path.dirname(__file__), '..', 'build', 'openadp-server')
    if not os.path.exists(server_binary):
        raise Exception(f"Server binary not found at {server_binary}")
    
    # Create temporary database
    temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    temp_db.close()
    
    # Start server
    cmd = [server_binary, '-port', str(port), '-db', temp_db.name]
    
    print(f"Starting Go server on port {port}...")
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Give server time to start
    time.sleep(2)
    
    return process, temp_db.name


def test_public_key_retrieval():
    """Test public key retrieval and parsing"""
    process = None
    temp_db = None
    
    try:
        # Start Go server
        process, temp_db = start_go_server()
        server_url = "http://localhost:19300"
        
        # Test basic connectivity
        print("Testing basic connectivity...")
        client = OpenADPClient(server_url)
        
        try:
            result = client.ping()
            print(f"✅ Ping successful: {result}")
        except Exception as e:
            print(f"❌ Ping failed: {e}")
            return False
        
        # Get server info
        print("\nRetrieving server info...")
        try:
            info = client.get_server_info()
            print(f"✅ Server info retrieved: {info}")
            
            if "noise_nk_public_key" not in info:
                print("❌ No noise_nk_public_key in server info")
                return False
            
            raw_key = info["noise_nk_public_key"]
            print(f"✅ Raw public key: {raw_key}")
            print(f"   Key length: {len(raw_key)} characters")
            
            # Try to decode the key
            try:
                key_bytes = base64.b64decode(raw_key)
                print(f"✅ Decoded key: {len(key_bytes)} bytes")
                print(f"   Key hex: {key_bytes.hex()}")
                
                if len(key_bytes) != 32:
                    print(f"❌ Expected 32 bytes, got {len(key_bytes)}")
                    return False
                
            except Exception as e:
                print(f"❌ Failed to decode key: {e}")
                return False
            
        except Exception as e:
            print(f"❌ Failed to get server info: {e}")
            return False
        
        # Test creating encrypted client
        print("\nTesting encrypted client creation...")
        try:
            # Format key as expected by Python client
            formatted_key = f"ed25519:{raw_key}"
            print(f"✅ Formatted key: {formatted_key}")
            
            # Parse the key as the client would
            public_key_bytes = base64.b64decode(formatted_key.replace("ed25519:", ""))
            print(f"✅ Parsed key bytes: {len(public_key_bytes)} bytes")
            
            # Create encrypted client
            encrypted_client = EncryptedOpenADPClient(server_url, public_key_bytes)
            print(f"✅ Encrypted client created successfully")
            
            # Test if client recognizes it has a public key
            if encrypted_client.has_public_key():
                print("✅ Client recognizes it has a public key")
            else:
                print("❌ Client doesn't recognize public key")
                return False
            
        except Exception as e:
            print(f"❌ Failed to create encrypted client: {e}")
            return False
        
        # Test simple encrypted operation (this will likely fail due to handshake issues)
        print("\nTesting encrypted ping (may fail due to handshake issues)...")
        try:
            result = encrypted_client.ping()
            print(f"✅ Encrypted ping successful: {result}")
        except Exception as e:
            print(f"⚠️  Encrypted ping failed (expected): {e}")
            # This is expected to fail due to handshake issues
        
        print("\n🎉 Public key retrieval and parsing works correctly!")
        print("   The issue is likely in the Noise-NK handshake implementation, not key retrieval.")
        return True
        
    finally:
        # Cleanup
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
                print("\n✅ Server terminated gracefully")
            except:
                process.kill()
                process.wait()
                print("\n⚠️  Server killed forcefully")
        
        if temp_db:
            try:
                os.unlink(temp_db)
            except:
                pass


if __name__ == "__main__":
    success = test_public_key_retrieval()
    sys.exit(0 if success else 1) 