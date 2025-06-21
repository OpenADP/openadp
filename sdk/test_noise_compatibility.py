#!/usr/bin/env python3
"""
Test Noise-NK compatibility between Python and Go implementations.

This test creates a simple Noise-NK handshake test to identify exactly
where the compatibility issue lies.
"""

import sys
import os
import subprocess
import time
import tempfile
import base64
import json

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from openadp import NoiseNK, OpenADPClient

def test_noise_nk_compatibility():
    """Test Noise-NK compatibility with Go server."""
    
    print("🔬 Testing Noise-NK Compatibility")
    print("=================================")
    
    # Start a single Go server
    server_binary = os.path.join(os.path.dirname(__file__), '..', 'build', 'openadp-server')
    if not os.path.exists(server_binary):
        print(f"❌ Server binary not found at {server_binary}")
        return False
    
    port = 19500
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
        temp_db_path = temp_db.name
    
    try:
        # Start Go server
        print(f"🖥️  Starting Go server on port {port}...")
        server_process = subprocess.Popen([
            server_binary,
            '-port', str(port),
            '-db', temp_db_path
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        time.sleep(2)  # Let server start
        
        # Test basic connectivity
        client = OpenADPClient(f"http://localhost:{port}")
        try:
            client.ping()
            print("✅ Basic connectivity works")
        except Exception as e:
            print(f"❌ Basic connectivity failed: {e}")
            return False
        
        # Get server's public key
        try:
            server_info = client.get_server_info()
            if 'noise_nk_public_key' not in server_info:
                print("❌ Server doesn't provide Noise-NK public key")
                return False
            
            server_public_key_b64 = server_info['noise_nk_public_key']
            server_public_key = base64.b64decode(server_public_key_b64)
            print(f"✅ Got server public key: {server_public_key_b64[:16]}...")
            
        except Exception as e:
            print(f"❌ Failed to get server info: {e}")
            return False
        
        # Test manual Noise-NK handshake
        try:
            print("🔐 Testing manual Noise-NK handshake...")
            
            # Create Noise-NK client
            noise_client = NoiseNK()
            noise_client.initialize_as_initiator(server_public_key)
            
            # Step 1: Client writes handshake message
            client_message = noise_client.write_message(b"Hello Server")
            print(f"✅ Client handshake message created: {len(client_message)} bytes")
            
            # Step 2: Send handshake to server via JSON-RPC
            handshake_request = {
                "jsonrpc": "2.0",
                "method": "noise_handshake",
                "params": [{
                    "session": "test_session_123",
                    "message": base64.b64encode(client_message).decode('ascii')
                }],
                "id": 1
            }
            
            import requests
            response = requests.post(
                f"http://localhost:{port}",
                headers={'Content-Type': 'application/json'},
                data=json.dumps(handshake_request),
                timeout=10
            )
            
            if response.status_code != 200:
                print(f"❌ Handshake HTTP error: {response.status_code}")
                return False
            
            handshake_response = response.json()
            if 'error' in handshake_response:
                error = handshake_response['error']
                print(f"❌ Handshake JSON-RPC error: {error['code']} - {error['message']}")
                return False
            
            # Step 3: Process server response
            server_message_b64 = handshake_response['result']['message']
            server_message = base64.b64decode(server_message_b64)
            print(f"✅ Server handshake response received: {len(server_message)} bytes")
            
            # Step 4: Client reads server response
            server_payload = noise_client.read_message(server_message)
            print(f"✅ Handshake complete! Server payload: {server_payload}")
            
            # Step 5: Test transport encryption
            test_message = b"Test transport message"
            encrypted = noise_client.encrypt(test_message)
            decrypted = noise_client.decrypt(encrypted)
            
            if decrypted == test_message:
                print("✅ Transport encryption/decryption works")
                return True
            else:
                print("❌ Transport encryption/decryption failed")
                return False
                
        except Exception as e:
            print(f"❌ Noise-NK handshake failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    finally:
        # Clean up
        try:
            server_process.terminate()
            server_process.wait(timeout=5)
        except:
            server_process.kill()
        
        try:
            os.unlink(temp_db_path)
        except:
            pass

if __name__ == "__main__":
    success = test_noise_nk_compatibility()
    sys.exit(0 if success else 1) 