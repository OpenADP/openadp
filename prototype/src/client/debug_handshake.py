#!/usr/bin/env python3
"""
Debug script for testing Noise-NK handshake
"""

import base64
import json
import requests
import secrets
import sys
import os

# Add path to access noise_nk module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'openadp'))

from noise_nk import NoiseNK

def debug_handshake():
    # Server key we're testing with
    server_key_hex = "ddd5308d24177f7e9c5a51d878eeecb84ee3168e5dfe45ca44bfa4bf27be0c59"
    server_public_key = bytes.fromhex(server_key_hex)
    
    print(f"Using server key: {server_key_hex}")
    
    # Generate session ID
    session_id = base64.b64encode(secrets.token_bytes(16)).decode('ascii')
    print(f"Session ID: {session_id}")
    
    # Create client
    temp_client = NoiseNK(role='responder')  # Just to get the dh object
    dh = temp_client.dh
    server_public_key_obj = dh.create_public(server_public_key)
    
    noise_client = NoiseNK(
        role='initiator',
        remote_static_key=server_public_key_obj
    )
    
    # Create handshake message
    client_handshake = noise_client.write_handshake_message(b"Client handshake")
    print(f"Client handshake message: {len(client_handshake)} bytes")
    print(f"Handshake hex: {client_handshake.hex()}")
    
    # Send to server
    handshake_payload = {
        "jsonrpc": "2.0",
        "method": "noise_handshake",
        "params": [session_id, base64.b64encode(client_handshake).decode('ascii')],
        "id": 1
    }
    
    print("\nSending handshake to server...")
    response = requests.post(
        "http://localhost:8080",
        headers={"Content-Type": "application/json"},
        data=json.dumps(handshake_payload),
        timeout=30
    )
    
    print(f"Response status: {response.status_code}")
    result = response.json()
    print(f"Response: {json.dumps(result, indent=2)}")
    
    if "error" in result:
        print(f"❌ Handshake failed: {result['error']}")
        return False
    
    # Process server response
    server_handshake_b64 = result["result"]["message"]
    server_handshake = base64.b64decode(server_handshake_b64)
    print(f"Server handshake: {len(server_handshake)} bytes")
    
    try:
        server_payload = noise_client.read_handshake_message(server_handshake)
        print(f"Server payload: {server_payload}")
        print(f"Handshake complete: {noise_client.is_handshake_complete()}")
        print("✅ Handshake succeeded!")
        return True
    except Exception as e:
        print(f"❌ Client handshake processing failed: {e}")
        return False

if __name__ == "__main__":
    debug_handshake() 