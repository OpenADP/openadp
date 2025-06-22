#!/usr/bin/env python3
"""
Debug script to compare JavaScript vs Python Noise-NK step by step
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'openadp'))

from openadp.client import NoiseNK, generate_keypair
import json

def debug_js_vs_python():
    print("🔍 Debugging JavaScript vs Python Noise-NK differences...")
    
    # Load the same server info that JavaScript client uses
    try:
        with open('server_info.json', 'r') as f:
            server_info = json.load(f)
            server_pubkey_hex = server_info['public_key']
            server_pubkey = bytes.fromhex(server_pubkey_hex)
    except:
        print("❌ Could not load server_info.json, generating new keys")
        server_private, server_pubkey = generate_keypair()
        server_pubkey_hex = server_pubkey.hex()
    
    print(f"📋 Using server public key: {server_pubkey_hex}")
    
    print("\n=== STEP 1: Initialize Python client as initiator ===")
    python_client = NoiseNK()
    python_client.initialize_as_initiator(server_pubkey)
    
    print("✅ Python client initialized")
    
    print("\n=== STEP 2: Python client writes first message ===")
    try:
        python_message1 = python_client.write_message(b'')
        print(f"📤 Python message 1 length: {len(python_message1)} bytes")
        print(f"📤 Python message 1 hex: {python_message1.hex()}")
        
        try:
            python_hash1 = python_client.get_handshake_hash()
            print(f"🔑 Python hash after message 1: {python_hash1.hex()}")
        except Exception as e:
            print(f"⚠️ Could not get Python hash: {e}")
            
    except Exception as e:
        print(f"❌ Python client failed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    print("\n=== STEP 3: Manual analysis of message structure ===")
    if len(python_message1) == 48:
        ephemeral_key = python_message1[:32]
        encrypted_payload = python_message1[32:]
        print(f"📋 Ephemeral key (32 bytes): {ephemeral_key.hex()}")
        print(f"📋 Encrypted payload (16 bytes): {encrypted_payload.hex()}")
    else:
        print(f"⚠️ Unexpected message length: {len(python_message1)}")
    
    print("\n=== STEP 4: Comparison with known JavaScript values ===")
    print("JavaScript from previous run:")
    print("📤 JS message 1: cdfa2bab5af1af617ca8567b57fd38e63727942f17e8972745389b6f3b2b970a8fe8fa788764b3931d1209310edc9ec3")
    print("🔑 JS hash: 141c33248fabd0e5899e61deb026b28cc6e8360b71a7199be6d45ce01ab4ab89")
    print("Python this run:")
    print(f"📤 PY message 1: {python_message1.hex()}")
    try:
        python_hash1 = python_client.get_handshake_hash()
        print(f"🔑 PY hash: {python_hash1.hex()}")
    except:
        print("🔑 PY hash: unavailable")
    
    # Check if the ephemeral keys match (they shouldn't - they should be random)
    js_ephemeral = "cdfa2bab5af1af617ca8567b57fd38e63727942f17e8972745389b6f3b2b970a"
    py_ephemeral = ephemeral_key.hex() if len(python_message1) == 48 else "unknown"
    print(f"\n📋 JS ephemeral:  {js_ephemeral}")
    print(f"📋 PY ephemeral:  {py_ephemeral}")
    print(f"🔍 Keys match: {js_ephemeral == py_ephemeral} (should be False - different random keys)")
    
    print("\n=== STEP 5: Test with Python server using Python message ===")
    try:
        # Test if a Python server can read a Python client message
        print("Creating Python server...")
        server_private, server_public = generate_keypair()
        python_server = NoiseNK()
        python_server.initialize_as_responder(server_private)
        
        print("Creating Python client with server's key...")
        test_client = NoiseNK()
        test_client.initialize_as_initiator(server_public)
        
        # Client writes message
        test_message = test_client.write_message(b'')
        print(f"📤 Test client message (48 bytes): {test_message.hex()}")
        
        # Server reads message
        test_payload = python_server.read_message(test_message)
        print(f"📝 Test server received payload: {test_payload}")
        print("✅ Python-to-Python communication works!")
        
        try:
            client_hash = test_client.get_handshake_hash()
            server_hash = python_server.get_handshake_hash()
            print(f"🔑 Test client hash: {client_hash.hex()}")
            print(f"🔑 Test server hash: {server_hash.hex()}")
            print(f"🔍 Hashes match: {client_hash.hex() == server_hash.hex()}")
        except Exception as e:
            print(f"⚠️ Could not compare test hashes: {e}")
        
    except Exception as e:
        print(f"❌ Python-to-Python test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_js_vs_python() 