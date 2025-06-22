#!/usr/bin/env python3
"""
Step-by-step debugging to find where JS and Python diverge
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'openadp'))

from openadp.client import NoiseNK, generate_keypair
import json

def debug_step_by_step():
    print("🔍 Step-by-step debugging to find divergence point...")
    
    # Use a fixed server key for consistent comparison
    server_pubkey_hex = "13e91f89921507d6636f3e0d40020377ae0fb4650adebc02077ed52bbf7d7c41"
    server_pubkey = bytes.fromhex(server_pubkey_hex)
    
    print(f"📋 Fixed server public key: {server_pubkey_hex}")
    
    # STEP 1: Create JavaScript client with debug to see its handshake hash
    print("\n=== STEP 1: Run JavaScript client to get hash ===")
    print("Need to run: cd /home/waywardgeek/projects/openadp/sdk/javascript && node noise_client.js")
    print("Expected JS hash: 141c33248fabd0e5899e61deb026b28cc6e8360b71a7199be6d45ce01ab4ab89")
    print("Expected JS message: cdfa2bab5af1af617ca8567b57fd38e63727942f17e8972745389b6f3b2b970a8fe8fa788764b3931d1209310edc9ec3")
    
    # STEP 2: Try to recreate the same conditions in Python
    print("\n=== STEP 2: Python client computation ===")
    python_client = NoiseNK()
    python_client.initialize_as_initiator(server_pubkey)
    
    # Before writing message, let's check the initialization
    print("📋 Python client initialized with:")
    print(f"   - Responder static key: {server_pubkey.hex()}")
    
    # Write message
    python_message = python_client.write_message(b'')
    print(f"📤 Python message: {python_message.hex()}")
    
    # The key insight: let me check if we can decode the handshake hash through the underlying noise library
    try:
        if hasattr(python_client, 'noise') and python_client.noise:
            if hasattr(python_client.noise, 'noise_protocol'):
                handshake_state = python_client.noise.noise_protocol.handshake_state
                print(f"🔍 Found handshake state: {type(handshake_state)}")
                if hasattr(handshake_state, 'symmetric_state'):
                    sym_state = handshake_state.symmetric_state
                    print(f"🔍 Found symmetric state: {type(sym_state)}")
                    if hasattr(sym_state, 'h'):
                        handshake_hash = sym_state.h
                        print(f"🔑 Python handshake hash: {handshake_hash.hex()}")
                    else:
                        print("⚠️ No 'h' in symmetric state")
                else:
                    print("⚠️ No symmetric_state in handshake_state")
            else:
                print("⚠️ No noise_protocol in noise")
        else:
            print("⚠️ No noise in python_client")
    except Exception as e:
        print(f"⚠️ Could not extract handshake hash: {e}")
    
    print("\n=== STEP 3: Manually verify JavaScript client process ===")
    print("The JavaScript client should be creating a handshake hash like Python.")
    print("Key question: Are both using the same protocol string?")
    print("Expected protocol: 'Noise_NK_25519_AESGCM_SHA256'")
    
    # Test different potential sources of divergence
    print("\n=== STEP 4: Test potential divergence sources ===")
    print("1. Protocol name initialization")
    print("2. Ephemeral key generation and mixing")
    print("3. DH operation and key mixing")
    print("4. Payload encryption")
    
    # Hypothesis: The problem might be in how the AEAD authentication tag is created
    print("\n=== HYPOTHESIS ===")
    print("The JavaScript AES-GCM implementation might be using different:")
    print("- Nonce format (Python uses 12-byte nonce)")
    print("- Associated data (should be handshake hash)")
    print("- Key derivation (HKDF)")
    print("- Message authentication")

if __name__ == "__main__":
    debug_step_by_step() 