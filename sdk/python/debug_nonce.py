#!/usr/bin/env python3
"""
Debug nonce format used by Python noiseprotocol library
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'openadp'))

from openadp.client import NoiseNK, generate_keypair

def debug_nonce_format():
    print("🔍 Debugging Python nonce format...")
    
    # Create a simple test
    server_private, server_public = generate_keypair()
    
    client = NoiseNK()
    client.initialize_as_initiator(server_public)
    
    print("Before writing message:")
    print(f"Client nonce counter: {getattr(client.noise.noise_protocol.handshake_state.symmetric_state.cipher_state, 'n', 'N/A')}")
    
    # Write first message - this will encrypt empty payload
    message1 = client.write_message(b'')
    
    print(f"Message 1 length: {len(message1)}")
    print(f"Message 1 hex: {message1.hex()}")
    
    # Try to extract nonce information from the underlying library
    try:
        cipher_state = client.noise.noise_protocol.handshake_state.symmetric_state.cipher_state
        print(f"Cipher state type: {type(cipher_state)}")
        print(f"Cipher state attributes: {[attr for attr in dir(cipher_state) if not attr.startswith('_')]}")
        
        if hasattr(cipher_state, 'n'):
            print(f"Nonce counter after encryption: {cipher_state.n}")
        
        if hasattr(cipher_state, 'cipher'):
            cipher = cipher_state.cipher
            print(f"Cipher type: {type(cipher)}")
            print(f"Cipher attributes: {[attr for attr in dir(cipher) if not attr.startswith('_')]}")
            
            # Check if we can see the nonce formatting function
            if hasattr(cipher, 'format_nonce'):
                print("Found format_nonce method!")
                # Test nonce formatting for n=0
                test_nonce = cipher.format_nonce(0)
                print(f"Formatted nonce for n=0: {test_nonce.hex()}")
                print(f"Nonce length: {len(test_nonce)}")
            
    except Exception as e:
        print(f"Could not extract nonce details: {e}")
    
    print("\n=== Expected JavaScript nonce for n=0 ===")
    js_nonce = b'\x00' * 12  # 12 zero bytes
    print(f"JavaScript nonce: {js_nonce.hex()}")
    print(f"JavaScript nonce length: {len(js_nonce)}")

if __name__ == "__main__":
    debug_nonce_format() 