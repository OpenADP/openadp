#!/usr/bin/env python3
"""
Debug script to understand what Python Noise-NK expects
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'openadp'))

from openadp.client import NoiseNK, generate_keypair

def debug_noise_nk():
    print("🔍 Debugging Noise-NK expectations...")
    
    # Generate server static key pair
    server_private, server_public = generate_keypair()
    print(f"📋 Server static public key: {server_public.hex()}")
    
    # Create client (initiator) and server (responder)
    client = NoiseNK()
    server = NoiseNK()
    
    print("\n=== STEP 1: Initialize as initiator and responder ===")
    client.initialize_as_initiator(server_public)
    server.initialize_as_responder(server_private)
    
    print("✅ Both initialized")
    
    try:
        # Get handshake hash before any messages
        print(f"🔑 Client hash before messages: {client.get_handshake_hash().hex()}")
        print(f"🔑 Server hash before messages: {server.get_handshake_hash().hex()}")
    except Exception as e:
        print(f"⚠️ Could not get initial hashes: {e}")
    
    print("\n=== STEP 2: Client writes first message ===")
    try:
        # Client writes first handshake message with empty payload
        message1 = client.write_message(b'')
        print(f"📤 Client message 1 length: {len(message1)} bytes")
        print(f"📤 Client message 1 hex: {message1.hex()}")
        
        # Get handshake hash after writing
        try:
            client_hash1 = client.get_handshake_hash()
            print(f"🔑 Client hash after writing message 1: {client_hash1.hex()}")
        except Exception as e:
            print(f"⚠️ Could not get client hash after writing: {e}")
            
    except Exception as e:
        print(f"❌ Client failed to write message 1: {e}")
        import traceback
        traceback.print_exc()
        return
    
    print("\n=== STEP 3: Server reads first message ===")
    try:
        # Server reads first handshake message
        print(f"📨 Server receiving: {len(message1)} bytes")
        print(f"📨 Server receiving hex: {message1.hex()}")
        
        # Get server hash before reading
        try:
            server_hash_before = server.get_handshake_hash()
            print(f"🔑 Server hash BEFORE reading message 1: {server_hash_before.hex()}")
        except Exception as e:
            print(f"⚠️ Could not get server hash before reading: {e}")
        
        payload1 = server.read_message(message1)
        print(f"📝 Server received payload: {payload1}")
        print(f"📝 Server received payload length: {len(payload1)} bytes")
        
        # Get server hash after reading
        try:
            server_hash1 = server.get_handshake_hash()
            print(f"🔑 Server hash AFTER reading message 1: {server_hash1.hex()}")
        except Exception as e:
            print(f"⚠️ Could not get server hash after reading: {e}")
            
    except Exception as e:
        print(f"❌ Server failed to read message 1: {e}")
        import traceback
        traceback.print_exc()
        return
    
    print("\n=== STEP 4: Compare hashes ===")
    try:
        client_final = client.get_handshake_hash()
        server_final = server.get_handshake_hash()
        print(f"🔑 Client final hash: {client_final.hex()}")
        print(f"🔑 Server final hash: {server_final.hex()}")
        
        if client_final == server_final:
            print("✅ Hashes match! Both sides processed message 1 the same way")
        else:
            print("❌ Hashes differ! There's a mismatch in processing")
            
    except Exception as e:
        print(f"⚠️ Could not compare final hashes: {e}")
    
    print("\n=== STEP 5: Try to continue handshake ===")
    try:
        # Server writes second message
        message2 = server.write_message(b'')
        print(f"📤 Server message 2 length: {len(message2)} bytes")
        print(f"📤 Server message 2 hex: {message2.hex()}")
        
        # Client reads second message
        payload2 = client.read_message(message2)
        print(f"📝 Client received payload 2: {payload2}")
        
        print(f"✅ Client handshake complete: {client.handshake_complete}")
        print(f"✅ Server handshake complete: {server.handshake_complete}")
        
        if client.handshake_complete and server.handshake_complete:
            print("🎉 Full handshake successful!")
            
            # Compare final handshake hashes
            client_final = client.get_handshake_hash()
            server_final = server.get_handshake_hash()
            print(f"🔑 Final client hash: {client_final.hex()}")
            print(f"🔑 Final server hash: {server_final.hex()}")
            
            if client_final == server_final:
                print("✅ Final hashes match!")
            else:
                print("❌ Final hashes differ!")
        
    except Exception as e:
        print(f"❌ Failed to complete handshake: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_noise_nk() 