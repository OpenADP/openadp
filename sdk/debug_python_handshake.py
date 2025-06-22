#!/usr/bin/env python3
"""
Debug script to test Python NoiseNK handshake processing
"""

import sys
import os
import json

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from openadp.client import NoiseNK, generate_keypair

def debug_python_handshake():
    print("🔍 Debug: Python Noise-NK Handshake Processing")
    print("=" * 60)
    
    try:
        # Load server info
        with open('python/server_info.json', 'r') as f:
            server_info = json.load(f)
        
        server_public_key_hex = server_info['public_key']
        server_public_key = bytes.fromhex(server_public_key_hex)
        
        print(f"📋 Server public key: {server_public_key_hex}")
        print(f"📋 Server public key length: {len(server_public_key)} bytes")
        
        # Generate server private key (we need this to act as responder)
        # For testing, let's generate a new keypair and see what happens
        server_private, server_public_test = generate_keypair()
        
        print(f"📋 Test server public: {server_public_test.hex()}")
        
        # Initialize Python NoiseNK as responder using the actual server key from file
        # We need to extract the private key somehow...
        # Actually, let's create a test message from JavaScript and see if we can process it
        
        # Test message from JavaScript (from debug output)
        js_message_hex = "5c974aef525289087bcac1d97893f2a50aea609d2ebda2ae74e176344a9b122210fe30e112dd85f0fc7173b26bcb26b3458f73ca456e93e2ba55765377153efd048907f4aa4151bbb6928af564"
        js_message = bytes.fromhex(js_message_hex)
        
        print(f"\n📤 JavaScript message length: {len(js_message)} bytes")
        print(f"📤 JavaScript message hex: {js_message.hex()}")
        
        # Try to process with a test server key
        noise_responder = NoiseNK()
        noise_responder.initialize_as_responder(server_private)
        
        print(f"\n🔧 Attempting to process JavaScript message...")
        
        try:
            payload = noise_responder.read_message(js_message)
            print(f"✅ Successfully processed message!")
            print(f"📝 Payload: {payload}")
        except Exception as e:
            print(f"❌ Failed to process message: {e}")
            import traceback
            traceback.print_exc()
            
        # Let's also test creating a message from Python side
        print(f"\n🔧 Creating Python initiator message for comparison...")
        
        noise_initiator = NoiseNK()
        noise_initiator.initialize_as_initiator(server_public_test)
        
        python_payload = b"Hello from Python client!"
        python_message = noise_initiator.write_message(python_payload)
        
        print(f"📤 Python message length: {len(python_message)} bytes")
        print(f"📤 Python message hex: {python_message.hex()}")
        
        # Try to process Python message with responder
        try:
            received_payload = noise_responder.read_message(python_message)
            print(f"✅ Python to Python works!")
            print(f"📝 Received payload: {received_payload}")
        except Exception as e:
            print(f"❌ Python to Python failed: {e}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_python_handshake() 