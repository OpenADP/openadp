#!/usr/bin/env python3
"""
Cross-platform compatibility test using the same keys
"""

import sys
import os
import json
import subprocess

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from openadp.client import NoiseNK, generate_keypair

def test_cross_platform_compatibility():
    print("🔍 Cross-Platform Noise-NK Compatibility Test")
    print("=" * 60)
    
    # Generate a test keypair that both implementations will use
    server_private, server_public = generate_keypair()
    
    print(f"📋 Test server private key: {server_private.hex()}")
    print(f"📋 Test server public key: {server_public.hex()}")
    
    # Save keys for JavaScript to use
    test_keys = {
        "server_private": server_private.hex(),
        "server_public": server_public.hex()
    }
    
    with open('test_keys.json', 'w') as f:
        json.dump(test_keys, f, indent=2)
    
    print("💾 Test keys saved to test_keys.json")
    
    # Test 1: Python initiator -> Python responder
    print("\n🧪 Test 1: Python initiator -> Python responder")
    test_python_to_python(server_private, server_public)
    
    # Test 2: JavaScript initiator -> Python responder
    print("\n🧪 Test 2: JavaScript initiator -> Python responder")
    test_javascript_to_python(server_private, server_public)

def test_python_to_python(server_private, server_public):
    """Test Python to Python communication"""
    try:
        # Create initiator
        initiator = NoiseNK()
        initiator.initialize_as_initiator(server_public)
        
        # Create responder
        responder = NoiseNK()
        responder.initialize_as_responder(server_private)
        
        # Handshake message 1: initiator -> responder
        payload1 = b"Hello from Python initiator!"
        message1 = initiator.write_message(payload1)
        
        print(f"📤 Python message 1 length: {len(message1)} bytes")
        print(f"📤 Python message 1 hex: {message1.hex()}")
        
        # Process message 1
        received_payload1 = responder.read_message(message1)
        print(f"📨 Received payload 1: {received_payload1}")
        
        # Handshake message 2: responder -> initiator
        payload2 = b"Hello from Python responder!"
        message2 = responder.write_message(payload2)
        
        print(f"📤 Python message 2 length: {len(message2)} bytes")
        print(f"📤 Python message 2 hex: {message2.hex()}")
        
        # Process message 2
        received_payload2 = initiator.read_message(message2)
        print(f"📨 Received payload 2: {received_payload2}")
        
        if initiator.handshake_complete and responder.handshake_complete:
            print("✅ Python to Python handshake successful!")
            
            # Test transport encryption
            plaintext = b"Test transport message"
            encrypted = initiator.encrypt(plaintext)
            decrypted = responder.decrypt(encrypted)
            
            if decrypted == plaintext:
                print("✅ Python to Python transport encryption successful!")
            else:
                print("❌ Python to Python transport encryption failed!")
        else:
            print("❌ Python to Python handshake failed!")
            
    except Exception as e:
        print(f"❌ Python to Python test failed: {e}")
        import traceback
        traceback.print_exc()

def test_javascript_to_python(server_private, server_public):
    """Test JavaScript to Python communication"""
    try:
        # Create JavaScript test script
        js_test_script = f"""
import {{ NoiseNK }} from './javascript/src/noise-nk.js';
import fs from 'fs';

function hexToBytes(hex) {{
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {{
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }}
    return bytes;
}}

function bytesToHex(bytes) {{
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}}

try {{
    // Load test keys
    const testKeys = JSON.parse(fs.readFileSync('test_keys.json', 'utf8'));
    const serverPublic = hexToBytes(testKeys.server_public);
    
    console.log('📋 Using server public key:', testKeys.server_public);
    
    // Create JavaScript initiator
    const initiator = new NoiseNK();
    initiator.initializeInitiator(serverPublic);
    
    // Create handshake message
    const payload = new TextEncoder().encode('Hello from JavaScript initiator!');
    const message = initiator.writeMessage(payload);
    
    console.log('📤 JavaScript message length:', message.length);
    console.log('📤 JavaScript message hex:', bytesToHex(message));
    
    // Save message for Python to process
    const messageData = {{
        message_hex: bytesToHex(message),
        payload_text: 'Hello from JavaScript initiator!'
    }};
    
    fs.writeFileSync('js_message.json', JSON.stringify(messageData, null, 2));
    console.log('💾 JavaScript message saved to js_message.json');
    
}} catch (error) {{
    console.error('❌ JavaScript test failed:', error.message);
    process.exit(1);
}}
"""
        
        # Write and run JavaScript test
        with open('js_test.js', 'w') as f:
            f.write(js_test_script)
        
        print("🔧 Running JavaScript test...")
        result = subprocess.run(['node', 'js_test.js'], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ JavaScript test failed:")
            print(result.stdout)
            print(result.stderr)
            return
        
        print(result.stdout.strip())
        
        # Load JavaScript message
        with open('js_message.json', 'r') as f:
            js_data = json.load(f)
        
        js_message = bytes.fromhex(js_data['message_hex'])
        
        # Process with Python responder
        print("\n🔧 Processing JavaScript message with Python responder...")
        
        responder = NoiseNK()
        responder.initialize_as_responder(server_private)
        
        received_payload = responder.read_message(js_message)
        print(f"📨 Python received payload: {received_payload}")
        
        expected_payload = js_data['payload_text'].encode('utf-8')
        if received_payload == expected_payload:
            print("✅ JavaScript to Python message processing successful!")
        else:
            print(f"❌ Payload mismatch!")
            print(f"   Expected: {expected_payload}")
            print(f"   Received: {received_payload}")
            
    except Exception as e:
        print(f"❌ JavaScript to Python test failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Clean up
        for file in ['js_test.js', 'js_message.json', 'test_keys.json']:
            if os.path.exists(file):
                os.remove(file)

if __name__ == "__main__":
    test_cross_platform_compatibility() 