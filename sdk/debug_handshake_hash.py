#!/usr/bin/env python3
"""
Debug handshake hash comparison between JavaScript and Python
"""

import sys
import os
import json
import subprocess
import time

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from openadp.client import NoiseNK, generate_keypair

def debug_handshake_hash():
    print("🔍 Handshake Hash Comparison Debug")
    print("=" * 50)
    
    # Generate fixed keys for consistent testing
    server_private = bytes.fromhex("90906e7d4cd603952e3a0218d3accbb8cad70e12899c241d527bc6d79c8e2551")
    server_public = bytes.fromhex("b4ee9c9600c55250bfc31c3fe9ef9c4d478d7fa75d85642d82ea68a2f254123f")
    
    print(f"📋 Server private: {server_private.hex()}")
    print(f"📋 Server public: {server_public.hex()}")
    
    # Create enhanced JavaScript client that logs hash states
    js_hash_debug_script = f"""
import {{ NoiseNK }} from './src/noise-nk.js';

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

const serverPublic = hexToBytes('{server_public.hex()}');

console.log('🟨 JavaScript Client Hash Debug');
console.log('================================');

// Create initiator
const noise = new NoiseNK();
noise.initializeInitiator(serverPublic);

console.log('Step 1 - After initialization:');
console.log('  hash:', bytesToHex(noise.h));
console.log('  ck:', bytesToHex(noise.ck));

// Create handshake message
const payload = new TextEncoder().encode('Test payload');
const message = noise.writeMessage(payload);

console.log('\\nStep 2 - After writeMessage:');
console.log('  hash:', bytesToHex(noise.h));
console.log('  ck:', bytesToHex(noise.ck));
console.log('  k:', noise.k ? bytesToHex(noise.k) : 'null');
console.log('  message length:', message.length);
console.log('  message:', bytesToHex(message));

// Save hash states for comparison
const hashData = {{
    step1_hash: bytesToHex(noise.h),
    step1_ck: bytesToHex(noise.ck),
    step2_hash: bytesToHex(noise.h),
    step2_ck: bytesToHex(noise.ck),
    step2_k: noise.k ? bytesToHex(noise.k) : null,
    message: bytesToHex(message),
    payload: bytesToHex(payload)
}};

import fs from 'fs';
fs.writeFileSync('js_hash_debug.json', JSON.stringify(hashData, null, 2));
console.log('\\n💾 Hash debug data saved');
"""
    
    # Write and run JavaScript hash debug
    js_dir = os.path.join(os.path.dirname(__file__), 'javascript')
    with open(os.path.join(js_dir, 'js_hash_debug.js'), 'w') as f:
        f.write(js_hash_debug_script)
    
    print("\n🟨 Running JavaScript client hash debug...")
    result = subprocess.run(['node', 'js_hash_debug.js'], cwd=js_dir, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ JavaScript debug failed:")
        print(result.stdout)
        print(result.stderr)
        return
    
    print(result.stdout.strip())
    
    # Load JavaScript hash data
    with open(os.path.join(js_dir, 'js_hash_debug.json'), 'r') as f:
        js_hash_data = json.load(f)
    
    # Now create a Python responder and manually step through to compare hashes
    print(f"\n🐍 Python Server Hash Debug")
    print("=" * 30)
    
    # Create responder
    python_responder = NoiseNK()
    python_responder.initialize_as_responder(server_private)
    
    print("Step 1 - Python responder initialized")
    # We can't easily access internal hash state of Python noiseprotocol library
    # But we can try to process the JavaScript message and see where it fails
    
    js_message = bytes.fromhex(js_hash_data['message'])
    js_payload = bytes.fromhex(js_hash_data['payload'])
    
    print(f"Processing JavaScript message: {len(js_message)} bytes")
    print(f"Expected payload: {js_payload}")
    
    try:
        received_payload = python_responder.read_message(js_message)
        print(f"✅ Success! Received: {received_payload}")
        print(f"✅ Payloads match: {received_payload == js_payload}")
        
        if python_responder.handshake_complete:
            print("✅ Handshake completed successfully!")
        else:
            print("❌ Handshake not marked as complete")
            
    except Exception as e:
        print(f"❌ Failed to process JavaScript message: {e}")
        print("This indicates hash/state mismatch between implementations")
        
        # Let's try the reverse - Python initiator to JavaScript responder simulation
        print(f"\n🔄 Reverse test: Python initiator message")
        
        python_initiator = NoiseNK()
        python_initiator.initialize_as_initiator(server_public)
        
        python_payload = b"Test payload"
        python_message = python_initiator.write_message(python_payload)
        
        print(f"Python message: {python_message.hex()}")
        print(f"Python message length: {len(python_message)}")
        print(f"JavaScript message: {js_hash_data['message']}")
        print(f"JavaScript message length: {len(js_message)}")
        
        if len(python_message) != len(js_message):
            print(f"❌ Length mismatch: Python {len(python_message)} vs JavaScript {len(js_message)}")
        else:
            print(f"✅ Lengths match: {len(python_message)} bytes")
            
        # Compare message structure
        py_ephemeral = python_message[:32]
        py_ciphertext = python_message[32:]
        js_ephemeral = js_message[:32]
        js_ciphertext = js_message[32:]
        
        print(f"\nMessage structure comparison:")
        print(f"Python ephemeral:    {py_ephemeral.hex()}")
        print(f"JavaScript ephemeral: {js_ephemeral.hex()}")
        print(f"Python ciphertext:    {py_ciphertext.hex()}")
        print(f"JavaScript ciphertext: {js_ciphertext.hex()}")
        print(f"Ephemeral lengths: Python {len(py_ephemeral)}, JavaScript {len(js_ephemeral)}")
        print(f"Ciphertext lengths: Python {len(py_ciphertext)}, JavaScript {len(js_ciphertext)}")
    
    # Clean up
    hash_debug_file = os.path.join(js_dir, 'js_hash_debug.js')
    hash_data_file = os.path.join(js_dir, 'js_hash_debug.json')
    for file in [hash_debug_file, hash_data_file]:
        if os.path.exists(file):
            os.remove(file)

if __name__ == "__main__":
    debug_handshake_hash() 