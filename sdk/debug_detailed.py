#!/usr/bin/env python3
"""
Detailed debug to compare JavaScript and Python Noise-NK implementations
"""

import sys
import os
import json
import subprocess

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from openadp.client import NoiseNK, generate_keypair

def debug_detailed_comparison():
    print("🔍 Detailed JavaScript vs Python Noise-NK Comparison")
    print("=" * 60)
    
    # Use fixed keys for reproducible debugging
    server_private = bytes.fromhex("90906e7d4cd603952e3a0218d3accbb8cad70e12899c241d527bc6d79c8e2551")
    server_public = bytes.fromhex("b4ee9c9600c55250bfc31c3fe9ef9c4d478d7fa75d85642d82ea68a2f254123f")
    
    print(f"📋 Fixed server private: {server_private.hex()}")
    print(f"📋 Fixed server public: {server_public.hex()}")
    
    # Test 1: Python implementation details
    print("\n🐍 Python Implementation Analysis")
    print("-" * 40)
    
    python_initiator = NoiseNK()
    python_initiator.initialize_as_initiator(server_public)
    
    # Check initial state
    print(f"Initial handshake complete: {python_initiator.handshake_complete}")
    
    # Create message
    payload = b"Hello from Python!"
    message = python_initiator.write_message(payload)
    
    print(f"Message length: {len(message)} bytes")
    print(f"Message hex: {message.hex()}")
    print(f"Payload length: {len(payload)} bytes")
    print(f"Payload: {payload}")
    
    # Break down message
    ephemeral_key = message[:32]
    ciphertext = message[32:]
    
    print(f"Ephemeral key (32 bytes): {ephemeral_key.hex()}")
    print(f"Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")
    
    # Test 2: JavaScript implementation details
    print("\n🟨 JavaScript Implementation Analysis")
    print("-" * 40)
    
    js_debug_script = f"""
import {{ NoiseNK }} from './javascript/src/noise-nk.js';

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

// Use same keys as Python
const serverPrivate = hexToBytes('{server_private.hex()}');
const serverPublic = hexToBytes('{server_public.hex()}');

console.log('📋 Fixed server private:', '{server_private.hex()}');
console.log('📋 Fixed server public:', '{server_public.hex()}');

// Create JavaScript initiator
const jsInitiator = new NoiseNK();
jsInitiator.initializeInitiator(serverPublic);

console.log('Initial handshake complete:', jsInitiator.handshakeComplete);

// Create message with same payload
const payload = new TextEncoder().encode('Hello from Python!');
const message = jsInitiator.writeMessage(payload);

console.log('Message length:', message.length, 'bytes');
console.log('Message hex:', bytesToHex(message));
console.log('Payload length:', payload.length, 'bytes');
console.log('Payload:', new TextDecoder().decode(payload));

// Break down message
const ephemeralKey = message.slice(0, 32);
const ciphertext = message.slice(32);

console.log('Ephemeral key (32 bytes):', bytesToHex(ephemeralKey));
console.log('Ciphertext (' + ciphertext.length + ' bytes):', bytesToHex(ciphertext));

// Show internal state
console.log('\\n🔍 Internal State:');
console.log('Chaining key:', bytesToHex(jsInitiator.ck));
console.log('Hash:', bytesToHex(jsInitiator.h));
console.log('Symmetric key:', jsInitiator.k ? bytesToHex(jsInitiator.k) : 'null');
console.log('Nonce counter:', jsInitiator.n);

// Save for comparison
const debugData = {{
    message_hex: bytesToHex(message),
    ephemeral_key: bytesToHex(ephemeralKey),
    ciphertext_hex: bytesToHex(ciphertext),
    chaining_key: bytesToHex(jsInitiator.ck),
    hash: bytesToHex(jsInitiator.h),
    symmetric_key: jsInitiator.k ? bytesToHex(jsInitiator.k) : null,
    nonce_counter: jsInitiator.n
}};

import fs from 'fs';
fs.writeFileSync('js_debug.json', JSON.stringify(debugData, null, 2));
"""
    
    # Write and run JavaScript debug
    with open('js_debug.js', 'w') as f:
        f.write(js_debug_script)
    
    result = subprocess.run(['node', 'js_debug.js'], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ JavaScript debug failed:")
        print(result.stdout)
        print(result.stderr)
        return
    
    print(result.stdout.strip())
    
    # Load JavaScript debug data
    with open('js_debug.json', 'r') as f:
        js_debug = json.load(f)
    
    # Compare implementations
    print("\n🔍 Comparison Analysis")
    print("-" * 40)
    
    print(f"Message length - Python: {len(message)}, JavaScript: {len(bytes.fromhex(js_debug['message_hex']))}")
    print(f"Ciphertext length - Python: {len(ciphertext)}, JavaScript: {len(bytes.fromhex(js_debug['ciphertext_hex']))}")
    
    # Check if ephemeral keys match (they shouldn't, but structure should)
    js_ephemeral = bytes.fromhex(js_debug['ephemeral_key'])
    print(f"Ephemeral key length - Python: {len(ephemeral_key)}, JavaScript: {len(js_ephemeral)}")
    
    # Try to process JavaScript message with Python
    print("\n🔧 Testing JavaScript message with Python responder...")
    
    try:
        python_responder = NoiseNK()
        python_responder.initialize_as_responder(server_private)
        
        js_message = bytes.fromhex(js_debug['message_hex'])
        received_payload = python_responder.read_message(js_message)
        print(f"✅ Success! Received: {received_payload}")
        
    except Exception as e:
        print(f"❌ Failed: {e}")
        print("This confirms the incompatibility issue")
        
        # Let's try to understand why
        print("\n🔍 Analyzing the difference...")
        
        # Compare ciphertext lengths
        python_ciphertext_len = len(ciphertext)
        js_ciphertext_len = len(bytes.fromhex(js_debug['ciphertext_hex']))
        
        print(f"Python ciphertext: {python_ciphertext_len} bytes")
        print(f"JavaScript ciphertext: {js_ciphertext_len} bytes")
        print(f"Difference: {js_ciphertext_len - python_ciphertext_len} bytes")
        
        if js_ciphertext_len - python_ciphertext_len == 4:
            print("💡 4-byte difference suggests AES-GCM tag handling issue")
            print("   JavaScript might be including extra tag bytes")
    
    # Clean up
    for file in ['js_debug.js', 'js_debug.json']:
        if os.path.exists(file):
            os.remove(file)

if __name__ == "__main__":
    debug_detailed_comparison() 