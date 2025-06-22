#!/usr/bin/env python3
"""
Step-by-step debug to compare Noise-NK operations
"""

import sys
import os
import json
import subprocess

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from openadp.client import NoiseNK, generate_keypair

def debug_step_by_step():
    print("🔍 Step-by-Step Noise-NK Operation Comparison")
    print("=" * 60)
    
    # Use fixed keys and ephemeral for reproducible debugging
    server_private = bytes.fromhex("90906e7d4cd603952e3a0218d3accbb8cad70e12899c241d527bc6d79c8e2551")
    server_public = bytes.fromhex("b4ee9c9600c55250bfc31c3fe9ef9c4d478d7fa75d85642d82ea68a2f254123f")
    
    # Fixed ephemeral key for deterministic testing
    ephemeral_private = bytes.fromhex("a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8")
    
    print(f"📋 Server public: {server_public.hex()}")
    print(f"📋 Ephemeral private: {ephemeral_private.hex()}")
    
    # Create JavaScript debug script with detailed step tracking
    js_debug_script = f"""
import {{ NoiseNK }} from './src/noise-nk.js';
import {{ x25519 }} from '@noble/curves/ed25519';

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

// Use same keys
const serverPublic = hexToBytes('{server_public.hex()}');
const ephemeralPrivate = hexToBytes('{ephemeral_private.hex()}');

console.log('🟨 JavaScript Step-by-Step Analysis');
console.log('📋 Server public:', bytesToHex(serverPublic));
console.log('📋 Ephemeral private:', bytesToHex(ephemeralPrivate));

// Create initiator
const noise = new NoiseNK();
noise.initializeInitiator(serverPublic);

console.log('\\n1️⃣ After initialization:');
console.log('   h (hash):', bytesToHex(noise.h));
console.log('   ck (chaining key):', bytesToHex(noise.ck));
console.log('   k (symmetric key):', noise.k ? bytesToHex(noise.k) : 'null');

// Manually set ephemeral key for deterministic testing
const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);
noise.e = {{ privateKey: ephemeralPrivate, publicKey: ephemeralPublic }};

console.log('\\n2️⃣ Set ephemeral key:');
console.log('   ephemeral public:', bytesToHex(ephemeralPublic));

// Step 3: mixHash(e.publicKey)
noise._mixHash(ephemeralPublic);
console.log('\\n3️⃣ After mixHash(ephemeral_public):');
console.log('   h (hash):', bytesToHex(noise.h));

// Step 4: DH and mixKey
const dh = noise._dh(noise.e, noise.rs);
console.log('\\n4️⃣ DH result:');
console.log('   dh:', bytesToHex(dh));

noise._mixKey(dh);
console.log('\\n5️⃣ After mixKey(dh):');
console.log('   ck (chaining key):', bytesToHex(noise.ck));
console.log('   k (symmetric key):', bytesToHex(noise.k));
console.log('   n (nonce counter):', noise.n);

// Step 6: Encrypt payload
const payload = new TextEncoder().encode('Hello!');
console.log('\\n6️⃣ Encrypting payload:');
console.log('   payload:', bytesToHex(payload));
console.log('   payload length:', payload.length);

// Show encryption details
console.log('   h before encrypt:', bytesToHex(noise.h));
const ciphertext = noise._encryptAndHash(payload);
console.log('   ciphertext:', bytesToHex(ciphertext));
console.log('   ciphertext length:', ciphertext.length);
console.log('   h after encrypt:', bytesToHex(noise.h));
console.log('   n after encrypt:', noise.n);

// Build final message
const message = new Uint8Array(32 + ciphertext.length);
message.set(ephemeralPublic);
message.set(ciphertext, 32);

console.log('\\n7️⃣ Final message:');
console.log('   message:', bytesToHex(message));
console.log('   message length:', message.length);

// Save debug data
const debugData = {{
    server_public: bytesToHex(serverPublic),
    ephemeral_private: bytesToHex(ephemeralPrivate),
    ephemeral_public: bytesToHex(ephemeralPublic),
    dh_result: bytesToHex(dh),
    steps: {{
        init_h: bytesToHex(noise.h),
        init_ck: bytesToHex(noise.ck),
        after_mixhash_h: bytesToHex(noise.h),
        after_mixkey_ck: bytesToHex(noise.ck),
        after_mixkey_k: bytesToHex(noise.k),
        payload: bytesToHex(payload),
        h_before_encrypt: bytesToHex(noise.h),
        ciphertext: bytesToHex(ciphertext),
        final_message: bytesToHex(message)
    }}
}};

import fs from 'fs';
fs.writeFileSync('js_steps.json', JSON.stringify(debugData, null, 2));
console.log('\\n💾 Debug data saved to js_steps.json');
"""
    
    # Write and run JavaScript debug
    with open('js_steps.js', 'w') as f:
        f.write(js_debug_script)
    
    result = subprocess.run(['node', 'js_steps.js'], capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ JavaScript debug failed:")
        print(result.stdout)
        print(result.stderr)
        return
    
    print(result.stdout.strip())
    
    # Now do the same with Python but manually step through
    print("\n🐍 Python Step-by-Step Analysis")
    print("=" * 40)
    
    # We can't easily replicate the internal steps of the Python noiseprotocol library
    # But we can compare the final results and see if we can make them match
    
    # Load JavaScript debug data
    with open('js_steps.json', 'r') as f:
        js_debug = json.load(f)
    
    print(f"📋 Server public: {server_public.hex()}")
    print(f"📋 Ephemeral private: {ephemeral_private.hex()}")
    
    # Try to create a Python message and compare
    python_noise = NoiseNK()
    python_noise.initialize_as_initiator(server_public)
    
    payload = b"Hello!"
    python_message = python_noise.write_message(payload)
    
    print(f"\n🔍 Comparison:")
    print(f"JavaScript message: {js_debug['steps']['final_message']}")
    print(f"Python message:     {python_message.hex()}")
    print(f"JavaScript length:  {len(bytes.fromhex(js_debug['steps']['final_message']))}")
    print(f"Python length:      {len(python_message)}")
    
    # Test if JavaScript message works with Python responder
    print(f"\n🔧 Testing JavaScript message with Python responder...")
    
    try:
        python_responder = NoiseNK()
        python_responder.initialize_as_responder(server_private)
        
        js_message = bytes.fromhex(js_debug['steps']['final_message'])
        received_payload = python_responder.read_message(js_message)
        print(f"✅ Success! Received: {received_payload}")
        
    except Exception as e:
        print(f"❌ Failed: {e}")
        
        # The issue might be in our manual ephemeral key setting
        # Let's try with the natural JavaScript generation
        print(f"\n🔧 Testing with natural JavaScript key generation...")
        
        js_natural_script = """
import { NoiseNK } from './src/noise-nk.js';

function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

const serverPublic = hexToBytes('b4ee9c9600c55250bfc31c3fe9ef9c4d478d7fa75d85642d82ea68a2f254123f');
const noise = new NoiseNK();
noise.initializeInitiator(serverPublic);

const payload = new TextEncoder().encode('Hello!');
const message = noise.writeMessage(payload);

console.log('Natural message:', bytesToHex(message));

import fs from 'fs';
fs.writeFileSync('js_natural.txt', bytesToHex(message));
"""
        
        with open('js_natural.js', 'w') as f:
            f.write(js_natural_script)
        
        result = subprocess.run(['node', 'js_natural.js'], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout.strip())
            
            # Test natural message
            with open('js_natural.txt', 'r') as f:
                natural_message_hex = f.read().strip()
            
            try:
                python_responder2 = NoiseNK()
                python_responder2.initialize_as_responder(server_private)
                
                natural_message = bytes.fromhex(natural_message_hex)
                received_payload2 = python_responder2.read_message(natural_message)
                print(f"✅ Natural message success! Received: {received_payload2}")
                
            except Exception as e2:
                print(f"❌ Natural message also failed: {e2}")
    
    # Clean up
    for file in ['js_steps.js', 'js_steps.json', 'js_natural.js', 'js_natural.txt']:
        if os.path.exists(file):
            os.remove(file)

if __name__ == "__main__":
    debug_step_by_step() 