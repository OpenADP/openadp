
import { NoiseNK } from './javascript/src/noise-nk.js';
import { x25519 } from '@noble/curves/ed25519';

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Use same keys
const serverPublic = hexToBytes('b4ee9c9600c55250bfc31c3fe9ef9c4d478d7fa75d85642d82ea68a2f254123f');
const ephemeralPrivate = hexToBytes('a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8');

console.log('🟨 JavaScript Step-by-Step Analysis');
console.log('📋 Server public:', bytesToHex(serverPublic));
console.log('📋 Ephemeral private:', bytesToHex(ephemeralPrivate));

// Create initiator
const noise = new NoiseNK();
noise.initializeInitiator(serverPublic);

console.log('\n1️⃣ After initialization:');
console.log('   h (hash):', bytesToHex(noise.h));
console.log('   ck (chaining key):', bytesToHex(noise.ck));
console.log('   k (symmetric key):', noise.k ? bytesToHex(noise.k) : 'null');

// Manually set ephemeral key for deterministic testing
const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);
noise.e = { privateKey: ephemeralPrivate, publicKey: ephemeralPublic };

console.log('\n2️⃣ Set ephemeral key:');
console.log('   ephemeral public:', bytesToHex(ephemeralPublic));

// Step 3: mixHash(e.publicKey)
noise._mixHash(ephemeralPublic);
console.log('\n3️⃣ After mixHash(ephemeral_public):');
console.log('   h (hash):', bytesToHex(noise.h));

// Step 4: DH and mixKey
const dh = noise._dh(noise.e, noise.rs);
console.log('\n4️⃣ DH result:');
console.log('   dh:', bytesToHex(dh));

noise._mixKey(dh);
console.log('\n5️⃣ After mixKey(dh):');
console.log('   ck (chaining key):', bytesToHex(noise.ck));
console.log('   k (symmetric key):', bytesToHex(noise.k));
console.log('   n (nonce counter):', noise.n);

// Step 6: Encrypt payload
const payload = new TextEncoder().encode('Hello!');
console.log('\n6️⃣ Encrypting payload:');
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

console.log('\n7️⃣ Final message:');
console.log('   message:', bytesToHex(message));
console.log('   message length:', message.length);

// Save debug data
const debugData = {
    server_public: bytesToHex(serverPublic),
    ephemeral_private: bytesToHex(ephemeralPrivate),
    ephemeral_public: bytesToHex(ephemeralPublic),
    dh_result: bytesToHex(dh),
    steps: {
        init_h: bytesToHex(noise.h),
        init_ck: bytesToHex(noise.ck),
        after_mixhash_h: bytesToHex(noise.h),
        after_mixkey_ck: bytesToHex(noise.ck),
        after_mixkey_k: bytesToHex(noise.k),
        payload: bytesToHex(payload),
        h_before_encrypt: bytesToHex(noise.h),
        ciphertext: bytesToHex(ciphertext),
        final_message: bytesToHex(message)
    }
};

import fs from 'fs';
fs.writeFileSync('js_steps.json', JSON.stringify(debugData, null, 2));
console.log('\n💾 Debug data saved to js_steps.json');
