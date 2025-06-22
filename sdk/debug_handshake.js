/**
 * Debug script to examine handshake message format
 */

import { NoiseNK } from './javascript/src/noise-nk.js';
import fs from 'fs';

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

function debugHandshakeMessage() {
    console.log('🔍 Debug: JavaScript Noise-NK Handshake Message Format');
    console.log('='.repeat(60));
    
    try {
        // Load server info
        const serverInfo = JSON.parse(fs.readFileSync('python/server_info.json', 'utf8'));
        const serverPublicKey = hexToBytes(serverInfo.public_key);
        
        console.log(`📋 Server public key: ${serverInfo.public_key}`);
        console.log(`📋 Server public key length: ${serverPublicKey.length} bytes`);
        
        // Initialize JavaScript NoiseNK as initiator
        const noise = new NoiseNK();
        noise.initializeInitiator(serverPublicKey);
        
        console.log('\n🔧 Creating handshake message...');
        
        // Create first handshake message
        const payload = new TextEncoder().encode('Hello from JavaScript client!');
        const message = noise.writeMessage(payload);
        
        console.log(`📤 Message length: ${message.length} bytes`);
        console.log(`📤 Message hex: ${bytesToHex(message)}`);
        
        // Break down the message structure
        const ephemeralKey = message.slice(0, 32);
        const ciphertext = message.slice(32);
        
        console.log(`\n📊 Message breakdown:`);
        console.log(`   Ephemeral key (32 bytes): ${bytesToHex(ephemeralKey)}`);
        console.log(`   Ciphertext (${ciphertext.length} bytes): ${bytesToHex(ciphertext)}`);
        
        // Check internal state
        console.log(`\n🔍 Internal state:`);
        console.log(`   Handshake complete: ${noise.handshakeComplete}`);
        console.log(`   Is initiator: ${noise.initiator}`);
        console.log(`   Has ephemeral key: ${noise.e ? 'Yes' : 'No'}`);
        console.log(`   Has remote static: ${noise.rs ? 'Yes' : 'No'}`);
        
        if (noise.e) {
            console.log(`   Ephemeral private: ${bytesToHex(noise.e.privateKey)}`);
            console.log(`   Ephemeral public: ${bytesToHex(noise.e.publicKey)}`);
        }
        
        console.log(`   Remote static: ${bytesToHex(noise.rs)}`);
        console.log(`   Chaining key: ${bytesToHex(noise.ck)}`);
        console.log(`   Hash: ${bytesToHex(noise.h)}`);
        
    } catch (error) {
        console.error('❌ Error:', error.message);
        console.error(error.stack);
    }
}

debugHandshakeMessage(); 