#!/usr/bin/env node

import { gcm } from '@noble/ciphers/aes';

function testAESGCMEncrypt() {
    console.log('🔐 JavaScript AES-GCM Compatibility Test');
    console.log('=' .repeat(50));
    
    // Exact same parameters as Python test
    const key = new Uint8Array([0x74, 0x67, 0x08, 0xfc, 0x3a, 0x2c, 0xbf, 0x23, 0xd7, 0xcd, 0xe3, 0x28, 0x03, 0xac, 0x24, 0xbc, 0x7f, 0x5f, 0x09, 0x05, 0x0f, 0xb1, 0xa5, 0xf9, 0xbb, 0x1b, 0x09, 0x5c, 0xba, 0x2c, 0xbe, 0x49]);
    const nonce = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const associatedData = new Uint8Array([0x1b, 0x42, 0xf7, 0xb5, 0xb5, 0xbc, 0xea, 0x1c, 0x55, 0x68, 0x64, 0x84, 0xc5, 0x51, 0x88, 0xd7, 0xf5, 0xe3, 0x39, 0x72, 0x37, 0x7f, 0xf1, 0xfc, 0x19, 0x9c, 0xf0, 0xaa, 0xec, 0xe0, 0x39, 0x98]);
    const plaintext = new Uint8Array(0); // Empty plaintext
    
    console.log('🧪 Testing JavaScript AES-GCM encryption:');
    console.log(`   Key: ${Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    console.log(`   Nonce: ${Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    console.log(`   Associated Data: ${Array.from(associatedData).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    console.log(`   Plaintext: ${Array.from(plaintext).map(b => b.toString(16).padStart(2, '0')).join('')} (empty)`);
    
    try {
        const cipher = gcm(key, nonce);
        const ciphertext = cipher.encrypt(plaintext, associatedData);
        const ciphertextHex = Array.from(ciphertext).map(b => b.toString(16).padStart(2, '0')).join('');
        
        console.log(`✅ SUCCESS: JavaScript ciphertext: ${ciphertextHex}`);
        console.log(`   Python produced: e7c15f341ff37d92fc647ffa956340ab`);
        console.log(`   Match: ${ciphertextHex === 'e7c15f341ff37d92fc647ffa956340ab' ? '✅ YES' : '❌ NO'}`);
        
        return ciphertext;
    } catch (error) {
        console.log(`❌ FAILED: ${error.message}`);
        return null;
    }
}

function testAESGCMDecrypt() {
    console.log('\n🧪 Testing JavaScript AES-GCM decryption of Python ciphertext:');
    
    // Try to decrypt what Python produced
    const key = new Uint8Array([0x74, 0x67, 0x08, 0xfc, 0x3a, 0x2c, 0xbf, 0x23, 0xd7, 0xcd, 0xe3, 0x28, 0x03, 0xac, 0x24, 0xbc, 0x7f, 0x5f, 0x09, 0x05, 0x0f, 0xb1, 0xa5, 0xf9, 0xbb, 0x1b, 0x09, 0x5c, 0xba, 0x2c, 0xbe, 0x49]);
    const nonce = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const associatedData = new Uint8Array([0x1b, 0x42, 0xf7, 0xb5, 0xb5, 0xbc, 0xea, 0x1c, 0x55, 0x68, 0x64, 0x84, 0xc5, 0x51, 0x88, 0xd7, 0xf5, 0xe3, 0x39, 0x72, 0x37, 0x7f, 0xf1, 0xfc, 0x19, 0x9c, 0xf0, 0xaa, 0xec, 0xe0, 0x39, 0x98]);
    
    // Python's ciphertext
    const pythonCiphertext = new Uint8Array([0xe7, 0xc1, 0x5f, 0x34, 0x1f, 0xf3, 0x7d, 0x92, 0xfc, 0x64, 0x7f, 0xfa, 0x95, 0x63, 0x40, 0xab]);
    
    console.log(`   Python ciphertext: ${Array.from(pythonCiphertext).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    
    try {
        const cipher = gcm(key, nonce);
        const plaintext = cipher.decrypt(pythonCiphertext, associatedData);
        console.log(`✅ SUCCESS: Decrypted plaintext: ${Array.from(plaintext).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        return plaintext;
    } catch (error) {
        console.log(`❌ FAILED: ${error.message}`);
        return null;
    }
}

// Run tests
const jsCiphertext = testAESGCMEncrypt();
const jsPlaintext = testAESGCMDecrypt();

console.log('\n🎯 CONCLUSION:');
if (jsCiphertext && jsPlaintext) {
    console.log('✅ JavaScript AES-GCM works but produces different results than Python');
} else {
    console.log('❌ JavaScript AES-GCM has issues');
} 