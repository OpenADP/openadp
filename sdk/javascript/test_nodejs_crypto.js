#!/usr/bin/env node

import { createCipherGCM, createDecipherGCM } from 'crypto';

function testNodejsCrypto() {
    console.log('🔐 Node.js Built-in Crypto AES-GCM Test');
    console.log('=' .repeat(50));
    
    // Same parameters as before
    const key = Buffer.from('746708fc3a2cbf23d7cde32803ac24bc7f5f09050fb1a5f9bb1b095cba2cbe49', 'hex');
    const nonce = Buffer.from('000000000000000000000000', 'hex');
    const associatedData = Buffer.from('1b42f7b5b5bcea1c55686484c55188d7f5e33972377ff1fc199cf0aaece03998', 'hex');
    const plaintext = Buffer.alloc(0); // Empty plaintext
    
    console.log('🧪 Testing Node.js AES-GCM encryption:');
    console.log(`   Key: ${key.toString('hex')}`);
    console.log(`   Nonce: ${nonce.toString('hex')}`);
    console.log(`   Associated Data: ${associatedData.toString('hex')}`);
    console.log(`   Plaintext: ${plaintext.toString('hex')} (empty)`);
    
    try {
        // Encrypt with Node.js
        const cipher = createCipherGCM('aes-256-gcm');
        cipher.setAAD(associatedData);
        
        let encrypted = cipher.update(plaintext);
        cipher.final();
        const tag = cipher.getAuthTag();
        const ciphertext = Buffer.concat([encrypted, tag]);
        
        console.log(`✅ SUCCESS: Node.js ciphertext: ${ciphertext.toString('hex')}`);
        console.log(`   JavaScript (@noble): c08ac722941440904eeae04a0157f8d1`);
        console.log(`   Python (cryptography): e7c15f341ff37d92fc647ffa956340ab`);
        console.log(`   Node.js matches Python: ${ciphertext.toString('hex') === 'e7c15f341ff37d92fc647ffa956340ab' ? '✅ YES' : '❌ NO'}`);
        console.log(`   Node.js matches @noble: ${ciphertext.toString('hex') === 'c08ac722941440904eeae04a0157f8d1' ? '✅ YES' : '❌ NO'}`);
        
        return ciphertext;
    } catch (error) {
        console.log(`❌ FAILED: ${error.message}`);
        return null;
    }
}

function testNodejsDecrypt() {
    console.log('\n🧪 Testing Node.js AES-GCM decryption of Python ciphertext:');
    
    const key = Buffer.from('746708fc3a2cbf23d7cde32803ac24bc7f5f09050fb1a5f9bb1b095cba2cbe49', 'hex');
    const nonce = Buffer.from('000000000000000000000000', 'hex');
    const associatedData = Buffer.from('1b42f7b5b5bcea1c55686484c55188d7f5e33972377ff1fc199cf0aaece03998', 'hex');
    
    // Python's ciphertext
    const pythonCiphertext = Buffer.from('e7c15f341ff37d92fc647ffa956340ab', 'hex');
    
    console.log(`   Python ciphertext: ${pythonCiphertext.toString('hex')}`);
    
    try {
        const decipher = createDecipherGCM('aes-256-gcm');
        decipher.setAAD(associatedData);
        decipher.setAuthTag(pythonCiphertext.slice(-16)); // Last 16 bytes are the tag
        
        let decrypted = decipher.update(pythonCiphertext.slice(0, -16)); // All but last 16 bytes
        decipher.final();
        
        console.log(`✅ SUCCESS: Decrypted plaintext: ${decrypted.toString('hex')}`);
        return decrypted;
    } catch (error) {
        console.log(`❌ FAILED: ${error.message}`);
        return null;
    }
}

// Wait, I need to set the IV (nonce) properly
function testNodejsCryptoFixed() {
    console.log('\n🔐 Node.js Crypto (Fixed) AES-GCM Test');
    console.log('=' .repeat(50));
    
    const key = Buffer.from('746708fc3a2cbf23d7cde32803ac24bc7f5f09050fb1a5f9bb1b095cba2cbe49', 'hex');
    const iv = Buffer.from('000000000000000000000000', 'hex');
    const associatedData = Buffer.from('1b42f7b5b5bcea1c55686484c55188d7f5e33972377ff1fc199cf0aaece03998', 'hex');
    const plaintext = Buffer.alloc(0);
    
    try {
        const cipher = createCipherGCM('aes-256-gcm');
        cipher.setAAD(associatedData);
        
        let encrypted = cipher.update(plaintext);
        cipher.final();
        const tag = cipher.getAuthTag();
        const ciphertext = Buffer.concat([encrypted, tag]);
        
        console.log(`✅ Node.js ciphertext: ${ciphertext.toString('hex')}`);
        console.log(`   Expected Python: e7c15f341ff37d92fc647ffa956340ab`);
        console.log(`   Match: ${ciphertext.toString('hex') === 'e7c15f341ff37d92fc647ffa956340ab' ? '✅ YES' : '❌ NO'}`);
        
        return ciphertext;
    } catch (error) {
        console.log(`❌ FAILED: ${error.message}`);
        return null;
    }
}

// Run tests
const nodejsCiphertext = testNodejsCrypto();
const nodejsPlaintext = testNodejsDecrypt();
const fixedTest = testNodejsCryptoFixed(); 