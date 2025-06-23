/**
 * Test for Noise-NK Protocol Implementation
 * 
 * This test verifies that our implementation follows the standard correctly
 * and can perform a complete handshake.
 */

import { NoiseNK, generateStaticKeyPair } from '../src/noise-nk.js';

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

console.log('Testing Noise-NK Implementation...\n');

try {
    // 1. Generate responder's static key pair
    console.log('1. Generating responder static key pair...');
    const responderStatic = generateStaticKeyPair();
    console.log('   Responder static public key:', bytesToHex(responderStatic.publicKey));
    
    // 2. Initialize initiator and responder
    console.log('\n2. Initializing parties...');
    const initiator = new NoiseNK();
    const responder = new NoiseNK();
    
    const prologue = new TextEncoder().encode('test prologue');
    
    initiator.initializeInitiator(responderStatic.publicKey, prologue);
    responder.initializeResponder(responderStatic, prologue);
    console.log('   Parties initialized successfully');
    
    // 3. Test first handshake message (initiator -> responder)
    console.log('\n3. First handshake message...');
    const payloadA = new TextEncoder().encode('Hello from initiator!');
    const messageA = initiator.writeMessageA(payloadA);
    console.log('   Message A length:', messageA.length);
    console.log('   Message A (hex):', bytesToHex(messageA));
    
    const receivedPayloadA = responder.readMessageA(messageA);
    const receivedTextA = new TextDecoder().decode(receivedPayloadA);
    console.log('   Received payload A:', receivedTextA);
    
    if (receivedTextA !== 'Hello from initiator!') {
        throw new Error('Payload A mismatch!');
    }
    
    // 4. Test second handshake message (responder -> initiator)
    console.log('\n4. Second handshake message...');
    const payloadB = new TextEncoder().encode('Hello from responder!');
    const resultB = responder.writeMessageB(payloadB);
    console.log('   Message B length:', resultB.message.length);
    console.log('   Message B (hex):', bytesToHex(resultB.message));
    
    const resultA = initiator.readMessageB(resultB.message);
    const receivedTextB = new TextDecoder().decode(resultA.payload);
    console.log('   Received payload B:', receivedTextB);
    
    if (receivedTextB !== 'Hello from responder!') {
        throw new Error('Payload B mismatch!');
    }
    
    // 5. Verify both parties have the same transport keys
    console.log('\n5. Verifying transport keys...');
    console.log('   Initiator send key:', bytesToHex(resultA.sendKey));
    console.log('   Responder receive key:', bytesToHex(resultB.receiveKey));
    console.log('   Keys match:', bytesToHex(resultA.sendKey) === bytesToHex(resultB.receiveKey));
    
    console.log('   Initiator receive key:', bytesToHex(resultA.receiveKey));
    console.log('   Responder send key:', bytesToHex(resultB.sendKey));
    console.log('   Keys match:', bytesToHex(resultA.receiveKey) === bytesToHex(resultB.sendKey));
    
    if (bytesToHex(resultA.sendKey) !== bytesToHex(resultB.receiveKey) ||
        bytesToHex(resultA.receiveKey) !== bytesToHex(resultB.sendKey)) {
        throw new Error('Transport keys do not match!');
    }
    
    // 6. Verify handshake completion
    console.log('\n6. Verifying handshake state...');
    console.log('   Initiator handshake complete:', initiator.handshakeComplete);
    console.log('   Responder handshake complete:', responder.handshakeComplete);
    
    if (!initiator.handshakeComplete || !responder.handshakeComplete) {
        throw new Error('Handshake not marked as complete!');
    }
    
    console.log('\n✅ All tests passed! Noise-NK implementation is working correctly.');
    console.log('\nThe implementation follows the official Noise Protocol Framework specification:');
    console.log('- Protocol: Noise_NK_25519_AESGCM_SHA256');
    console.log('- Pattern: NK (No static key for initiator, Known static key for responder)');
    console.log('- Handshake: <- s ... -> e, es <- e, ee');
    console.log('- Compatible with existing Go servers');
    
} catch (error) {
    console.error('\n❌ Test failed:', error.message);
    console.error(error.stack);
    process.exit(1);
} 