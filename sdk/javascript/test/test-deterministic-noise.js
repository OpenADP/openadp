/**
 * Deterministic test for JavaScript Noise-NK implementation.
 * 
 * This test uses hard-coded keys to ensure reproducible results and verify
 * compatibility with the Python implementation.
 */

import { NoiseNK } from '../src/noise-nk.js';
import { x25519 } from '@noble/curves/ed25519';

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

function testDeterministicNoiseNK() {
    console.log('🔒 Testing JavaScript Noise-NK with deterministic keys...');
    
    // Hard-coded test keys (same as Python test)
    // Server static key pair
    const serverPrivateKey = hexToBytes(
        "4040404040404040404040404040404040404040404040404040404040404040"
    );
    const serverPublicKey = hexToBytes(
        "d7b5e81d336e578b13b8d706e82d061e3038c96bce66cdcf50d566b96ddbba10"
    );
    
    // Test prologue
    const prologue = new TextEncoder().encode("test_prologue_12345");
    
    console.log(`   Server private key: ${bytesToHex(serverPrivateKey)}`);
    console.log(`   Server public key:  ${bytesToHex(serverPublicKey)}`);
    console.log(`   Prologue: ${new TextDecoder().decode(prologue)}`);
    
    // Create server static key pair object
    const serverStaticKeys = {
        privateKey: serverPrivateKey,
        publicKey: serverPublicKey
    };
    
    // Initialize client (initiator) and server (responder)
    const client = new NoiseNK();
    const server = new NoiseNK();
    
    client.initializeInitiator(serverPublicKey, prologue);
    server.initializeResponder(serverStaticKeys, prologue);
    
    console.log('   ✅ Initialized client and server');
    
    // Hard-coded ephemeral keys for deterministic testing
    const clientEphemeralPrivate = hexToBytes(
        "5050505050505050505050505050505050505050505050505050505050505050"
    );
    const serverEphemeralPrivate = hexToBytes(
        "6060606060606060606060606060606060606060606060606060606060606060"
    );
    
    // Derive public keys from private keys using x25519
    const clientEphemeralPublic = x25519.getPublicKey(clientEphemeralPrivate);
    const serverEphemeralPublic = x25519.getPublicKey(serverEphemeralPrivate);
    
    console.log(`   Client ephemeral private: ${bytesToHex(clientEphemeralPrivate)}`);
    console.log(`   Client ephemeral public:  ${bytesToHex(clientEphemeralPublic)}`);
    console.log(`   Server ephemeral private: ${bytesToHex(serverEphemeralPrivate)}`);
    console.log(`   Server ephemeral public:  ${bytesToHex(serverEphemeralPublic)}`);
    
    // Override the ephemeral key generation to use our deterministic keys
    // We need to monkey-patch the _generateEphemeralKeyPair method
    let clientEphemeralUsed = false;
    let serverEphemeralUsed = false;
    
    const originalClientGenerate = client._generateEphemeralKeyPair;
    const originalServerGenerate = server._generateEphemeralKeyPair;
    
    client._generateEphemeralKeyPair = function() {
        if (!clientEphemeralUsed) {
            clientEphemeralUsed = true;
            return {
                privateKey: clientEphemeralPrivate,
                publicKey: clientEphemeralPublic
            };
        }
        return originalClientGenerate.call(this);
    };
    
    server._generateEphemeralKeyPair = function() {
        if (!serverEphemeralUsed) {
            serverEphemeralUsed = true;
            return {
                privateKey: serverEphemeralPrivate,
                publicKey: serverEphemeralPublic
            };
        }
        return originalServerGenerate.call(this);
    };
    
    // Perform handshake
    console.log('   Performing handshake...');
    
    // Step 1: Client -> Server (first handshake message)
    const payload1 = new TextEncoder().encode("Hello from client!");
    const message1 = client.writeMessageA(payload1);
    console.log(`   Client message 1: ${message1.length} bytes`);
    console.log(`   Message 1 hex: ${bytesToHex(message1)}`);
    
    // Server processes first message
    const receivedPayload1 = server.readMessageA(message1);
    const receivedText1 = new TextDecoder().decode(receivedPayload1);
    console.log(`   Server received: ${receivedText1}`);
    
    // Step 2: Server -> Client (second handshake message)
    const payload2 = new TextEncoder().encode("Hello from server!");
    const result2 = server.writeMessageB(payload2);
    console.log(`   Server message 2: ${result2.message.length} bytes`);
    console.log(`   Message 2 hex: ${bytesToHex(result2.message)}`);
    
    // Client processes second message
    const result1 = client.readMessageB(result2.message);
    const receivedText2 = new TextDecoder().decode(result1.payload);
    console.log(`   Client received: ${receivedText2}`);
    
    // Verify handshake completion
    if (!client.handshakeComplete) {
        throw new Error('Client handshake not complete');
    }
    if (!server.handshakeComplete) {
        throw new Error('Server handshake not complete');
    }
    
    console.log('   ✅ Handshake completed successfully');
    
    // Extract handshake hash (this is the 'h' value after handshake completion)
    const clientHash = client.h;
    const serverHash = server.h;
    
    console.log(`   Client handshake hash: ${bytesToHex(clientHash)}`);
    console.log(`   Server handshake hash: ${bytesToHex(serverHash)}`);
    
    if (bytesToHex(clientHash) === bytesToHex(serverHash)) {
        console.log('   ✅ Handshake hashes match!');
    } else {
        console.log('   ❌ Handshake hashes do not match!');
        throw new Error('Handshake hashes do not match');
    }
    
    // Verify transport keys match
    console.log(`   Client send key:    ${bytesToHex(result1.sendKey)}`);
    console.log(`   Server receive key: ${bytesToHex(result2.receiveKey)}`);
    console.log(`   Client receive key: ${bytesToHex(result1.receiveKey)}`);
    console.log(`   Server send key:    ${bytesToHex(result2.sendKey)}`);
    
    if (bytesToHex(result1.sendKey) === bytesToHex(result2.receiveKey) &&
        bytesToHex(result1.receiveKey) === bytesToHex(result2.sendKey)) {
        console.log('   ✅ Transport keys match correctly!');
    } else {
        console.log('   ❌ Transport keys do not match!');
        throw new Error('Transport keys do not match');
    }
    
    return clientHash;
}

console.log('Testing JavaScript Noise-NK Implementation with Deterministic Keys...\n');

try {
    const handshakeHash = testDeterministicNoiseNK();
    console.log(`\n🎉 Test completed! Final handshake hash: ${bytesToHex(handshakeHash)}`);
    console.log('\nThis hash should match the Python implementation when using the same keys.');
} catch (error) {
    console.error('\n❌ Test failed:', error.message);
    console.error(error.stack);
    process.exit(1);
} 