/**
 * Example usage of Noise-NK Protocol Implementation
 * 
 * This example demonstrates how to use the Noise-NK implementation
 * for a complete handshake between an initiator and responder.
 */

import { NoiseNK, generateStaticKeyPair } from '../src/noise-nk.js';

function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

console.log('=== Noise-NK Protocol Example ===\n');

// Step 1: Server generates its static key pair (this would be done once and stored)
console.log('1. Generating server static key pair...');
const serverStaticKeys = generateStaticKeyPair();
console.log('   Server public key:', bytesToHex(serverStaticKeys.publicKey));
console.log('   (Server private key would be kept secret)');

// Step 2: Client initiates connection (knowing server's public key)
console.log('\n2. Client initiating handshake...');
const client = new NoiseNK();
const server = new NoiseNK();

// Initialize both parties
const prologue = new TextEncoder().encode('example-app-v1');
client.initializeInitiator(serverStaticKeys.publicKey, prologue);
server.initializeResponder(serverStaticKeys, prologue);

// Step 3: Client sends first message
console.log('\n3. Client -> Server: First handshake message');
const clientMessage1 = new TextEncoder().encode('Client hello!');
const handshakeMessage1 = client.writeMessageA(clientMessage1);
console.log('   Message size:', handshakeMessage1.length, 'bytes');

// Server receives and processes first message
const receivedMessage1 = server.readMessageA(handshakeMessage1);
const receivedText1 = new TextDecoder().decode(receivedMessage1);
console.log('   Server received:', receivedText1);

// Step 4: Server responds with second message
console.log('\n4. Server -> Client: Second handshake message');
const serverMessage2 = new TextEncoder().encode('Server hello!');
const handshakeResult2 = server.writeMessageB(serverMessage2);
console.log('   Message size:', handshakeResult2.message.length, 'bytes');

// Client receives and processes second message (handshake complete)
const clientResult = client.readMessageB(handshakeResult2.message);
const receivedText2 = new TextDecoder().decode(clientResult.payload);
console.log('   Client received:', receivedText2);

// Step 5: Display handshake completion
console.log('\n5. Handshake completed successfully!');
console.log('   Client handshake complete:', client.handshakeComplete);
console.log('   Server handshake complete:', server.handshakeComplete);

// Step 6: Show transport keys (for secure channel)
console.log('\n6. Transport keys established:');
console.log('   Client->Server key:', bytesToHex(clientResult.sendKey));
console.log('   Server->Client key:', bytesToHex(clientResult.receiveKey));

console.log('\n=== Example Complete ===');
console.log('\nThe handshake established a secure channel with:');
console.log('- Forward secrecy (ephemeral keys)');
console.log('- Server authentication (static key)');
console.log('- Resistance to replay attacks');
console.log('- Compatible with existing Go Noise-NK servers'); 