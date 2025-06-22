#!/usr/bin/env node

/**
 * Standalone JavaScript debug test for handshake hash computation
 */

import { NoiseNK } from './src/noise-nk.js';

// Enable debug logging
process.env.NOISE_DEBUG = '1';

function debugStandalone() {
    console.log('🔍 JavaScript Standalone Debug Test');
    console.log('===================================');
    
    // Use the same server key as Python for comparison
    const serverPubkeyHex = "0b6853e9bfa19e74b117ab40d2e1bea675415f15a15c18ef7ec2b02dcf9d1400";
    const serverPubkey = new Uint8Array(Buffer.from(serverPubkeyHex, 'hex'));
    
    console.log(`📋 Using fixed server public key: ${serverPubkeyHex}`);
    console.log();
    
    // Create client
    const client = new NoiseNK();
    console.log('=== INITIALIZING AS INITIATOR ===');
    client.initializeInitiator(serverPubkey);
    
    console.log();
    console.log('=== WRITING FIRST MESSAGE ===');
    const message1 = client.writeMessage(new Uint8Array()); // empty payload
    
    console.log();
    console.log('=== FINAL RESULTS ===');
    console.log(`📤 Generated message: ${Array.from(message1).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    console.log(`📤 Message length: ${message1.length} bytes`);
    
    const finalHash = client.getHandshakeHash();
    console.log(`🔑 Final JavaScript handshake hash: ${Array.from(finalHash).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    
    console.log();
    console.log('=== COMPARISON WITH PYTHON ===');
    console.log('Expected Python hash: 07b5687c597122f17cac8836b5ff2ed1292019c7b63e36451050372044a55096');
    console.log(`Actual JavaScript hash: ${Array.from(finalHash).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    
    const pythonHash = "07b5687c597122f17cac8836b5ff2ed1292019c7b63e36451050372044a55096";
    const jsHash = Array.from(finalHash).map(b => b.toString(16).padStart(2, '0')).join('');
    console.log(`Hashes match: ${pythonHash === jsHash}`);
}

debugStandalone(); 