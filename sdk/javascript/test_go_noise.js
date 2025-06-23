#!/usr/bin/env node

import { EncryptedOpenADPClient, parseServerPublicKey } from './src/client.js';

async function testGoNoiseNK() {
    console.log('🔐 Testing JavaScript Noise-NK client with Go server...');
    
    try {
        // Step 1: Get server info to extract Noise-NK public key
        console.log('📡 Getting server info...');
        const plainClient = new EncryptedOpenADPClient('http://localhost:8081');
        const serverInfo = await plainClient.getServerInfo();
        
        console.log('✅ Server info received:');
        console.log(`   Version: ${serverInfo.version}`);
        console.log(`   Noise-NK key: ${serverInfo.noise_nk_public_key ? serverInfo.noise_nk_public_key.substring(0, 32) + '...' : 'Not available'}`);
        
        if (!serverInfo.noise_nk_public_key) {
            throw new Error('Server does not support Noise-NK encryption');
        }
        
        // Step 2: Parse the server's public key
        const serverPublicKey = parseServerPublicKey(serverInfo.noise_nk_public_key);
        console.log(`🔑 Parsed server public key: ${serverPublicKey.length} bytes`);
        
        // Step 3: Create encrypted client
        const encryptedClient = new EncryptedOpenADPClient('http://localhost:8081', serverPublicKey);
        console.log('🔒 Created encrypted client');
        
        // Step 4: Test encrypted echo
        console.log('📤 Testing encrypted echo...');
        const testMessage = 'Hello from JavaScript with Noise-NK!';
        const echoResult = await encryptedClient.echo(testMessage, true); // encrypted=true
        
        if (echoResult === testMessage) {
            console.log('✅ Encrypted echo test: PASSED');
            console.log(`   Sent: "${testMessage}"`);
            console.log(`   Received: "${echoResult}"`);
        } else {
            console.log('❌ Encrypted echo test: FAILED');
            console.log(`   Expected: "${testMessage}"`);
            console.log(`   Got: "${echoResult}"`);
            return false;
        }
        
        // Step 5: Test encrypted server info
        console.log('📤 Testing encrypted GetServerInfo...');
        const encryptedServerInfo = await encryptedClient.getServerInfo();
        console.log('✅ Encrypted GetServerInfo test: PASSED');
        console.log(`   Version: ${encryptedServerInfo.version}`);
        
        console.log('🎉 All tests passed! JavaScript ↔ Go Noise-NK is working!');
        return true;
        
    } catch (error) {
        console.log('❌ Test failed:');
        console.log(`   Error: ${error.message}`);
        if (error.details) {
            console.log(`   Details: ${error.details}`);
        }
        console.log(`   Stack: ${error.stack}`);
        return false;
    }
}

// Run the test
testGoNoiseNK().then(success => {
    process.exit(success ? 0 : 1);
}); 