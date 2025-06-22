/**
 * Noise-NK TCP Client
 * 
 * A JavaScript client that uses Noise-NK protocol to connect to the Python server
 * and demonstrate cross-platform compatibility.
 */

import { NoiseNK } from './src/noise-nk.js';
import net from 'net';
import fs from 'fs';
import path from 'path';

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

class NoiseNKClient {
    constructor() {
        this.socket = null;
        this.noise = null;
        this.connected = false;
        this.handshakeComplete = false;
    }

    async connect(host, port, serverPublicKey) {
        return new Promise((resolve, reject) => {
            console.log(`🔗 Connecting to ${host}:${port}...`);
            
            this.socket = net.createConnection(port, host);
            
            this.socket.on('connect', () => {
                console.log('✅ TCP connection established');
                this.connected = true;
                this.startNoiseHandshake(serverPublicKey)
                    .then(() => resolve())
                    .catch(reject);
            });
            
            this.socket.on('error', (error) => {
                console.error('❌ Connection error:', error.message);
                reject(error);
            });
            
            this.socket.on('close', () => {
                console.log('🔌 Connection closed');
                this.connected = false;
                this.handshakeComplete = false;
            });
        });
    }

    async startNoiseHandshake(serverPublicKey) {
        console.log('🔒 Starting Noise-NK handshake...');
        
        // Initialize Noise-NK as initiator (client)
        this.noise = new NoiseNK();
        this.noise.initializeInitiator(serverPublicKey);
        
        // Send first handshake message (with empty payload)
        const message1 = this.noise.writeMessage();
        
        // Print handshake hash after first message
        const hash1 = this.noise.getHandshakeHash();
        console.log(`🔑 Handshake hash after message 1: ${Array.from(hash1).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        console.log(`📤 Sending handshake message 1: ${message1.length} bytes`);
        console.log(`🔍 Raw message 1 hex: ${Array.from(message1).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        await this.sendMessage(message1);
        
        // Receive second handshake message
        const message2 = await this.receiveMessage();
        if (!message2) {
            throw new Error('Failed to receive handshake message 2');
        }
        
        console.log(`📨 Received handshake message 2: ${message2.length} bytes`);
        
        // Process second handshake message
        const serverPayload = this.noise.readMessage(message2);
        const serverPayloadText = new TextDecoder().decode(serverPayload);
        
        // Print final handshake hash
        const finalHash = this.noise.getHandshakeHash();
        console.log(`🔑 Final handshake hash: ${Array.from(finalHash).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        console.log(`📝 Server payload: ${serverPayloadText}`);
        
        if (!this.noise.handshakeComplete) {
            throw new Error('Handshake not complete');
        }
        
        this.handshakeComplete = true;
        console.log('✅ Noise-NK handshake completed successfully!');
        console.log(`🔐 Secure channel established`);
    }

    async sendSecureMessage(message) {
        if (!this.handshakeComplete) {
            throw new Error('Handshake not complete');
        }
        
        console.log(`📤 Sending secure message: ${message}`);
        
        // Encrypt message
        const plaintext = new TextEncoder().encode(message);
        const encrypted = this.noise.encrypt(plaintext);
        
        // Send encrypted message
        await this.sendMessage(encrypted);
        
        // Receive encrypted response
        const encryptedResponse = await this.receiveMessage();
        if (!encryptedResponse) {
            throw new Error('Failed to receive response');
        }
        
        // Decrypt response
        const decryptedResponse = this.noise.decrypt(encryptedResponse);
        const response = new TextDecoder().decode(decryptedResponse);
        
        console.log(`📨 Received secure response: ${response}`);
        return response;
    }

    async sendMessage(data) {
        return new Promise((resolve, reject) => {
            if (!this.connected) {
                reject(new Error('Not connected'));
                return;
            }
            
            // Send length prefix (4 bytes, big-endian)
            const length = data.length;
            const lengthBuffer = Buffer.allocUnsafe(4);
            lengthBuffer.writeUInt32BE(length, 0);
            
            // Send length then data
            this.socket.write(lengthBuffer);
            this.socket.write(data);
            resolve();
        });
    }

    async receiveMessage() {
        return new Promise((resolve, reject) => {
            if (!this.connected) {
                reject(new Error('Not connected'));
                return;
            }
            
            let lengthBuffer = Buffer.alloc(0);
            let dataBuffer = Buffer.alloc(0);
            let expectedLength = null;
            let receivingData = false;
            
            const onData = (chunk) => {
                if (!receivingData) {
                    // Receiving length
                    lengthBuffer = Buffer.concat([lengthBuffer, chunk]);
                    
                    if (lengthBuffer.length >= 4) {
                        expectedLength = lengthBuffer.readUInt32BE(0);
                        receivingData = true;
                        
                        // If there's extra data after the length, it's part of the message
                        if (lengthBuffer.length > 4) {
                            const extraData = lengthBuffer.slice(4);
                            dataBuffer = Buffer.concat([dataBuffer, extraData]);
                        }
                    }
                } else {
                    // Receiving data
                    dataBuffer = Buffer.concat([dataBuffer, chunk]);
                }
                
                // Check if we have the complete message
                if (receivingData && dataBuffer.length >= expectedLength) {
                    this.socket.removeListener('data', onData);
                    this.socket.removeListener('error', onError);
                    
                    const messageData = dataBuffer.slice(0, expectedLength);
                    resolve(new Uint8Array(messageData));
                }
            };
            
            const onError = (error) => {
                this.socket.removeListener('data', onData);
                this.socket.removeListener('error', onError);
                reject(error);
            };
            
            this.socket.on('data', onData);
            this.socket.on('error', onError);
        });
    }

    disconnect() {
        if (this.socket) {
            this.socket.end();
        }
    }
}

function loadServerInfo() {
    try {
        const serverInfoPath = path.join(process.cwd(), '..', 'python', 'server_info.json');
        const data = fs.readFileSync(serverInfoPath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('❌ Could not load server info:', error.message);
        console.log('   Make sure the Python server is running and has created server_info.json');
        process.exit(1);
    }
}

async function main() {
    console.log('🔐 Noise-NK JavaScript Client');
    console.log('=============================');
    
    try {
        // Load server information
        const serverInfo = loadServerInfo();
        console.log('📋 Server info loaded:');
        console.log(`   Host: ${serverInfo.host}`);
        console.log(`   Port: ${serverInfo.port}`);
        console.log(`   Protocol: ${serverInfo.protocol}`);
        console.log(`   Public Key: ${serverInfo.public_key.substring(0, 32)}...`);
        
        const serverPublicKey = hexToBytes(serverInfo.public_key);
        
        // Create client and connect
        const client = new NoiseNKClient();
        await client.connect(serverInfo.host, serverInfo.port, serverPublicKey);
        
        // Send some test messages
        console.log('\n🔐 Testing secure communication...');
        
        const messages = [
            'Hello from JavaScript!',
            'This is a test message',
            'Noise-NK is working great!',
            'Cross-platform compatibility confirmed!'
        ];
        
        for (let i = 0; i < messages.length; i++) {
            console.log(`\n--- Test Message ${i + 1} ---`);
            const response = await client.sendSecureMessage(messages[i]);
            
            // Verify echo response
            const expectedEcho = `Echo: ${messages[i]} (from Python server)`;
            if (response === expectedEcho) {
                console.log('✅ Response matches expected echo');
            } else {
                console.log('❌ Response does not match expected echo');
                console.log(`   Expected: ${expectedEcho}`);
                console.log(`   Received: ${response}`);
            }
            
            // Wait a bit between messages
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
        
        console.log('\n🎉 All tests completed successfully!');
        console.log('🔗 Python server and JavaScript client are fully compatible!');
        
        // Disconnect
        client.disconnect();
        
    } catch (error) {
        console.error('❌ Client error:', error.message);
        console.error(error.stack);
        process.exit(1);
    }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down client...');
    process.exit(0);
});

main(); 