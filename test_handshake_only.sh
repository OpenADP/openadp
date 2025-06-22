#!/bin/bash

# Test script for Noise-NK handshake only (no transport messages)
# This will help us verify the handshake works before debugging transport

set -e

echo "🧪 Noise-NK Handshake-Only Test"
echo "==============================="

# Cleanup function
cleanup() {
    echo "🧹 Cleaning up..."
    pkill -f noise_server.py 2>/dev/null || true
    sleep 1
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Create logs directory
mkdir -p logs
rm -f logs/*.log

echo "📁 Starting Python server..."

# Start Python server in background
cd sdk/python
python3 noise_server.py > ../../logs/server_handshake.log 2>&1 &
SERVER_PID=$!
cd ../..

# Wait for server to start
echo "⏳ Waiting for server to initialize..."
sleep 3

# Check if server is still running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ Server failed to start!"
    echo "📄 Server log:"
    cat logs/server_handshake.log
    exit 1
fi

echo "🚀 Server started (PID: $SERVER_PID)"
echo "📱 Creating handshake-only client..."

# Create a simple client that only does handshake
cat > handshake_test_client.js << 'EOF'
import net from 'net';
import fs from 'fs';
import { NoiseNK } from './src/noise-nk.js';

async function testHandshakeOnly() {
    try {
        console.log('🔐 Noise-NK Handshake-Only Test');
        console.log('===============================');
        
        // Read server info
        const serverInfo = JSON.parse(fs.readFileSync('../python/server_info.json', 'utf8'));
        console.log(`📋 Connecting to ${serverInfo.host}:${serverInfo.port}`);
        console.log(`🔑 Server public key: ${serverInfo.public_key.substring(0, 16)}...`);
        
        // Connect to server
        const socket = new net.Socket();
        const serverPublicKey = Buffer.from(serverInfo.public_key, 'hex');
        
        await new Promise((resolve, reject) => {
            socket.connect(serverInfo.port, serverInfo.host, () => {
                console.log('✅ TCP connection established');
                resolve();
            });
            socket.on('error', reject);
        });
        
        // Initialize Noise-NK as initiator
        console.log('🔒 Starting Noise-NK handshake...');
        const noise = new NoiseNK();
        noise.initializeAsInitiator(serverPublicKey);
        
        // Send first handshake message
        const message1 = noise.writeMessageA();
        const message1Bytes = new Uint8Array(4 + message1.length);
        message1Bytes.set(new Uint8Array([(message1.length >>> 24) & 0xFF, (message1.length >>> 16) & 0xFF, (message1.length >>> 8) & 0xFF, message1.length & 0xFF]), 0);
        message1Bytes.set(message1, 4);
        
        socket.write(message1Bytes);
        console.log(`📤 Sent handshake message 1: ${message1.length} bytes`);
        
        // Receive second handshake message
        const response = await new Promise((resolve, reject) => {
            let buffer = Buffer.alloc(0);
            
            socket.on('data', (data) => {
                buffer = Buffer.concat([buffer, data]);
                
                if (buffer.length >= 4) {
                    const messageLength = buffer.readUInt32BE(0);
                    if (buffer.length >= 4 + messageLength) {
                        const message = buffer.slice(4, 4 + messageLength);
                        resolve(message);
                    }
                }
            });
            
            socket.on('error', reject);
            setTimeout(() => reject(new Error('Timeout waiting for response')), 5000);
        });
        
        console.log(`📨 Received handshake message 2: ${response.length} bytes`);
        
        // Process second handshake message
        const result = noise.readMessageB(new Uint8Array(response));
        console.log(`📝 Server payload: ${result ? new TextDecoder().decode(result) : '(empty)'}`);
        
        if (noise.handshakeComplete) {
            console.log('✅ Handshake completed successfully!');
            console.log(`🔑 Final handshake hash: ${Array.from(noise.getHandshakeHash()).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        } else {
            console.log('❌ Handshake not complete');
        }
        
        // Close connection immediately after handshake
        socket.end();
        console.log('🔌 Connection closed (handshake-only test)');
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        process.exit(1);
    }
}

testHandshakeOnly();
EOF

echo "📱 Running handshake-only client..."

# Run handshake-only client
cd sdk/javascript
node handshake_test_client.js > ../../logs/client_handshake.log 2>&1
CLIENT_EXIT_CODE=$?
cd ../..

# Wait a moment for any final server output
sleep 2

echo ""
echo "📊 Handshake Test Results"
echo "========================="

echo ""
echo "🐍 Python Server Output:"
echo "------------------------"
cat logs/server_handshake.log

echo ""
echo "🟨 JavaScript Client Output:"
echo "----------------------------"
cat logs/client_handshake.log

echo ""
echo "📈 Summary:"
echo "----------"
if [ $CLIENT_EXIT_CODE -eq 0 ]; then
    echo "✅ Client completed successfully"
else
    echo "❌ Client failed with exit code: $CLIENT_EXIT_CODE"
fi

if kill -0 $SERVER_PID 2>/dev/null; then
    echo "✅ Server is still running"
else
    echo "⚠️  Server has stopped"
fi

# Check for handshake completion
if grep -q "✅ Handshake completed successfully" logs/client_handshake.log; then
    echo "✅ Handshake completed successfully"
else
    echo "❌ Handshake failed or incomplete"
fi

# Clean up test file
rm -f handshake_test_client.js

echo ""
echo "📝 Log files saved to:"
echo "   - logs/server_handshake.log"
echo "   - logs/client_handshake.log" 