#!/bin/bash

# Test script for Noise-NK communication between JavaScript client and Python server
# This script runs both components and captures their output for analysis

set -e

echo "🧪 Noise-NK Communication Test"
echo "=============================="

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
python3 noise_server.py > ../../logs/server.log 2>&1 &
SERVER_PID=$!
cd ../..

# Wait for server to start
echo "⏳ Waiting for server to initialize..."
sleep 3

# Check if server is still running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ Server failed to start!"
    echo "📄 Server log:"
    cat logs/server.log
    exit 1
fi

echo "🚀 Server started (PID: $SERVER_PID)"
echo "📱 Starting JavaScript client..."

# Run JavaScript client
cd sdk/javascript
node noise_client.js > ../../logs/client.log 2>&1
CLIENT_EXIT_CODE=$?
cd ../..

# Wait a moment for any final server output
sleep 2

echo ""
echo "📊 Test Results"
echo "==============="

echo ""
echo "🐍 Python Server Output:"
echo "------------------------"
cat logs/server.log

echo ""
echo "🟨 JavaScript Client Output:"
echo "----------------------------"
cat logs/client.log

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

# Check for key indicators of success
if grep -q "✅ Noise-NK handshake completed" logs/server.log; then
    echo "✅ Handshake completed successfully"
else
    echo "❌ Handshake failed or incomplete"
fi

if grep -q "TRANSPORT ENCRYPT" logs/client.log && grep -q "TRANSPORT DECRYPT" logs/server.log; then
    echo "✅ Transport encryption/decryption attempted"
else
    echo "⚠️  Transport encryption/decryption not detected"
fi

echo ""
echo "📝 Log files saved to:"
echo "   - logs/server.log"
echo "   - logs/client.log" 