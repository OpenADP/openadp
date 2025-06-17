#!/bin/bash
set -e

echo "🚀 Starting OpenADP Staging Node..."
echo "   (Authentication disabled for Phase 0 testing)"
echo ""

# Check if we're in the right directory
if [ ! -f "prototype/run_server.py" ]; then
    echo "❌ Error: Must run from project root directory"
    echo "   Expected to find prototype/run_server.py"
    exit 1
fi

# Change to prototype directory
cd prototype

# Check if database exists
if [ ! -f "openadp.db" ]; then
    echo "📦 Initializing new database..."
else
    echo "📦 Using existing database"
fi

# Check Python environment
if [ ! -d "../.venv" ]; then
    echo "⚠️  Warning: No .venv directory found. Make sure you have required packages installed:"
    echo "   pip install -r requirements.txt"
    echo ""
fi

echo "🌐 Starting server on http://localhost:8081"
echo "   (Note: Using port 8081 to avoid conflict with Keycloak on 8080)"
echo ""
echo "📋 Available endpoints:"
echo "   POST /  - JSON-RPC endpoint"
echo ""
echo "🧪 Test with curl:"
echo '   curl -H "Content-Type: application/json" \'
echo '        -d '"'"'{"jsonrpc":"2.0","method":"Echo","params":["Hello!"],"id":1}'"'"' \'
echo '        http://localhost:8081'
echo ""
echo "🛑 Press Ctrl+C to stop the server"
echo ""

# Modify the server to run on port 8081 instead of 8080
export OPENADP_PORT=8081

# Run the server
python3 run_server.py 