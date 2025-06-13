#!/bin/bash
set -e

echo "🚀 OpenADP Phase 0 - Complete Setup"
echo "===================================="
echo ""

# Step 1: Start Keycloak
echo "📦 Step 1: Starting Keycloak..."
docker-compose -f docker-compose.keycloak.yml up -d

# Wait for Keycloak to be ready
echo "⏳ Waiting for Keycloak to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:8080/health/ready > /dev/null 2>&1; then
        echo "✅ Keycloak is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Keycloak failed to start within 5 minutes"
        exit 1
    fi
    echo "   Attempt $i/30... (waiting 10s)"
    sleep 10
done

# Step 2: Configure Keycloak
echo ""
echo "🔧 Step 2: Configuring Keycloak..."
./scripts/setup-keycloak.sh

# Step 3: Check dependencies
echo ""
echo "🐍 Step 3: Checking Python dependencies..."
if ! python3 -c "import cryptography, jwt" 2>/dev/null; then
    echo "📦 Installing required Python packages..."
    pip install cryptography pyjwt
    echo "✅ Dependencies installed"
else
    echo "✅ Dependencies already installed"
fi

# Step 4: Display what to do next
echo ""
echo "🎉 Phase 0 setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Test PoP token generation:"
echo "   ./scripts/test-pop-token.py"
echo ""
echo "2. Launch staging OpenADP node (in another terminal):"
echo "   ./scripts/run-staging-node.sh"
echo ""
echo "3. Test staging node:"
echo '   curl -H "Content-Type: application/json" \'
echo '        -d '"'"'{"jsonrpc":"2.0","method":"Echo","params":["Hello!"],"id":1}'"'"' \'
echo '        http://localhost:8081'
echo ""
echo "🔗 Useful URLs:"
echo "   Keycloak Admin: http://localhost:8080/admin (admin/admin)"
echo "   OIDC Discovery: http://localhost:8080/realms/openadp/.well-known/openid-configuration"
echo ""
echo "📖 See PHASE-0-README.md for detailed instructions" 