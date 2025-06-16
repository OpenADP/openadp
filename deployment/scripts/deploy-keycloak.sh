#!/bin/bash

# Deploy Keycloak to OpenADP servers
# Usage: ./deploy-keycloak.sh [server]

set -e

# Configuration
KEYCLOAK_SERVER="bill@xyzzy"  # Default to xyzzy server
PROJECT_DIR="~/projects/openadp"
KEYCLOAK_DIR="prototype/deployment/keycloak"

# Parse command line arguments
if [ $# -gt 0 ]; then
    KEYCLOAK_SERVER="$1"
fi

echo "🚀 Deploying Keycloak to $KEYCLOAK_SERVER"
echo "============================================"

# Check if server is reachable
if ! ssh -o ConnectTimeout=5 "$KEYCLOAK_SERVER" "echo 'Server reachable'" >/dev/null 2>&1; then
    echo "❌ Cannot connect to $KEYCLOAK_SERVER"
    echo "   Make sure SSH is configured and the server is running"
    exit 1
fi

echo "✅ Server $KEYCLOAK_SERVER is reachable"

# Sync the project to the server
echo "📦 Syncing project files..."
rsync -avz --delete \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.env' \
    --exclude='venv' \
    --exclude='.venv' \
    ./ "$KEYCLOAK_SERVER:$PROJECT_DIR/"

echo "✅ Project files synced"

# Deploy Keycloak
echo "🔧 Deploying Keycloak..."
ssh "$KEYCLOAK_SERVER" << 'EOF'
    set -e
    cd ~/projects/openadp/prototype/deployment/keycloak
    
    echo "📍 Current directory: $(pwd)"
    echo "📁 Available files:"
    ls -la
    
    # Make setup script executable
    chmod +x setup-keycloak.sh
    
    # Run the setup
    echo "🚀 Running Keycloak setup..."
    ./setup-keycloak.sh
    
    echo "✅ Keycloak deployment complete!"
EOF

echo ""
echo "🎉 Keycloak Deployment Complete!"
echo "================================="
echo "🌐 Server: $KEYCLOAK_SERVER"
echo "🔗 Local URL: http://$KEYCLOAK_SERVER:8081"
echo "🌍 Public URL: https://auth.openadp.org (if Cloudflare tunnel configured)"
echo ""
echo "📋 Next Steps:"
echo "1. Access the admin console and configure the 'openadp' realm"
echo "2. Create the 'cli-test' client with DPoP support"
echo "3. Test authentication with OpenADP tools"
echo ""
echo "🔧 Useful Commands:"
echo "   SSH to server: ssh $KEYCLOAK_SERVER"
echo "   View logs: ssh $KEYCLOAK_SERVER 'cd ~/projects/openadp/prototype/deployment/keycloak && docker-compose -f docker-compose.keycloak.yml logs -f'"
echo "   Restart: ssh $KEYCLOAK_SERVER 'cd ~/projects/openadp/prototype/deployment/keycloak && docker-compose -f docker-compose.keycloak.yml restart'" 