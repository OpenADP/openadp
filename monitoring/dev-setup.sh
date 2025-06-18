#!/bin/bash

# OpenADP Health Monitoring - Development Setup
# Quick setup for development and testing

set -e

echo "🔧 OpenADP Health Monitoring - Development Setup"
echo "================================================"

# Check if we're in the right directory
if [ ! -f "cloudflare-worker.js" ]; then
    echo "❌ Error: Please run this script from the monitoring/ directory"
    exit 1
fi

# Install wrangler if not present
if ! command -v wrangler >/dev/null 2>&1; then
    echo "📦 Installing Wrangler CLI..."
    npm install -g wrangler
fi

# Check authentication
echo "🔐 Checking Cloudflare authentication..."
if ! wrangler whoami >/dev/null 2>&1; then
    echo "🌐 Please authenticate with Cloudflare..."
    wrangler auth login
fi

echo "✅ Ready for deployment!"
echo ""
echo "Next steps:"
echo "1. Run './deploy.sh' for full deployment"
echo "2. Or run 'wrangler dev' for local development"
echo "3. Or run 'wrangler deploy' for quick deployment (you'll need to configure KV and secrets manually)" 