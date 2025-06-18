#!/bin/bash

# OpenADP Health Monitoring - Configuration Helper
# Helps set up GitHub and Discord integration

echo "🔧 OpenADP Health Monitoring - Configuration Helper"
echo "==================================================="
echo ""

echo "This script will help you gather the required configuration for the monitoring system."
echo ""

# GitHub Token Instructions
echo "📋 1. GitHub Personal Access Token"
echo "=================================="
echo ""
echo "You need a GitHub Personal Access Token to automatically commit health data."
echo ""
echo "Steps to create one:"
echo "1. Go to: https://github.com/settings/tokens"
echo "2. Click 'Generate new token' → 'Generate new token (classic)'"
echo "3. Give it a descriptive name like 'OpenADP Health Monitoring'"
echo "4. Set expiration (recommend 'No expiration' for production)"
echo "5. Select scopes: Check 'repo' (Full control of private repositories)"
echo "6. Click 'Generate token'"
echo "7. IMPORTANT: Copy the token immediately (you won't see it again!)"
echo ""
echo "Keep this token safe - you'll need it during deployment."
echo ""

# Discord Webhook Instructions  
echo "📋 2. Discord Webhook URL"
echo "========================="
echo ""
echo "You need a Discord webhook to receive monitoring alerts."
echo ""
echo "Steps to create one:"
echo "1. Go to your Discord server"
echo "2. Right-click on the channel where you want alerts"
echo "3. Select 'Edit Channel'"
echo "4. Go to 'Integrations' tab"
echo "5. Click 'Webhooks' → 'Create Webhook'"
echo "6. Give it a name like 'OpenADP Health Monitor'"
echo "7. Optionally change the avatar"
echo "8. Copy the 'Webhook URL'"
echo ""
echo "Example webhook URL format:"
echo "https://discord.com/api/webhooks/123456789/abcdefghijklmnop"
echo ""

# Server Configuration
echo "📋 3. Server Configuration"
echo "=========================="
echo ""
echo "The monitoring system will check servers listed in the worker's configuration."
echo "You can configure servers in the cloudflare-worker.js file or use a dynamic"
echo "servers.json file that gets committed to GitHub."
echo ""
echo "Example servers.json format:"
echo '{'
echo '  "servers": ['
echo '    {'
echo '      "url": "https://server1.example.com:8080",'
echo '      "name": "Server 1",'
echo '      "location": "US-East"'
echo '    },'
echo '    {'
echo '      "url": "https://server2.example.com:8080",'
echo '      "name": "Server 2",'
echo '      "location": "EU-West"'
echo '    }'
echo '  ]'
echo '}'
echo ""

# Summary
echo "📋 Summary"
echo "=========="
echo ""
echo "Before running the deployment script, make sure you have:"
echo "✓ GitHub Personal Access Token (with 'repo' scope)"
echo "✓ Discord Webhook URL"
echo "✓ List of OpenADP servers to monitor"
echo "✓ Cloudflare account (free tier is sufficient)"
echo ""
echo "Once you have these, run: ./deploy.sh"
echo ""
echo "For development/testing, you can run: ./dev-setup.sh" 