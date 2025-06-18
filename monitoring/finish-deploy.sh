#!/bin/bash

# Simple script to finish the OpenADP monitoring deployment
# Run this after authentication and KV namespaces are set up

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔑 Setting up Secrets${NC}"
echo "========================="

echo "You'll need to provide two secrets:"
echo "1. GitHub Personal Access Token (for committing health data)"
echo "2. Discord Webhook URL (for alerts)"
echo ""

echo -e "${YELLOW}GitHub Personal Access Token:${NC}"
echo "- Go to https://github.com/settings/tokens"
echo "- Create a new token with 'repo' scope"
echo "- Copy the token (it won't be shown again)"
echo ""
read -p "Enter your GitHub Personal Access Token: " -s GITHUB_TOKEN
echo ""

if [ -z "$GITHUB_TOKEN" ]; then
    echo -e "${RED}❌ Error: GitHub token cannot be empty${NC}"
    exit 1
fi

echo "Setting GitHub token..."
echo "$GITHUB_TOKEN" | ./node_modules/.bin/wrangler secret put GITHUB_TOKEN --env=""
echo -e "${GREEN}✅ GitHub token configured${NC}"

echo ""
echo -e "${YELLOW}Discord Webhook URL:${NC}"
echo "- Go to your Discord server settings"
echo "- Navigate to Integrations → Webhooks"
echo "- Create New Webhook or use existing one"
echo "- Copy the Webhook URL"
echo ""
read -p "Enter your Discord Webhook URL: " DISCORD_WEBHOOK_URL

if [ -z "$DISCORD_WEBHOOK_URL" ]; then
    echo -e "${RED}❌ Error: Discord webhook URL cannot be empty${NC}"
    exit 1
fi

echo "Setting Discord webhook..."
echo "$DISCORD_WEBHOOK_URL" | ./node_modules/.bin/wrangler secret put DISCORD_WEBHOOK_URL --env=""
echo -e "${GREEN}✅ Discord webhook configured${NC}"

echo ""
echo -e "${GREEN}🚀 Deploying to Cloudflare${NC}"
echo "==========================="

./node_modules/.bin/wrangler deploy --env=""

echo ""
echo -e "${GREEN}✅ Deployment Complete!${NC}"
echo ""
echo "Your OpenADP Health Monitor is now running at:"
echo "https://openadp-health-monitor.your-subdomain.workers.dev"
echo ""
echo "Test it with:"
echo "curl https://openadp-health-monitor.your-subdomain.workers.dev/health/trigger-check" 