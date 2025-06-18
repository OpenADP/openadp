#!/bin/bash

# OpenADP Health Monitoring System Deployment Script
# This script automates the deployment of the health monitoring system to Cloudflare Workers

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ASCII Art Banner
echo -e "${BLUE}"
cat << "EOF"
   ____                   _____  _____  _____  
  / __ \                 |  _  ||  _  ||  _  | 
 | |  | |_ __   ___ _ __ | |_| || |_| || |_| | 
 | |  | | '_ \ / _ \ '_ \|  _  ||  _  ||  _  | 
 | |__| | |_) |  __/ | | | | | || | | || | | | 
  \____/| .__/ \___|_| |_|_| |_||_| |_||_| |_| 
        | |                                   
        |_|   Health Monitoring Deployment    
EOF
echo -e "${NC}"

echo -e "${GREEN}🚀 OpenADP Health Monitoring System Deployment${NC}"
echo "=============================================="
echo ""

# Check if we're in the right directory
if [ ! -f "cloudflare-worker.js" ]; then
    echo -e "${RED}❌ Error: Please run this script from the monitoring/ directory${NC}"
    echo "Expected files: cloudflare-worker.js, wrangler.toml"
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to prompt for user input
prompt_user() {
    local prompt="$1"
    local var_name="$2"
    local is_secret="${3:-false}"
    
    echo -e "${YELLOW}$prompt${NC}"
    if [ "$is_secret" = "true" ]; then
        read -s value
        echo ""  # Add newline after secret input
    else
        read value
    fi
    
    if [ -z "$value" ]; then
        echo -e "${RED}❌ Error: Value cannot be empty${NC}"
        exit 1
    fi
    
    eval "$var_name='$value'"
}

# Function to run command with status
run_command() {
    local description="$1"
    local command="$2"
    
    echo -e "${BLUE}🔄 $description...${NC}"
    if eval "$command"; then
        echo -e "${GREEN}✅ $description completed${NC}"
    else
        echo -e "${RED}❌ $description failed${NC}"
        exit 1
    fi
    echo ""
}

# Step 1: Check Prerequisites
echo -e "${BLUE}📋 Step 1: Checking Prerequisites${NC}"
echo "=================================="

# Check for Node.js
if ! command_exists node; then
    echo -e "${RED}❌ Node.js is not installed${NC}"
    echo "Please install Node.js from https://nodejs.org/"
    exit 1
fi
echo -e "${GREEN}✅ Node.js found: $(node --version)${NC}"

# Check for npm
if ! command_exists npm; then
    echo -e "${RED}❌ npm is not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✅ npm found: $(npm --version)${NC}"

# Check for wrangler
if ! command_exists wrangler; then
    echo -e "${YELLOW}⚠️  Wrangler CLI not found. Installing...${NC}"
    run_command "Installing Wrangler CLI" "npm install -g wrangler"
else
    echo -e "${GREEN}✅ Wrangler CLI found: $(wrangler --version)${NC}"
fi

# Check for git
if ! command_exists git; then
    echo -e "${RED}❌ Git is not installed${NC}"
    echo "Please install Git from https://git-scm.com/"
    exit 1
fi
echo -e "${GREEN}✅ Git found: $(git --version)${NC}"

echo ""

# Step 2: Cloudflare Authentication
echo -e "${BLUE}🔐 Step 2: Cloudflare Authentication${NC}"
echo "===================================="

echo "Checking Cloudflare authentication..."
if wrangler whoami >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Already authenticated with Cloudflare${NC}"
    echo "Current user: $(wrangler whoami)"
else
    echo -e "${YELLOW}⚠️  Not authenticated with Cloudflare${NC}"
    echo "Opening browser for authentication..."
    run_command "Authenticating with Cloudflare" "wrangler auth login"
fi

echo ""

# Step 3: Create KV Namespaces
echo -e "${BLUE}🗄️  Step 3: Creating KV Namespaces${NC}"
echo "=================================="

echo "Creating KV namespace for health data..."
KV_OUTPUT=$(wrangler kv:namespace create "HEALTH_DATA" 2>/dev/null || true)
if [ $? -eq 0 ]; then
    PROD_KV_ID=$(echo "$KV_OUTPUT" | grep -o 'id = "[^"]*"' | cut -d'"' -f2)
    echo -e "${GREEN}✅ Production KV namespace created: $PROD_KV_ID${NC}"
else
    echo -e "${YELLOW}⚠️  Production KV namespace might already exist${NC}"
    echo "Please check your Cloudflare dashboard for the namespace ID"
    prompt_user "Enter your production KV namespace ID:" "PROD_KV_ID"
fi

echo "Creating preview KV namespace..."
PREVIEW_KV_OUTPUT=$(wrangler kv:namespace create "HEALTH_DATA" --preview 2>/dev/null || true)
if [ $? -eq 0 ]; then
    PREVIEW_KV_ID=$(echo "$PREVIEW_KV_OUTPUT" | grep -o 'id = "[^"]*"' | cut -d'"' -f2)
    echo -e "${GREEN}✅ Preview KV namespace created: $PREVIEW_KV_ID${NC}"
else
    echo -e "${YELLOW}⚠️  Preview KV namespace might already exist${NC}"
    echo "Please check your Cloudflare dashboard for the preview namespace ID"
    prompt_user "Enter your preview KV namespace ID:" "PREVIEW_KV_ID"
fi

# Update wrangler.toml with KV IDs
echo "Updating wrangler.toml with KV namespace IDs..."
sed -i.bak "s/id = \"your-kv-namespace-id\"/id = \"$PROD_KV_ID\"/" wrangler.toml
sed -i.bak "s/preview_id = \"your-preview-kv-namespace-id\"/preview_id = \"$PREVIEW_KV_ID\"/" wrangler.toml
echo -e "${GREEN}✅ wrangler.toml updated with KV namespace IDs${NC}"

echo ""

# Step 4: Configure Secrets
echo -e "${BLUE}🔑 Step 4: Configuring Secrets${NC}"
echo "==============================="

echo "You'll need to provide two secrets for the monitoring system:"
echo "1. GitHub Personal Access Token (for committing health data)"
echo "2. Discord Webhook URL (for alerts)"
echo ""

# GitHub Token
echo -e "${YELLOW}GitHub Personal Access Token:${NC}"
echo "- Go to https://github.com/settings/tokens"
echo "- Create a new token with 'repo' scope"
echo "- Copy the token (it won't be shown again)"
echo ""
prompt_user "Enter your GitHub Personal Access Token:" "GITHUB_TOKEN" true

echo "Setting GitHub token..."
echo "$GITHUB_TOKEN" | wrangler secret put GITHUB_TOKEN
echo -e "${GREEN}✅ GitHub token configured${NC}"

echo ""

# Discord Webhook
echo -e "${YELLOW}Discord Webhook URL:${NC}"
echo "- Go to your Discord server settings"
echo "- Navigate to Integrations → Webhooks"
echo "- Create New Webhook or use existing one"
echo "- Copy the Webhook URL"
echo ""
prompt_user "Enter your Discord Webhook URL:" "DISCORD_WEBHOOK_URL"

echo "Setting Discord webhook..."
echo "$DISCORD_WEBHOOK_URL" | wrangler secret put DISCORD_WEBHOOK_URL
echo -e "${GREEN}✅ Discord webhook configured${NC}"

echo ""

# Step 5: Deploy Worker
echo -e "${BLUE}🚀 Step 5: Deploying Worker${NC}"
echo "============================"

run_command "Deploying OpenADP Health Monitor to Cloudflare" "wrangler deploy"

# Get worker URL
WORKER_URL=$(wrangler deploy --dry-run 2>/dev/null | grep -o 'https://[^/]*\.workers\.dev' || echo "your-worker.workers.dev")
echo -e "${GREEN}✅ Worker deployed successfully!${NC}"
echo -e "${BLUE}Worker URL: $WORKER_URL${NC}"

echo ""

# Step 6: Test Deployment
echo -e "${BLUE}🧪 Step 6: Testing Deployment${NC}"
echo "=============================="

echo "Testing worker endpoints..."

# Test trigger endpoint
echo "Testing manual health check..."
if curl -s -f "$WORKER_URL/health/trigger-check" >/dev/null; then
    echo -e "${GREEN}✅ Manual health check endpoint working${NC}"
else
    echo -e "${YELLOW}⚠️  Manual health check endpoint not responding (this is normal if no servers are configured yet)${NC}"
fi

# Test health endpoint
echo "Testing health endpoint..."
if curl -s -f "$WORKER_URL/health" >/dev/null; then
    echo -e "${GREEN}✅ Health endpoint working${NC}"
else
    echo -e "${YELLOW}⚠️  Health endpoint not responding (this is normal if no data exists yet)${NC}"
fi

echo ""

# Step 7: Next Steps
echo -e "${BLUE}📋 Step 7: Next Steps${NC}"
echo "====================="

echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
echo ""
echo "Your OpenADP Health Monitoring System is now deployed:"
echo -e "${BLUE}• Worker URL: $WORKER_URL${NC}"
echo -e "${BLUE}• Health Dashboard: $WORKER_URL/health${NC}"
echo -e "${BLUE}• Server List: $WORKER_URL/health/servers${NC}"
echo ""

echo -e "${YELLOW}Next steps to complete setup:${NC}"
echo "1. Configure your servers.json with actual OpenADP server URLs"
echo "2. Wait 5-10 minutes for first health check to run"
echo "3. Visit the health dashboard to verify data collection"
echo "4. Set up custom domain (optional): health.openadp.org"
echo "5. Deploy the dashboard HTML to your website"
echo ""

echo -e "${YELLOW}Useful commands:${NC}"
echo "• View logs: wrangler tail"
echo "• Update worker: wrangler deploy"
echo "• Check KV data: wrangler kv:key list --binding=HEALTH_DATA"
echo "• Manual health check: curl $WORKER_URL/health/trigger-check"
echo ""

echo -e "${GREEN}🚀 OpenADP Health Monitoring System is ready!${NC}"

# Save deployment info
cat > deployment-info.txt << EOF
OpenADP Health Monitoring Deployment Info
==========================================

Deployment Date: $(date)
Worker URL: $WORKER_URL
Production KV ID: $PROD_KV_ID
Preview KV ID: $PREVIEW_KV_ID

Endpoints:
- Health Check: $WORKER_URL/health
- Server List: $WORKER_URL/health/servers  
- History: $WORKER_URL/health/history?hours=24
- Manual Trigger: $WORKER_URL/health/trigger-check

Next Steps:
1. Configure servers.json with actual server URLs
2. Wait for first health check (5-10 minutes)
3. Set up custom domain (optional)
4. Deploy dashboard to website
EOF

echo -e "${BLUE}📄 Deployment info saved to deployment-info.txt${NC}" 