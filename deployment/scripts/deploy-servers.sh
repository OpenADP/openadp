#!/bin/bash

# OpenADP Go Server Deployment Script
# This script automates the deployment process across multiple servers using the update script

# Note: Removed 'set -e' to allow proper error handling in loops

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SERVERS=("bill@xyzzy" "bill@sky" "bill@minime")
PROJECT_DIR="~/projects/openadp"
UPDATE_SCRIPT="scripts/update-openadp-node.sh"

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

print_banner() {
    echo -e "${BLUE}"
    echo "================================================================="
    echo "             OpenADP Multi-Server Deployment"
    echo "================================================================="
    echo -e "${NC}"
}

# Function to deploy to a single server
deploy_to_server() {
    local server=$1
    echo ""
    log_step "Deploying Go Server to $server"

    # Using a heredoc to run all commands in a single SSH session.
    # This should make sudo ask for a password only once per server.
    if ssh -t "$server" <<ENDSSH
        set -e
        echo "Connected to $server"
        
        # Change to project directory
        cd $PROJECT_DIR
        
        # Make sure we have the latest deployment scripts
        echo "Updating deployment scripts from git..."
        git fetch origin
        git checkout main
        git pull origin main
        
        # Use the standardized update script with minimal flags
        echo "Running OpenADP update script..."
        sudo $UPDATE_SCRIPT --verbose
        
        # Quick health check
        echo "Testing server health..."
        sleep 3
        curl -s http://localhost:8080/health | jq . || echo "Health check failed or jq not available"
        
        # Test Echo method
        echo "Testing Echo method..."
        curl -s -H "Content-Type: application/json" \
             -d '{"jsonrpc":"2.0","method":"Echo","params":["Deployment test from update script"],"id":1}' \
             http://localhost:8080 | jq . || echo "Echo test failed or jq not available"
        
        # Show version
        echo "Server version:"
        sudo -u openadp /opt/openadp/bin/openadp-server -version || echo "Version check failed"
        
        # Show current service status
        echo "Service status:"
        sudo systemctl status openadp-server --no-pager -l || true
        
        # Show recent logs
        echo "Recent logs (last 20 lines):"
        sudo journalctl -u openadp-server -n 20 --no-pager
ENDSSH
    then
        log_info "✅ Successfully deployed to $server"
        echo ""
        echo -n "Press Enter to continue to next server, or Ctrl+C to abort..."
        read -r
        echo ""
        return 0
    else
        log_error "❌ Deployment to $server failed"
        echo ""
        echo -n "Continue to next server anyway? Press Enter to continue, or Ctrl+C to abort..."
        read -r
        echo ""
        return 1
    fi
}

# Main execution
main() {
    print_banner
    
    log_info "Starting deployment to ${#SERVERS[@]} servers"
    log_info "Using update script: $UPDATE_SCRIPT"
    log_warn "Each server will be updated using the standardized update script"
    echo ""
    
    # Confirm before proceeding
    read -p "This will update all servers with the latest code and restart services. Continue? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Deployment cancelled by user"
        exit 0
    fi
    
    # Deploy to each server
    local successful=0
    local failed=0
    
    for server in "${SERVERS[@]}"; do
        if deploy_to_server "$server"; then
            ((successful++))
        else
            ((failed++))
        fi
    done
    
    # Summary
    echo ""
    log_step "Deployment Summary"
    echo "Servers processed: ${#SERVERS[@]}"
    echo "Successful: $successful"
    echo "Failed: $failed"
    
    if [ $failed -eq 0 ]; then
        log_info "🎉 All servers deployed successfully!"
    else
        log_warn "⚠️  $failed server(s) had deployment issues"
    fi
    
    echo ""
    log_info "Post-deployment commands:"
    echo "Check server status:   ssh <server> 'sudo systemctl status openadp-server'"
    echo "View logs:            ssh <server> 'sudo journalctl -u openadp-server -f'"
    echo "Test health endpoint:  curl -s http://<server>:8080/health"
    echo "Test Echo method:     curl -s -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"Echo\",\"params\":[\"test\"],\"id\":1}' http://<server>:8080"
}

# Run main function
main "$@" 
