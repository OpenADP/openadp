#!/bin/bash

# OpenADP Go Server Deployment Script
# This script automates the deployment process across multiple servers

set -e

# Configuration
SERVERS=("bill@xyzzy" "bill@sky" "bill@minime")
PROJECT_DIR="~/projects/openadp"
# Note: This path is relative to the PROJECT_DIR on the remote server
INSTALL_SCRIPT="deployment/scripts/install-openadp-service.sh"

# Function to deploy to a single server
deploy_to_server() {
    local server=$1
    echo "=== Deploying Go Server to $server ==="

    # Using a heredoc to run all commands in a single SSH session.
    # This should make sudo ask for a password only once per server.
    ssh -t "$server" <<ENDSSH
        set -e
        echo "--> On $server:"
        
        # Change to project directory
        cd $PROJECT_DIR
        
        # Stop the service
        echo "Stopping OpenADP Go service..."
        sudo systemctl stop openadp-server || true
        
        # Update code and run installation
        echo "Updating code from git..."
        git pull
        echo "Running Go server installation script..."
        sudo $INSTALL_SCRIPT
        
        # Start and enable service
        echo "Starting and enabling Go service..."
        sudo systemctl start openadp-server
        sudo systemctl enable openadp-server
        
        # Wait a moment for service to start
        sleep 2
        
        # Check service status
        echo "Checking Go service status..."
        # We use '|| true' because systemctl status returns a non-zero exit code
        # when the service is inactive, which would cause 'set -e' to exit.
        sudo systemctl status openadp-server || true
        
        # Test the Go server health endpoint
        echo "Testing Go server health endpoint..."
        curl -s http://localhost:8080/health | jq . || echo "Health check failed or jq not available"
        
        # Test the Go server Echo method
        echo "Testing Go server Echo method..."
        curl -s -H "Content-Type: application/json" \
             -d '{"jsonrpc":"2.0","method":"Echo","params":["Deployment test"],"id":1}' \
             http://localhost:8080 | jq . || echo "Echo test failed or jq not available"
        
        # Show Go server version
        echo "Checking Go server version..."
        sudo -u openadp /opt/openadp/bin/openadp-server -version || true
        
        # Show recent server logs
        echo "Showing recent Go server logs..."
        sudo journalctl -u openadp-server -n 50 --no-pager
ENDSSH
    
    # After remote execution, pause for user confirmation
    echo ""
    read -p "Logs from $server are shown above. Press Enter to continue if logs look good, or Ctrl+C to abort..."
    echo ""
}

# Main deployment loop
for server in "${SERVERS[@]}"; do
    deploy_to_server "$server"
done

echo "=== Go Server Deployment Complete ===" 
echo ""
echo "All servers have been updated with the Go implementation!"
echo ""
echo "You can check server status with:"
echo "  ssh <server> 'sudo systemctl status openadp-server'"
echo ""
echo "You can view logs with:"
echo "  ssh <server> 'sudo journalctl -u openadp-server -f'"
echo ""
echo "You can test connectivity with:"
echo "  curl -s http://<server>:8080/health" 
