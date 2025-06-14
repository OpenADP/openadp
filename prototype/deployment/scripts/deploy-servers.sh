#!/bin/bash

# OpenADP Server Deployment Script
# This script automates the deployment process across multiple servers

set -e

# Configuration
SERVERS=("bill@xyzzy" "bill@sky" "bill@minime")
PROJECT_DIR="~/projects/openadp/prototype"
# Note: This path is relative to the PROJECT_DIR on the remote server
INSTALL_SCRIPT="deployment/scripts/install-openadp-service.sh"

# Function to deploy to a single server
deploy_to_server() {
    local server=$1
    echo "=== Deploying to $server ==="

    # Using a heredoc to run all commands in a single SSH session.
    # This should make sudo ask for a password only once per server.
    ssh -t "$server" <<ENDSSH
        set -e
        echo "--> On $server:"
        
        # Change to project directory
        cd $PROJECT_DIR
        
        # Stop the service
        echo "Stopping OpenADP service..."
        sudo systemctl stop openadp-server || true
        
        # Update code and run installation
        echo "Updating code from git..."
        git pull
        echo "Running installation script..."
        sudo $INSTALL_SCRIPT
        
        # Start and enable service
        echo "Starting and enabling service..."
        sudo systemctl start openadp-server
        sudo systemctl enable openadp-server
        
        # Check service status
        echo "Checking service status..."
        # We use '|| true' because systemctl status returns a non-zero exit code
        # when the service is inactive, which would cause 'set -e' to exit.
        sudo systemctl status openadp-server || true
        
        # Show logs
        echo "Showing recent server logs..."
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

echo "=== Deployment Complete ===" 
