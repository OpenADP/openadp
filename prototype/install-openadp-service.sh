#!/bin/bash
# OpenADP Server Installation Script
# This script installs the OpenADP JSON-RPC server as a systemd service

set -e

# Configuration
INSTALL_DIR="/opt/openadp"
SERVICE_USER="openadp"
SERVICE_GROUP="openadp"
SOURCE_DIR="$(dirname "$(readlink -f "$0")")"

echo "=== OpenADP Server Installation ==="
echo "Source directory: $SOURCE_DIR"
echo "Install directory: $INSTALL_DIR"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

# Create service user and group
echo "Creating service user and group..."
if ! getent group "$SERVICE_GROUP" > /dev/null 2>&1; then
    groupadd --system "$SERVICE_GROUP"
    echo "Created group: $SERVICE_GROUP"
fi

if ! getent passwd "$SERVICE_USER" > /dev/null 2>&1; then
    useradd --system --gid "$SERVICE_GROUP" --home-dir "$INSTALL_DIR" \
            --shell /usr/sbin/nologin --comment "OpenADP Server" "$SERVICE_USER"
    echo "Created user: $SERVICE_USER"
fi

# Create installation directory
echo "Creating installation directory..."
mkdir -p "$INSTALL_DIR"

# Copy files
echo "Copying OpenADP files..."
cp "$SOURCE_DIR"/*.py "$INSTALL_DIR/"
cp "$SOURCE_DIR"/proto/*.proto "$INSTALL_DIR/" 2>/dev/null || true

# Set permissions
echo "Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
chmod 644 "$INSTALL_DIR"/*.py
chmod +x "$INSTALL_DIR/jsonrpc_server.py"

# Install systemd service
echo "Installing systemd service..."
cp "$SOURCE_DIR/openadp-server.service" /etc/systemd/system/
systemctl daemon-reload

# Install dependencies
echo "Installing Python dependencies..."
apt-get update
apt-get install -y python3 python3-pip sqlite3
pip3 install cryptography

echo "=== Installation Complete ==="
echo ""
echo "To start the service:"
echo "  sudo systemctl start openadp-server"
echo ""
echo "To enable auto-start on boot:"
echo "  sudo systemctl enable openadp-server"
echo ""
echo "To check service status:"
echo "  sudo systemctl status openadp-server"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u openadp-server -f"
echo ""
echo "Database location: $INSTALL_DIR/openadp.db"
echo "Service runs on port 8080" 