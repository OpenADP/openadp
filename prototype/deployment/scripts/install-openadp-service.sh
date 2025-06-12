#!/bin/bash
# OpenADP Server Installation Script
# This script installs the OpenADP JSON-RPC server as a systemd service

set -e

# Configuration
INSTALL_DIR="/opt/openadp"
SERVICE_USER="openadp"
SERVICE_GROUP="openadp"
# Correctly set the source directory to be the 'prototype' directory
SOURCE_DIR=$(dirname "$(readlink -f "$0")")/../../

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

# Copy files from the correct 'prototype/src' location
echo "Copying OpenADP files..."
# Remove old directories to ensure a clean install
if [ -d "$INSTALL_DIR/src" ]; then rm -rf "$INSTALL_DIR/src"; fi
# Copy the entire src directory
cp -r "$SOURCE_DIR/src" "$INSTALL_DIR/"

# Set permissions
echo "Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chmod -R 750 "$INSTALL_DIR"
find "$INSTALL_DIR" -type f -exec chmod 640 {} \;
chmod +x "$INSTALL_DIR/src/server/jsonrpc_server.py"

# Create and own the virtual environment
echo "Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/venv"
# Explicitly make pip and python executable
chmod +x "$INSTALL_DIR/venv/bin/pip"
chmod +x "$INSTALL_DIR/venv/bin/python"

# Install systemd service
echo "Installing systemd service..."
cp "$SOURCE_DIR/deployment/systemd/openadp-server.service" /etc/systemd/system/
# The conf file is not used by the service, but we'll copy it for completeness
cp "$SOURCE_DIR/deployment/systemd/openadp-server.conf" "$INSTALL_DIR/"
systemctl daemon-reload

# Copy requirements file and set permissions
cp "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/"
chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/requirements.txt"

# Install dependencies from requirements.txt as the service user
echo "Installing Python dependencies into virtual environment..."
if [ -f "$INSTALL_DIR/requirements.txt" ]; then
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
else
    echo "Warning: requirements.txt not found. Skipping dependency installation."
fi


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
echo "Service runs on port 4433" 
