#!/bin/bash
# OpenADP Server Installation Script (Universal)
# This script automatically detects the OS and installs the OpenADP JSON-RPC server

set -e

# Configuration
INSTALL_DIR="/opt/openadp"
SERVICE_USER="openadp"
SERVICE_GROUP="openadp"
# Navigate from deployment/scripts/ back to project root
SOURCE_DIR="$(dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")"

echo "=== OpenADP Server Installation ==="
echo "Source directory: $SOURCE_DIR"
echo "Install directory: $INSTALL_DIR"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

# Detect OS and set package manager
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    echo "Detected OS: $OS ($PRETTY_NAME)"
else
    echo "Cannot detect OS. /etc/os-release not found."
    exit 1
fi

# Set package manager and minimal system packages based on OS
case $OS in
    ubuntu|debian|raspbian)
        PKG_UPDATE="apt-get update"
        PKG_INSTALL="apt-get install -y"
        SYSTEM_PKGS="python3 python3-venv python3-pip sqlite3 build-essential libffi-dev libssl-dev"
        ;;
    fedora|rhel|centos|rocky|almalinux)
        PKG_UPDATE="dnf update -y"
        PKG_INSTALL="dnf install -y"
        SYSTEM_PKGS="python3 python3-venv python3-pip sqlite gcc openssl-devel libffi-devel"
        ;;
    opensuse*|sles)
        PKG_UPDATE="zypper refresh"
        PKG_INSTALL="zypper install -y"
        SYSTEM_PKGS="python3 python3-venv python3-pip sqlite3 gcc libopenssl-devel libffi-devel"
        ;;
    arch|manjaro)
        PKG_UPDATE="pacman -Sy"
        PKG_INSTALL="pacman -S --noconfirm"
        SYSTEM_PKGS="python python-virtualenv python-pip sqlite gcc openssl libffi base-devel"
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "Supported: Ubuntu, Debian, Raspbian, Fedora, RHEL, CentOS, Rocky, AlmaLinux, openSUSE, SLES, Arch, Manjaro"
        exit 1
        ;;
esac

echo "Using package manager: ${PKG_INSTALL%% *}"

# Install minimal system dependencies (only what's needed for Python compilation and basic functionality)
echo "Installing minimal system dependencies..."
echo "Running: $PKG_UPDATE"
$PKG_UPDATE

echo "Installing system packages: $SYSTEM_PKGS"
$PKG_INSTALL $SYSTEM_PKGS

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

# Copy files from the new directory structure
echo "Copying OpenADP files..."
# Remove old directories to ensure a clean install
if [ -d "$INSTALL_DIR/openadp" ]; then rm -rf "$INSTALL_DIR/openadp"; fi
if [ -d "$INSTALL_DIR/server" ]; then rm -rf "$INSTALL_DIR/server"; fi
if [ -d "$INSTALL_DIR/client" ]; then rm -rf "$INSTALL_DIR/client"; fi
if [ -d "$INSTALL_DIR/proto" ]; then rm -rf "$INSTALL_DIR/proto"; fi
if [ -d "$INSTALL_DIR/tools" ]; then rm -rf "$INSTALL_DIR/tools"; fi
if [ -d "$INSTALL_DIR/api" ]; then rm -rf "$INSTALL_DIR/api"; fi

# Copy the necessary directories
cp -r "$SOURCE_DIR/openadp" "$INSTALL_DIR/"
cp -r "$SOURCE_DIR/server" "$INSTALL_DIR/"
cp -r "$SOURCE_DIR/client" "$INSTALL_DIR/" 2>/dev/null || echo "Note: client directory not found, skipping"
cp -r "$SOURCE_DIR/proto" "$INSTALL_DIR/" 2>/dev/null || echo "Note: proto directory not found, skipping"
cp -r "$SOURCE_DIR/tools" "$INSTALL_DIR/" 2>/dev/null || echo "Note: tools directory not found, skipping"
cp -r "$SOURCE_DIR/api" "$INSTALL_DIR/" 2>/dev/null || echo "Note: api directory not found, skipping"
cp "$SOURCE_DIR/run_server.py" "$INSTALL_DIR/" 2>/dev/null || echo "Note: run_server.py not found, skipping"

# Set permissions
echo "Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chmod -R 750 "$INSTALL_DIR"
find "$INSTALL_DIR" -type f -name "*.py" -exec chmod 640 {} \;
# Make main server scripts executable
find "$INSTALL_DIR" -name "jsonrpc_server.py" -exec chmod +x {} \;
find "$INSTALL_DIR" -name "run_server.py" -exec chmod +x {} \;
find "$INSTALL_DIR" -name "encrypt.py" -exec chmod +x {} \; 2>/dev/null || true
find "$INSTALL_DIR" -name "decrypt.py" -exec chmod +x {} \; 2>/dev/null || true

# Create and configure Python virtual environment
echo "Creating Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/venv"
# Explicitly make pip and python executable
chmod +x "$INSTALL_DIR/venv/bin/pip"
chmod +x "$INSTALL_DIR/venv/bin/python"

# Copy requirements file and install Python dependencies
echo "Installing Python dependencies into virtual environment..."
if [ -f "$SOURCE_DIR/requirements.txt" ]; then
    cp "$SOURCE_DIR/requirements.txt" "$INSTALL_DIR/"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/requirements.txt"
    echo "Installing dependencies from requirements.txt..."
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
else
    echo "Warning: requirements.txt not found. Installing basic dependencies..."
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install cryptography requests dissononce PyNaCl
fi

# Install systemd service
echo "Installing systemd service..."
if [ -f "$SOURCE_DIR/deployment/systemd/openadp-server.service" ]; then
    cp "$SOURCE_DIR/deployment/systemd/openadp-server.service" /etc/systemd/system/
    echo "Installed systemd service file"
else
    echo "Warning: systemd service file not found at $SOURCE_DIR/deployment/systemd/openadp-server.service"
fi

if [ -f "$SOURCE_DIR/deployment/systemd/openadp-server.conf" ]; then
    cp "$SOURCE_DIR/deployment/systemd/openadp-server.conf" "$INSTALL_DIR/"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/openadp-server.conf"
fi

systemctl daemon-reload

echo "=== Installation Complete ==="
echo ""
echo "OS: $PRETTY_NAME"
echo "Package manager: ${PKG_INSTALL%% *}"
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
echo "Service configuration: $INSTALL_DIR/openadp-server.conf"
echo "Python virtual environment: $INSTALL_DIR/venv" 
