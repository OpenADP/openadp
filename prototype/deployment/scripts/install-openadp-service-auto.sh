#!/bin/bash
# OpenADP Server Installation Script (Auto-detect OS)
# This script automatically detects the OS and installs the OpenADP JSON-RPC server

set -e

# Configuration
INSTALL_DIR="/opt/openadp"
SERVICE_USER="openadp"
SERVICE_GROUP="openadp"
# Navigate from deployment/scripts/ back to prototype root
SOURCE_DIR="$(dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")"

echo "=== OpenADP Server Installation (Auto-detect) ==="
echo "Source directory: $SOURCE_DIR"
echo "Install directory: $INSTALL_DIR"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    echo "Detected OS: $OS ($PRETTY_NAME)"
else
    echo "Cannot detect OS. /etc/os-release not found."
    exit 1
fi

# Set package manager and package names based on OS
case $OS in
    ubuntu|debian|raspbian)
        PKG_MANAGER="apt-get"
        PKG_UPDATE="apt-get update"
        PKG_INSTALL="apt-get install -y"
        PYTHON_PKG="python3"
        SQLITE_PKG="sqlite3"
        CRYPTO_PKG="python3-cryptography"
        NOISE_PKG="python3-dissononce"
        ;;
    fedora|rhel|centos|rocky|almalinux)
        PKG_MANAGER="dnf"
        PKG_UPDATE="dnf update -y"
        PKG_INSTALL="dnf install -y"
        PYTHON_PKG="python3"
        SQLITE_PKG="sqlite"
        CRYPTO_PKG="python3-cryptography"
        NOISE_PKG="python3-pip"  # DissoNonce not in dnf repos, will pip install
        ;;
    opensuse*|sles)
        PKG_MANAGER="zypp"
        PKG_UPDATE="zypper refresh"
        PKG_INSTALL="zypper install -y"
        PYTHON_PKG="python3"
        SQLITE_PKG="sqlite3"
        CRYPTO_PKG="python3-cryptography"
        NOISE_PKG="python3-pip"  # DissoNonce not in zypper repos
        ;;
    arch|manjaro)
        PKG_MANAGER="pacman"
        PKG_UPDATE="pacman -Sy"
        PKG_INSTALL="pacman -S --noconfirm"
        PYTHON_PKG="python"
        SQLITE_PKG="sqlite"
        CRYPTO_PKG="python-cryptography"
        NOISE_PKG="python-pip"  # DissoNonce via pip
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "Supported: Ubuntu, Debian, Raspbian, Fedora, RHEL, CentOS, Rocky, AlmaLinux, openSUSE, SLES, Arch, Manjaro"
        exit 1
        ;;
esac

echo "Using package manager: $PKG_MANAGER"

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
cp -r "$SOURCE_DIR"/src "$INSTALL_DIR/"
cp -r "$SOURCE_DIR"/proto "$INSTALL_DIR/" 2>/dev/null || true
cp -r "$SOURCE_DIR"/tools "$INSTALL_DIR/" 2>/dev/null || true
cp "$SOURCE_DIR"/run_server.py "$INSTALL_DIR/"

# Set permissions
echo "Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
find "$INSTALL_DIR" -name "*.py" -exec chmod 644 {} \;
chmod +x "$INSTALL_DIR/run_server.py"
chmod +x "$INSTALL_DIR/tools/encrypt.py"
chmod +x "$INSTALL_DIR/tools/decrypt.py"

# Install systemd service
echo "Installing systemd service..."
cp "$SOURCE_DIR/deployment/systemd/openadp-server.service" /etc/systemd/system/
cp "$SOURCE_DIR/deployment/systemd/openadp-server.conf" "$INSTALL_DIR/"
systemctl daemon-reload

# Install dependencies
echo "Installing Python dependencies..."
echo "Running: $PKG_UPDATE"
$PKG_UPDATE

echo "Running: $PKG_INSTALL $PYTHON_PKG $SQLITE_PKG $CRYPTO_PKG $NOISE_PKG"
$PKG_INSTALL $PYTHON_PKG $SQLITE_PKG $CRYPTO_PKG $NOISE_PKG

# Install DissoNonce via pip for non-Debian systems
case $OS in
    ubuntu|debian|raspbian)
        echo "DissoNonce installed via apt package"
        ;;
    *)
        echo "Installing DissoNonce via pip..."
        pip3 install dissononce
        ;;
esac

echo "=== Installation Complete ==="
echo ""
echo "OS: $PRETTY_NAME"
echo "Package manager: $PKG_MANAGER"
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