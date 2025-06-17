#!/bin/bash
# OpenADP Go Server Installation Script (Universal)
# This script automatically detects the OS and installs the OpenADP Go JSON-RPC server

set -e

# Configuration
INSTALL_DIR="/opt/openadp"
SERVICE_USER="openadp"
SERVICE_GROUP="openadp"
# Navigate from deployment/scripts/ back to project root
SOURCE_DIR="$(dirname "$(dirname "$(dirname "$(readlink -f "$0")")")")"

echo "=== OpenADP Go Server Installation ==="
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
        SYSTEM_PKGS="wget gcc sqlite3"
        ;;
    fedora|rhel|centos|rocky|almalinux)
        PKG_UPDATE="dnf update -y"
        PKG_INSTALL="dnf install -y"
        SYSTEM_PKGS="wget gcc sqlite"
        ;;
    opensuse*|sles)
        PKG_UPDATE="zypper refresh"
        PKG_INSTALL="zypper install -y"
        SYSTEM_PKGS="wget gcc sqlite3"
        ;;
    arch|manjaro)
        PKG_UPDATE="pacman -Sy"
        PKG_INSTALL="pacman -S --noconfirm"
        SYSTEM_PKGS="wget gcc sqlite"
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "Supported: Ubuntu, Debian, Raspbian, Fedora, RHEL, CentOS, Rocky, AlmaLinux, openSUSE, SLES, Arch, Manjaro"
        exit 1
        ;;
esac

echo "Using package manager: ${PKG_INSTALL%% *}"

# Install minimal system dependencies (wget for Go download, C compiler for SQLite driver, SQLite database)
echo "Installing minimal dependencies for Go server..."
echo "Running: $PKG_UPDATE"
$PKG_UPDATE

echo "Installing system packages: $SYSTEM_PKGS"
$PKG_INSTALL $SYSTEM_PKGS

# Install modern Go version
echo "Installing Go 1.23.10..."
GO_VERSION="1.23.10"
GO_TARBALL="go${GO_VERSION}.linux-"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        GO_ARCH="amd64"
        ;;
    aarch64|arm64)
        GO_ARCH="arm64"
        ;;
    armv7l)
        GO_ARCH="armv6l"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

GO_TARBALL="${GO_TARBALL}${GO_ARCH}.tar.gz"
GO_URL="https://golang.org/dl/${GO_TARBALL}"

echo "Downloading Go ${GO_VERSION} for ${GO_ARCH}..."
cd /tmp
wget -O "$GO_TARBALL" "$GO_URL"

# Remove old Go installation and install new one
echo "Installing Go to /usr/local..."
rm -rf /usr/local/go
tar -C /usr/local -xzf "$GO_TARBALL"
rm "$GO_TARBALL"

# Set up Go environment
export PATH="/usr/local/go/bin:$PATH"
export GOPATH="/tmp/go-workspace"
export GOCACHE="/tmp/go-cache"

# Verify Go installation
echo "Verifying Go installation..."
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed or not in PATH"
    exit 1
fi

INSTALLED_GO_VERSION=$(go version)
echo "Go version: $INSTALLED_GO_VERSION"

# Create service user and group
echo "Creating service user and group..."
if ! getent group "$SERVICE_GROUP" > /dev/null 2>&1; then
    groupadd --system "$SERVICE_GROUP"
    echo "Created group: $SERVICE_GROUP"
fi

if ! getent passwd "$SERVICE_USER" > /dev/null 2>&1; then
    useradd --system --gid "$SERVICE_GROUP" --home-dir "$INSTALL_DIR" \
            --shell /usr/sbin/nologin --comment "OpenADP Go Server" "$SERVICE_USER"
    echo "Created user: $SERVICE_USER"
fi

# Create installation directory
echo "Creating installation directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$INSTALL_DIR/data"

# Copy source code for building
echo "Copying OpenADP source code..."
# Remove old directories to ensure a clean install
if [ -d "$INSTALL_DIR/src" ]; then rm -rf "$INSTALL_DIR/src"; fi

# Copy source code to build location
mkdir -p "$INSTALL_DIR/src"
cp -r "$SOURCE_DIR"/* "$INSTALL_DIR/src/" 2>/dev/null || true

# Set permissions for building (entire install directory, not just src)
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"

# Build the Go server binary
echo "Building OpenADP Go server..."
cd "$INSTALL_DIR/src"

# Build as the service user to avoid permission issues
sudo -u "$SERVICE_USER" bash -c "
    export PATH='/usr/local/go/bin:/usr/bin:/bin:\$PATH'
    export GOPATH=/tmp/go-build-$$
    export GOCACHE=/tmp/go-cache-$$
    /bin/mkdir -p \$GOPATH \$GOCACHE
    cd '$INSTALL_DIR/src'
    
    echo 'Downloading Go dependencies...'
    go mod download
    go mod tidy
    
    echo 'Building OpenADP server binary...'
    go build -o '$INSTALL_DIR/bin/openadp-server' -ldflags '-X main.version=1.0.0' ./cmd/openadp-server
    
    echo 'Building additional tools...'
    go build -o '$INSTALL_DIR/bin/openadp-encrypt' -ldflags '-X main.version=1.0.0' ./cmd/openadp-encrypt || echo 'Note: openadp-encrypt build failed, skipping'
    go build -o '$INSTALL_DIR/bin/openadp-decrypt' -ldflags '-X main.version=1.0.0' ./cmd/openadp-decrypt || echo 'Note: openadp-decrypt build failed, skipping'
    
    # Clean up build cache
    go clean -cache -modcache 2>/dev/null || true
    /bin/rm -rf \$GOPATH \$GOCACHE 2>/dev/null || true
"

# Verify the binary was built successfully
if [ ! -f "$INSTALL_DIR/bin/openadp-server" ]; then
    echo "ERROR: Failed to build openadp-server binary"
    exit 1
fi

echo "Successfully built OpenADP Go server binary"

# Test the binary
echo "Testing the built binary..."
sudo -u "$SERVICE_USER" "$INSTALL_DIR/bin/openadp-server" -version

# Copy configuration files
echo "Installing configuration files..."
if [ -f "$SOURCE_DIR/deployment/systemd/openadp-server.conf" ]; then
    cp "$SOURCE_DIR/deployment/systemd/openadp-server.conf" "$INSTALL_DIR/"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/openadp-server.conf"
    echo "Installed server configuration file"
fi

# Set final permissions
echo "Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
chmod -R 750 "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/bin/openadp-server"
chmod +x "$INSTALL_DIR/bin/openadp-encrypt" 2>/dev/null || true
chmod +x "$INSTALL_DIR/bin/openadp-decrypt" 2>/dev/null || true

# Set database directory permissions
chmod 755 "$INSTALL_DIR/data"

# Clean up source code (no longer needed after build)
echo "Cleaning up build artifacts..."
rm -rf "$INSTALL_DIR/src"

# Install systemd service
echo "Installing systemd service..."
if [ -f "$SOURCE_DIR/deployment/systemd/openadp-server.service" ]; then
    cp "$SOURCE_DIR/deployment/systemd/openadp-server.service" /etc/systemd/system/
    echo "Installed systemd service file"
else
    echo "Warning: systemd service file not found at $SOURCE_DIR/deployment/systemd/openadp-server.service"
fi

systemctl daemon-reload

echo "=== Installation Complete ==="
echo ""
echo "OS: $PRETTY_NAME"
echo "Go version: $INSTALLED_GO_VERSION"
echo "Package manager: ${PKG_INSTALL%% *}"
echo ""
echo "Installed files:"
echo "  Binary: $INSTALL_DIR/bin/openadp-server"
echo "  Configuration: $INSTALL_DIR/openadp-server.conf"
echo "  Database directory: $INSTALL_DIR/data/"
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
echo "Database location: $INSTALL_DIR/data/openadp.db"
echo "Service configuration: $INSTALL_DIR/openadp-server.conf" 
