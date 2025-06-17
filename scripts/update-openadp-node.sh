#!/bin/bash

# OpenADP Node Update/Install Script
# Automated script for OpenADP operators to install or update their nodes
# This script combines all tasks from deploy-servers.sh and install-openadp-service.sh

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/openadp"
SERVICE_USER="openadp"
SERVICE_GROUP="openadp"
SERVICE_NAME="openadp-server"
PROJECT_DIR="$(pwd)"
DEFAULT_PORT="8080"

# Script options
SKIP_DEPS=false
SKIP_TESTS=false
DRY_RUN=false
VERBOSE=false
BACKUP_CONFIG=true

# Banner
print_banner() {
    echo -e "${BLUE}"
    echo "================================================================="
    echo " ██████╗ ██████╗ ███████╗███╗   ██╗ █████╗ ██████╗ ██████╗ "
    echo "██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔══██╗"
    echo "██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████║██║  ██║██████╔╝"
    echo "██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██╔══██║██║  ██║██╔═══╝ "
    echo "╚██████╔╝██║     ███████╗██║ ╚████║██║  ██║██████╔╝██║     "
    echo " ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚═╝     "
    echo ""
    echo "        OpenADP Node Automated Update/Install Script"
    echo "                  Version 1.0.0"
    echo "================================================================="
    echo -e "${NC}"
}

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

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Usage information
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "OpenADP Node automated installer/updater"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help           Show this help message"
    echo "  -v, --verbose        Enable verbose output"
    echo "  -n, --dry-run        Show what would be done without executing"
    echo "  -s, --skip-deps      Skip system dependency installation"
    echo "  -t, --skip-tests     Skip service tests after installation"
    echo "  -b, --no-backup      Don't backup existing configuration"
    echo "  -p, --port PORT      Set service port (default: 8080)"
    echo ""
    echo "EXAMPLES:"
    echo "  $0                   # Full install/update with all checks"
    echo "  $0 --dry-run         # Preview what would be done"
    echo "  $0 --skip-deps       # Update only (skip system packages)"
    echo "  $0 --port 8081       # Install with custom port"
    echo ""
    echo "This script performs the following actions:"
    echo "  1. Check prerequisites and detect environment"
    echo "  2. Update system packages (unless --skip-deps)"
    echo "  3. Install/update Go compiler"
    echo "  4. Stop existing OpenADP service (if running)"
    echo "  5. Backup current configuration (unless --no-backup)"
    echo "  6. Update source code from git"
    echo "  7. Build and install OpenADP binaries"
    echo "  8. Update systemd service configuration"
    echo "  9. Start and enable the service"
    echo "  10. Run health checks and tests (unless --skip-tests)"
    echo ""
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -n|--dry-run)
                DRY_RUN=true
                log_warn "DRY RUN MODE - No changes will be made"
                shift
                ;;
            -s|--skip-deps)
                SKIP_DEPS=true
                shift
                ;;
            -t|--skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            -b|--no-backup)
                BACKUP_CONFIG=false
                shift
                ;;
            -p|--port)
                DEFAULT_PORT="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Execute command with dry-run support
exec_cmd() {
    if [ "$VERBOSE" = true ] || [ "$DRY_RUN" = true ]; then
        echo -e "${PURPLE}[CMD]${NC} $*"
    fi
    
    if [ "$DRY_RUN" = false ]; then
        "$@"
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check if we're in a git repository
    if [ ! -d ".git" ]; then
        log_error "This script must be run from the OpenADP git repository root"
        exit 1
    fi
    
    # Check for essential commands
    local missing_cmds=()
    for cmd in git wget curl; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_cmds+=("$cmd")
        fi
    done
    
    if [ ${#missing_cmds[@]} -ne 0 ]; then
        log_error "Missing required commands: ${missing_cmds[*]}"
        log_info "Please install them first, then rerun this script"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Detect OS and set package manager
detect_os() {
    log_step "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        log_info "Detected OS: $OS ($PRETTY_NAME)"
    else
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    # Set package manager based on OS
    case $OS in
        ubuntu|debian|raspbian)
            PKG_UPDATE="apt-get update"
            PKG_INSTALL="apt-get install -y"
            SYSTEM_PKGS="wget gcc sqlite3 jq curl"
            ;;
        fedora|rhel|centos|rocky|almalinux)
            PKG_UPDATE="dnf update -y"
            PKG_INSTALL="dnf install -y"
            SYSTEM_PKGS="wget gcc sqlite jq curl"
            ;;
        opensuse*|sles)
            PKG_UPDATE="zypper refresh"
            PKG_INSTALL="zypper install -y"
            SYSTEM_PKGS="wget gcc sqlite3 jq curl"
            ;;
        arch|manjaro)
            PKG_UPDATE="pacman -Sy"
            PKG_INSTALL="pacman -S --noconfirm"
            SYSTEM_PKGS="wget gcc sqlite jq curl"
            ;;
        *)
            log_error "Unsupported OS: $OS"
            log_info "Supported: Ubuntu, Debian, Raspbian, Fedora, RHEL, CentOS, Rocky, AlmaLinux, openSUSE, SLES, Arch, Manjaro"
            exit 1
            ;;
    esac

    log_info "Package manager: ${PKG_INSTALL%% *}"
}

# Install system dependencies
install_dependencies() {
    if [ "$SKIP_DEPS" = true ]; then
        log_info "Skipping system dependency installation"
        return
    fi
    
    log_step "Installing system dependencies..."
    
    log_info "Updating package manager..."
    exec_cmd $PKG_UPDATE
    
    log_info "Installing packages: $SYSTEM_PKGS"
    exec_cmd $PKG_INSTALL $SYSTEM_PKGS
    
    log_success "System dependencies installed"
}

# Install/update Go
install_go() {
    log_step "Installing/updating Go compiler..."
    
    GO_VERSION="1.23.10"
    
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
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    GO_URL="https://golang.org/dl/${GO_TARBALL}"

    log_info "Downloading Go ${GO_VERSION} for ${GO_ARCH}..."
    exec_cmd cd /tmp
    exec_cmd wget -O "$GO_TARBALL" "$GO_URL"

    log_info "Installing Go to /usr/local..."
    exec_cmd rm -rf /usr/local/go
    exec_cmd tar -C /usr/local -xzf "$GO_TARBALL"
    exec_cmd rm -f "$GO_TARBALL"

    # Set up Go environment
    export PATH="/usr/local/go/bin:$PATH"
    
    if [ "$DRY_RUN" = false ]; then
        # Verify Go installation
        if ! command -v go &> /dev/null; then
            log_error "Go installation failed"
            exit 1
        fi
        
        GO_INSTALLED_VERSION=$(go version)
        log_success "Go installed: $GO_INSTALLED_VERSION"
    else
        log_info "Would verify Go installation"
    fi
}

# Stop existing service
stop_service() {
    log_step "Stopping existing OpenADP service..."
    
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Stopping $SERVICE_NAME service..."
        exec_cmd systemctl stop "$SERVICE_NAME"
        sleep 2
        log_success "Service stopped"
    else
        log_info "Service is not running"
    fi
}

# Backup existing configuration
backup_config() {
    if [ "$BACKUP_CONFIG" = false ]; then
        log_info "Skipping configuration backup"
        return
    fi
    
    log_step "Backing up existing configuration..."
    
    BACKUP_DIR="/tmp/openadp-backup-$(date +%Y%m%d_%H%M%S)"
    
    if [ -f "$INSTALL_DIR/openadp-server.conf" ]; then
        exec_cmd mkdir -p "$BACKUP_DIR"
        exec_cmd cp "$INSTALL_DIR/openadp-server.conf" "$BACKUP_DIR/"
        log_success "Configuration backed up to $BACKUP_DIR"
    else
        log_info "No existing configuration to backup"
    fi
}

# Update source code
update_source() {
    log_step "Updating source code from git..."
    
    # Get current branch and status
    CURRENT_BRANCH=$(git branch --show-current)
    log_info "Current branch: $CURRENT_BRANCH"
    
    # Check for uncommitted changes
    if ! git diff --quiet || ! git diff --cached --quiet; then
        log_warn "You have uncommitted changes in the repository"
        if [ "$DRY_RUN" = false ]; then
            read -p "Do you want to continue? This will not affect your changes. [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Update cancelled by user"
                exit 0
            fi
        fi
    fi
    
    # Pull latest changes
    log_info "Pulling latest changes..."
    exec_cmd git pull
    
    log_success "Source code updated"
}

# Create service user and directories
setup_user_and_dirs() {
    log_step "Setting up service user and directories..."
    
    # Create service group
    if ! getent group "$SERVICE_GROUP" > /dev/null 2>&1; then
        exec_cmd groupadd --system "$SERVICE_GROUP"
        log_info "Created group: $SERVICE_GROUP"
    fi

    # Create service user
    if ! getent passwd "$SERVICE_USER" > /dev/null 2>&1; then
        exec_cmd useradd --system --gid "$SERVICE_GROUP" --home-dir "$INSTALL_DIR" \
                --shell /usr/sbin/nologin --comment "OpenADP Go Server" "$SERVICE_USER"
        log_info "Created user: $SERVICE_USER"
    fi

    # Create directories
    exec_cmd mkdir -p "$INSTALL_DIR"/{bin,data,logs}
    
    log_success "User and directories setup complete"
}

# Build OpenADP binaries
build_binaries() {
    log_step "Building OpenADP binaries..."
    
    # Remove old build directory
    exec_cmd rm -rf "$INSTALL_DIR/src"
    
    # Copy source code
    exec_cmd mkdir -p "$INSTALL_DIR/src"
    exec_cmd cp -r "$PROJECT_DIR"/* "$INSTALL_DIR/src/" 2>/dev/null || true
    
    # Set permissions
    exec_cmd chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    
    if [ "$DRY_RUN" = false ]; then
        # Build as service user
        log_info "Building Go binaries..."
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
            
            # Clean up
            go clean -cache -modcache 2>/dev/null || true
            /bin/rm -rf \$GOPATH \$GOCACHE 2>/dev/null || true
        "
        
        # Verify binary was built
        if [ ! -f "$INSTALL_DIR/bin/openadp-server" ]; then
            log_error "Failed to build openadp-server binary"
            exit 1
        fi
        
        # Test the binary
        log_info "Testing built binary..."
        sudo -u "$SERVICE_USER" "$INSTALL_DIR/bin/openadp-server" -version
        
        log_success "Binaries built successfully"
    else
        log_info "Would build OpenADP binaries"
    fi
}

# Install configuration and service files
install_config() {
    log_step "Installing configuration and service files..."
    
    # Install server configuration
    if [ -f "$PROJECT_DIR/deployment/systemd/openadp-server.conf" ]; then
        exec_cmd cp "$PROJECT_DIR/deployment/systemd/openadp-server.conf" "$INSTALL_DIR/"
        exec_cmd chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/openadp-server.conf"
        log_info "Installed server configuration"
    fi
    
    # Install systemd service
    if [ -f "$PROJECT_DIR/deployment/systemd/openadp-server.service" ]; then
        exec_cmd cp "$PROJECT_DIR/deployment/systemd/openadp-server.service" /etc/systemd/system/
        exec_cmd systemctl daemon-reload
        log_info "Installed systemd service"
    fi
    
    # Set final permissions
    exec_cmd chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    exec_cmd chmod -R 750 "$INSTALL_DIR"
    exec_cmd chmod +x "$INSTALL_DIR/bin"/*
    exec_cmd chmod 755 "$INSTALL_DIR/data"
    
    # Clean up source code
    exec_cmd rm -rf "$INSTALL_DIR/src"
    
    log_success "Configuration installed"
}

# Start and enable service
start_service() {
    log_step "Starting OpenADP service..."
    
    exec_cmd systemctl enable "$SERVICE_NAME"
    exec_cmd systemctl start "$SERVICE_NAME"
    
    if [ "$DRY_RUN" = false ]; then
        # Wait for service to start
        sleep 3
        
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log_success "Service started successfully"
        else
            log_error "Service failed to start"
            log_info "Check logs with: journalctl -u $SERVICE_NAME -n 50"
            exit 1
        fi
    else
        log_info "Would start and enable service"
    fi
}

# Run health checks and tests
run_tests() {
    if [ "$SKIP_TESTS" = true ]; then
        log_info "Skipping service tests"
        return
    fi
    
    if [ "$DRY_RUN" = true ]; then
        log_info "Would run health checks and tests"
        return
    fi
    
    log_step "Running health checks and tests..."
    
    # Wait for service to be fully ready
    sleep 5
    
    # Test health endpoint
    log_info "Testing health endpoint..."
    if curl -s "http://localhost:$DEFAULT_PORT/health" | jq . > /dev/null 2>&1; then
        log_success "Health check passed"
    else
        log_warn "Health check failed - service may still be starting"
    fi
    
    # Test Echo method
    log_info "Testing Echo JSON-RPC method..."
    ECHO_RESPONSE=$(curl -s -H "Content-Type: application/json" \
         -d '{"jsonrpc":"2.0","method":"Echo","params":["Node update test"],"id":1}' \
         "http://localhost:$DEFAULT_PORT" 2>/dev/null || echo "")
    
    if echo "$ECHO_RESPONSE" | jq -e '.result' > /dev/null 2>&1; then
        log_success "Echo test passed"
    else
        log_warn "Echo test failed - check service logs"
    fi
    
    # Show service status
    log_info "Service status:"
    systemctl status "$SERVICE_NAME" --no-pager -l
}

# Show final status and information
show_final_status() {
    echo ""
    log_success "OpenADP node update/installation completed!"
    echo ""
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "${CYAN}Service Information:${NC}"
        echo "  Status: $(systemctl is-active $SERVICE_NAME)"
        echo "  Port: $DEFAULT_PORT"
        echo "  Database: $INSTALL_DIR/data/openadp.db"
        echo "  Configuration: $INSTALL_DIR/openadp-server.conf"
        echo "  Logs: journalctl -u $SERVICE_NAME -f"
        echo ""
        
        echo -e "${CYAN}Useful Commands:${NC}"
        echo "  Check status:    systemctl status $SERVICE_NAME"
        echo "  View logs:       journalctl -u $SERVICE_NAME -f"
        echo "  Restart service: systemctl restart $SERVICE_NAME"
        echo "  Stop service:    systemctl stop $SERVICE_NAME"
        echo ""
        
        echo -e "${CYAN}Health Check:${NC}"
        echo "  curl http://localhost:$DEFAULT_PORT/health"
        echo ""
        
        if [ -f "/tmp/openadp-backup-"* ]; then
            echo -e "${YELLOW}Configuration Backup:${NC}"
            echo "  Previous configuration backed up to: $(ls -t /tmp/openadp-backup-* | head -n1)"
            echo ""
        fi
    else
        echo -e "${YELLOW}This was a dry run - no changes were made${NC}"
        echo "Run without --dry-run to perform the actual update/installation"
    fi
}

# Main execution function
main() {
    print_banner
    parse_args "$@"
    
    check_root
    check_prerequisites
    detect_os
    install_dependencies
    install_go
    stop_service
    backup_config
    update_source
    setup_user_and_dirs
    build_binaries
    install_config
    start_service
    run_tests
    show_final_status
    
    log_success "All operations completed successfully!"
}

# Run main function with all arguments
main "$@" 