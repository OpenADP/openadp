#!/bin/bash

# OpenADP Environment Setup Script
# =================================
# This script checks for required dependencies and sets up the development environment
# for building and testing OpenADP across all supported languages.

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ️${NC} $1"
}

print_header() {
    echo -e "${BOLD}$1${NC}"
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s)
    ARCH=$(uname -m)
    
    case $OS in
        Linux*)
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                DISTRO=$ID
            elif [ -f /etc/redhat-release ]; then
                DISTRO="rhel"
            else
                DISTRO="unknown"
            fi
            ;;
        Darwin*)
            DISTRO="macos"
            ;;
        CYGWIN*|MINGW*|MSYS*)
            DISTRO="windows"
            ;;
        *)
            DISTRO="unknown"
            ;;
    esac
    
    print_info "Detected: $OS $ARCH ($DISTRO)"
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system dependencies
check_system_deps() {
    print_header "🔍 Checking System Dependencies"
    
    local missing_deps=()
    local optional_missing=()
    
    # Essential dependencies
    if ! command_exists go; then
        missing_deps+=("go")
    else
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        print_status "Go $GO_VERSION installed"
    fi
    
    if ! command_exists python3; then
        missing_deps+=("python3")
    else
        PYTHON_VERSION=$(python3 --version | awk '{print $2}')
        print_status "Python $PYTHON_VERSION installed"
    fi
    
    if ! command_exists make; then
        missing_deps+=("make")
    else
        print_status "Make installed"
    fi
    
    # C++ compiler (gcc or clang)
    if ! command_exists gcc && ! command_exists clang; then
        missing_deps+=("gcc-or-clang")
    else
        if command_exists gcc; then
            GCC_VERSION=$(gcc --version | head -n1 | awk '{print $3}')
            print_status "GCC $GCC_VERSION installed"
        fi
        if command_exists clang; then
            CLANG_VERSION=$(clang --version | head -n1 | awk '{print $3}')
            print_status "Clang $CLANG_VERSION installed"
        fi
    fi
    
    # Optional dependencies
    if ! command_exists node; then
        optional_missing+=("node")
    else
        NODE_VERSION=$(node --version)
        print_status "Node.js $NODE_VERSION installed"
    fi
    
    if ! command_exists rustc; then
        optional_missing+=("rust")
    else
        RUST_VERSION=$(rustc --version | awk '{print $2}')
        print_status "Rust $RUST_VERSION installed"
    fi
    
    # Report missing dependencies
    if [ ${#missing_deps[@]} -gt 0 ]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        provide_installation_instructions "${missing_deps[@]}"
        return 1
    fi
    
    if [ ${#optional_missing[@]} -gt 0 ]; then
        print_warning "Missing optional dependencies: ${optional_missing[*]}"
        print_info "Some tests may be skipped. Install these for full functionality."
        provide_installation_instructions "${optional_missing[@]}"
    fi
    
    return 0
}

# Provide installation instructions based on platform
provide_installation_instructions() {
    local deps=("$@")
    
    print_header "📦 Installation Instructions"
    
    case $DISTRO in
        ubuntu|debian)
            print_info "For Ubuntu/Debian systems:"
            if [[ " ${deps[*]} " =~ " go " ]]; then
                echo "  sudo apt update && sudo apt install golang-go"
            fi
            if [[ " ${deps[*]} " =~ " python3 " ]]; then
                echo "  sudo apt install python3 python3-pip python3-venv"
            fi
            if [[ " ${deps[*]} " =~ " make " ]]; then
                echo "  sudo apt install build-essential"
            fi
            if [[ " ${deps[*]} " =~ " gcc-or-clang " ]]; then
                echo "  sudo apt install build-essential"
            fi
            if [[ " ${deps[*]} " =~ " node " ]]; then
                echo "  curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -"
                echo "  sudo apt install nodejs"
            fi
            if [[ " ${deps[*]} " =~ " rust " ]]; then
                echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
            fi
            ;;
        centos|rhel|fedora)
            print_info "For CentOS/RHEL/Fedora systems:"
            if [[ " ${deps[*]} " =~ " go " ]]; then
                echo "  sudo dnf install golang  # or sudo yum install golang"
            fi
            if [[ " ${deps[*]} " =~ " python3 " ]]; then
                echo "  sudo dnf install python3 python3-pip  # or sudo yum install python3 python3-pip"
            fi
            if [[ " ${deps[*]} " =~ " make " ]]; then
                echo "  sudo dnf groupinstall 'Development Tools'  # or sudo yum groupinstall 'Development Tools'"
            fi
            if [[ " ${deps[*]} " =~ " gcc-or-clang " ]]; then
                echo "  sudo dnf groupinstall 'Development Tools'  # or sudo yum groupinstall 'Development Tools'"
            fi
            if [[ " ${deps[*]} " =~ " node " ]]; then
                echo "  sudo dnf install nodejs  # or sudo yum install nodejs"
            fi
            if [[ " ${deps[*]} " =~ " rust " ]]; then
                echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
            fi
            ;;
        macos)
            print_info "For macOS systems:"
            echo "  Install Homebrew first: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
            if [[ " ${deps[*]} " =~ " go " ]]; then
                echo "  brew install go"
            fi
            if [[ " ${deps[*]} " =~ " python3 " ]]; then
                echo "  brew install python3"
            fi
            if [[ " ${deps[*]} " =~ " make " ]]; then
                echo "  xcode-select --install"
            fi
            if [[ " ${deps[*]} " =~ " gcc-or-clang " ]]; then
                echo "  xcode-select --install"
            fi
            if [[ " ${deps[*]} " =~ " node " ]]; then
                echo "  brew install node"
            fi
            if [[ " ${deps[*]} " =~ " rust " ]]; then
                echo "  brew install rust"
            fi
            ;;
        *)
            print_info "For your system, please install:"
            for dep in "${deps[@]}"; do
                case $dep in
                    go) echo "  - Go 1.18+ from https://golang.org/dl/" ;;
                    python3) echo "  - Python 3.8+ from https://www.python.org/downloads/" ;;
                    make) echo "  - Make build tool" ;;
                    gcc-or-clang) echo "  - GCC or Clang C++ compiler" ;;
                    node) echo "  - Node.js from https://nodejs.org/" ;;
                    rust) echo "  - Rust from https://rustup.rs/" ;;
                esac
            done
            ;;
    esac
    
    # Special instructions for Raspberry Pi
    if [[ $ARCH == "aarch64" || $ARCH == "armv7l" ]]; then
        print_header "🍓 Raspberry Pi Notes"
        print_info "For Raspberry Pi systems:"
        echo "  - Go: sudo apt install golang-go (may be older version)"
        echo "  - For latest Go: wget https://go.dev/dl/go1.21.6.linux-arm64.tar.gz"
        echo "    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-arm64.tar.gz"
        echo "    export PATH=\$PATH:/usr/local/go/bin"
        echo "  - Node.js: Use NodeSource repository for latest version"
        echo "  - Rust builds may take significant time on older Pi models"
    fi
}

# Set up Python environment
setup_python_env() {
    print_header "🐍 Setting up Python Environment"
    
    if [ ! -d "venv" ]; then
        print_info "Creating Python virtual environment..."
        python3 -m venv venv
        print_status "Virtual environment created"
    else
        print_status "Virtual environment already exists"
    fi
    
    print_info "Installing Python dependencies..."
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r sdk/python/requirements.txt
    
    print_info "Installing OpenADP Python SDK in development mode..."
    cd sdk/python
    pip install -e .
    cd ../..
    
    print_status "Python environment ready"
}

# Build Go components
build_go_components() {
    print_header "🔨 Building Go Components"
    
    if ! command_exists go; then
        print_error "Go not installed, skipping Go build"
        return 1
    fi
    
    # Check Go version compatibility
    local go_version=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
    local major=$(echo $go_version | cut -d. -f1)
    local minor=$(echo $go_version | cut -d. -f2)
    
    if (( major < 1 || (major == 1 && minor < 21) )); then
        print_warning "Go $go_version detected, but OpenADP requires Go 1.21+"
        if [[ $ARCH == "aarch64" || $ARCH == "armv7l" ]]; then
            print_info "For Raspberry Pi, install Go 1.21+ manually:"
            echo "  wget https://go.dev/dl/go1.21.6.linux-arm64.tar.gz"
            echo "  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-arm64.tar.gz"
            echo "  export PATH=\$PATH:/usr/local/go/bin"
            echo "  # Add to ~/.bashrc: export PATH=\$PATH:/usr/local/go/bin"
        else
            print_info "Please upgrade Go to version 1.21 or later:"
            echo "  https://golang.org/dl/"
        fi
        print_warning "Skipping Go build due to version incompatibility"
        return 1
    fi
    
    print_info "Downloading Go dependencies..."
    if ! go mod download; then
        print_error "Failed to download Go dependencies"
        return 1
    fi
    
    print_info "Building Go tools..."
    if ! make build-go; then
        print_error "Failed to build Go components"
        return 1
    fi
    
    print_status "Go components built"
}

# Check JavaScript dependencies
setup_javascript_env() {
    print_header "🟨 Setting up JavaScript Environment"
    
    if ! command_exists node; then
        print_warning "Node.js not installed, JavaScript tests will be skipped"
        return 1
    fi
    
    cd sdk/javascript
    if [ ! -d "node_modules" ]; then
        print_info "Installing JavaScript dependencies..."
        npm install
        print_status "JavaScript dependencies installed"
    else
        print_status "JavaScript dependencies already installed"
    fi
    cd ../..
}

# Build Rust components
setup_rust_env() {
    print_header "🦀 Setting up Rust Environment"
    
    if ! command_exists rustc; then
        print_warning "Rust not installed, Rust tests will be skipped"
        return 1
    fi
    
    cd sdk/rust
    print_info "Building Rust components..."
    cargo build --release
    print_status "Rust components built"
    cd ../..
}

# Main setup function
main() {
    print_header "🚀 OpenADP Environment Setup"
    echo "This script will check dependencies and set up your development environment."
    echo
    
    # Detect platform
    detect_platform
    echo
    
    # Check system dependencies
    if ! check_system_deps; then
        echo
        print_error "Please install the missing system dependencies and run this script again."
        exit 1
    fi
    
    echo
    print_status "All required system dependencies are installed!"
    echo
    
    # Set up environments
    setup_python_env
    echo
    
    if build_go_components; then
        echo
    fi
    
    if setup_javascript_env; then
        echo
    fi
    
    if setup_rust_env; then
        echo
    fi
    
    print_header "🎉 Environment Setup Complete!"
    echo
    print_status "You can now run the test suite:"
    echo "  ./run_all_tests.py"
    echo
    print_info "If you encounter issues, check that all dependencies are properly installed."
    print_info "For Raspberry Pi or ARM systems, some builds may take extra time."
}

# Run main function
main "$@" 