# OpenADP Development Setup

This guide helps you set up a complete OpenADP development environment for building and testing all components.

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/OpenADP/openadp.git
cd openadp

# 2. Run the setup script
scripts/setup_env.sh

# 3. Run the test suite
./run_all_tests.py
```

## What the Setup Script Does

The `scripts/setup_env.sh` script will:

1. **🔍 Check System Dependencies**: Detect your OS and verify required tools are installed
2. **📦 Provide Installation Instructions**: Give specific commands for your platform if anything is missing
3. **🐍 Set up Python Environment**: Create virtual environment and install Python dependencies
4. **🔨 Build Go Components**: Download dependencies and build Go tools
5. **🟨 Set up JavaScript Environment**: Install Node.js dependencies if available
6. **🦀 Build Rust Components**: Compile Rust tools if available

## System Requirements

### Required Dependencies
- **Go 1.18+** - Core server and tools
- **Python 3.8+** - Python SDK and test tools  
- **Make** - Build system
- **C++ Compiler** (GCC or Clang) - C++ SDK

### Optional Dependencies
- **Node.js** - JavaScript SDK and browser tests
- **Rust** - Rust SDK (for comprehensive cross-language testing)

## Platform-Specific Installation

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install golang-go python3 python3-pip python3-venv build-essential
```

### CentOS/RHEL/Fedora
```bash
sudo dnf install golang python3 python3-pip make gcc-c++
# or: sudo yum install golang python3 python3-pip make gcc-c++
```

### macOS
```bash
# Install Homebrew first
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install go python3 make
xcode-select --install  # For C++ compiler
```

### Raspberry Pi
```bash
sudo apt update
sudo apt install golang-go python3 python3-pip python3-venv build-essential

# For latest Go (optional):
wget https://go.dev/dl/go1.21.6.linux-arm64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-arm64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

## Troubleshooting

### "Go not found" Error
- Make sure Go is installed and in your PATH
- On Raspberry Pi, you may need to install a newer version manually
- Verify with: `go version`

### Python Environment Issues
- Ensure Python 3.8+ is installed: `python3 --version`
- Make sure you have `python3-venv` package installed
- The setup script will create and manage the virtual environment

### JavaScript Tests Skipped
- Install Node.js from https://nodejs.org/ or your package manager
- JavaScript tests are optional but provide additional cross-language validation

### Rust Tests Skipped  
- Install Rust from https://rustup.rs/
- Rust tests are optional but provide comprehensive cross-language compatibility testing
- Note: Rust compilation can take significant time on older hardware

### Permission Errors
- Don't run the setup script with sudo
- If you see permission errors, check that your user owns the project directory
- For system package installation, use your platform's package manager with appropriate permissions

## Advanced Usage

### Running Individual Test Categories
```bash
# Run only Go tests
make test

# Run only Python tests
source venv/bin/activate
cd sdk/python/tests && python -m pytest

# Run only JavaScript tests  
cd sdk/javascript && npm test

# Run cross-language compatibility tests
python tests/cross-language/test_cross_language_encrypt_decrypt.py
```

### Development Workflow
```bash
# After making changes, run the full test suite
./run_all_tests.py

# For faster iteration, run specific test categories
# (see Advanced Usage above)
```

## Support

If you encounter issues:

1. **Check Dependencies**: Run `scripts/setup_env.sh` again to verify all dependencies
2. **Platform Issues**: The setup script provides platform-specific installation instructions
3. **Hardware Limitations**: Some tests (especially Rust compilation) may be slow on older hardware
4. **GitHub Issues**: Report persistent issues at https://github.com/OpenADP/openadp/issues

The setup script is designed to be safe to run multiple times and will skip steps that are already completed. 