# OpenADP Node Operator Guide

## Quick Start

The easiest way to install or update your OpenADP node is using the automated script:

```bash
# Download and run the OpenADP node installer/updater
sudo ./scripts/update-openadp-node.sh
```

## What This Script Does

The `update-openadp-node.sh` script automates the entire process of installing or updating an OpenADP node:

1. **Environment Check**: Detects your OS and verifies prerequisites
2. **System Updates**: Installs required packages (Go, SQLite, etc.)
3. **Service Management**: Safely stops the existing service
4. **Backup**: Backs up current configuration
5. **Code Update**: Pulls latest code from git
6. **Build**: Compiles the latest OpenADP binaries
7. **Installation**: Installs binaries and configuration
8. **Service Start**: Starts and enables the service
9. **Verification**: Runs health checks to ensure everything works

## Command Options

```bash
# Basic usage
sudo ./scripts/update-openadp-node.sh

# See what would be done without making changes
sudo ./scripts/update-openadp-node.sh --dry-run

# Skip system package installation (faster for updates)
sudo ./scripts/update-openadp-node.sh --skip-deps

# Skip post-installation tests
sudo ./scripts/update-openadp-node.sh --skip-tests

# Don't backup existing configuration
sudo ./scripts/update-openadp-node.sh --no-backup

# Install with custom port
sudo ./scripts/update-openadp-node.sh --port 8081

# Get help
./scripts/update-openadp-node.sh --help
```

## Supported Operating Systems

- Ubuntu / Debian / Raspbian
- Fedora / RHEL / CentOS / Rocky Linux / AlmaLinux
- openSUSE / SLES
- Arch Linux / Manjaro

## Prerequisites

- Git repository cloned: `git clone https://github.com/waywardgeek/openadp.git`
- Run as root: `sudo ./scripts/update-openadp-node.sh`
- Internet connection for downloading dependencies

## Common Usage Scenarios

### First-Time Installation

```bash
# Clone the repository
git clone https://github.com/waywardgeek/openadp.git
cd openadp

# Run the installer
sudo ./scripts/update-openadp-node.sh
```

### Regular Updates

```bash
# Update your existing node
cd openadp
sudo ./scripts/update-openadp-node.sh --skip-deps
```

### Preview Changes

```bash
# See what would be updated without making changes
sudo ./scripts/update-openadp-node.sh --dry-run
```

## Service Management

After installation, your OpenADP node runs as a systemd service:

```bash
# Check service status
sudo systemctl status openadp-server

# View real-time logs
sudo journalctl -u openadp-server -f

# Restart the service
sudo systemctl restart openadp-server

# Stop the service
sudo systemctl stop openadp-server

# Start the service
sudo systemctl start openadp-server
```

## Testing Your Node

```bash
# Health check
curl http://localhost:8080/health

# Test the Echo method
curl -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"Echo","params":["Hello"],"id":1}' \
     http://localhost:8080
```

## File Locations

- **Binary**: `/opt/openadp/bin/openadp-server`
- **Configuration**: `/opt/openadp/openadp-server.conf`
- **Database**: `/opt/openadp/data/openadp.db`
- **Service File**: `/etc/systemd/system/openadp-server.service`
- **Logs**: `journalctl -u openadp-server`

## Troubleshooting

### Script Fails to Run
- Ensure you're running as root: `sudo ./scripts/update-openadp-node.sh`
- Check you're in the git repository root directory
- Verify internet connectivity

### Service Won't Start
```bash
# Check logs for errors
sudo journalctl -u openadp-server -n 50

# Check service status
sudo systemctl status openadp-server

# Try starting manually for debugging
sudo -u openadp /opt/openadp/bin/openadp-server -version
```

### Port Already in Use
```bash
# Check what's using port 8080
sudo netstat -tlnp | grep 8080

# Or install with different port
sudo ./scripts/update-openadp-node.sh --port 8081
```

### Permission Issues
```bash
# Fix permissions
sudo chown -R openadp:openadp /opt/openadp
sudo chmod -R 750 /opt/openadp
sudo chmod 755 /opt/openadp/data
```

## Configuration Backup

The script automatically backs up your configuration before updates:
- Backup location: `/tmp/openadp-backup-YYYYMMDD_HHMMSS/`
- Contains: `openadp-server.conf`

## Getting Help

- **Script Help**: `./scripts/update-openadp-node.sh --help`
- **Dry Run**: `sudo ./scripts/update-openadp-node.sh --dry-run`
- **Logs**: `sudo journalctl -u openadp-server -f`
- **GitHub Issues**: https://github.com/waywardgeek/openadp/issues

## Security Notes

- Script must run as root to install system packages and manage services
- Service runs as dedicated `openadp` user (not root)
- Database and configuration files are owned by `openadp` user
- Service uses systemd security features (PrivateTmp, ProtectSystem, etc.) 