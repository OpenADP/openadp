# OpenADP Scripts Directory

This directory contains automation scripts and tools for OpenADP operators and developers.

## Operator Scripts

### `update-openadp-node.sh`
**The main automated installer/updater for OpenADP nodes.**

This comprehensive script automates the entire process of installing or updating an OpenADP node:

- **Environment Detection**: Automatically detects your OS and sets up the appropriate package manager
- **Dependency Management**: Installs required system packages and Go compiler
- **Service Management**: Safely stops/starts the OpenADP service
- **Code Updates**: Pulls latest code from git and builds binaries
- **Configuration**: Backs up existing config and installs new systemd service
- **Verification**: Runs health checks and tests after installation

**Usage:**
```bash
# Full installation/update
sudo ./scripts/update-openadp-node.sh

# Preview what would be done
sudo ./scripts/update-openadp-node.sh --dry-run

# Quick update (skip system packages)
sudo ./scripts/update-openadp-node.sh --skip-deps

# Get help
./scripts/update-openadp-node.sh --help
```

**Supported OS:** Ubuntu, Debian, Raspbian, Fedora, RHEL, CentOS, Rocky, AlmaLinux, openSUSE, SLES, Arch, Manjaro

### `OPERATOR_GUIDE.md`
Complete guide for OpenADP node operators covering:
- Installation procedures
- Service management
- Troubleshooting
- Configuration options
- Security considerations

## Makefile Integration

The scripts are integrated with the project Makefile for easy access:

```bash
# Node operator commands
make install-node      # Full install/update (requires sudo)
make update-node       # Quick update (requires sudo)
make node-status       # Show service status
make node-logs         # Show recent logs
make node-test         # Test node functionality
make operator-help     # Show detailed help
```

## Developer Scripts

### Original Deployment Scripts
- `deployment/scripts/deploy-servers.sh` - Multi-server deployment (for development)
- `deployment/scripts/install-openadp-service.sh` - Single server installation (used by update script)

## Script Features

### Safety Features
- **Dry-run mode**: Preview changes without executing
- **Root privilege check**: Ensures proper permissions
- **Configuration backup**: Automatic backup before updates
- **Git status check**: Warns about uncommitted changes
- **Service validation**: Verifies service starts correctly

### Flexibility
- **OS detection**: Works across multiple Linux distributions
- **Skip options**: Skip dependencies, tests, or backups as needed
- **Custom ports**: Install with non-default ports
- **Verbose output**: Detailed logging for debugging

### Robustness
- **Error handling**: Comprehensive error checking and recovery
- **Idempotent**: Safe to run multiple times
- **Service management**: Proper systemd service handling
- **Permission management**: Correct file/directory permissions

## Security Considerations

- Script requires root privileges for system-level operations
- Service runs as dedicated `openadp` user (not root)
- Uses systemd security features (PrivateTmp, ProtectSystem, etc.)
- Configuration files are owned by service user
- Database directory has appropriate permissions

## Troubleshooting

Common issues and solutions:

1. **Permission denied**: Ensure running with `sudo`
2. **Git not found**: Install git first
3. **Service won't start**: Check logs with `make node-logs`
4. **Port already in use**: Use `--port` option or check what's using the port
5. **Build failures**: Ensure Go is properly installed

## Development

To modify or extend the scripts:

1. Test changes with `--dry-run` first
2. Follow the existing error handling patterns
3. Update the help text and documentation
4. Test on multiple OS distributions
5. Ensure backward compatibility

## File Structure

```
scripts/
├── update-openadp-node.sh    # Main operator script
├── OPERATOR_GUIDE.md         # Complete operator guide
└── README.md                 # This file

deployment/scripts/
├── deploy-servers.sh         # Multi-server deployment
└── install-openadp-service.sh # Single server installation
```

## Future Enhancements

Potential improvements:
- Docker support
- Kubernetes deployment
- Automated certificate management
- Monitoring integration
- Update notifications
- Rollback functionality 