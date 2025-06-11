# OpenADP Prototype

OpenADP (Open Asynchronous Distributed Password) is a distributed secret sharing system that replaces traditional password-based key derivation with a more secure distributed approach.

## Features

- **Distributed secret sharing** across multiple servers
- **Threshold cryptography** (need minimum servers to recover)
- **Ed25519-based** elliptic curve cryptography
- **ChaCha20-Poly1305** authenticated encryption
- **Server metadata binding** for reliable decryption
- **Cross-platform systemd service** support

## Quick Start

### Manual Dependencies (Development)

For development and testing on Ubuntu 24.04:

```bash
sudo apt install sqlite3 python3-cryptography
```

You also need to build the Python files for openadp.proto. Go into the `proto/` directory and follow the README.md there.

## Project Structure

```
prototype/
├── README.md                  # This file
├── TODO                      # Development tasks
├── run_server.py             # Server runner script
├── src/                      # Core library code
│   ├── openadp/             # Main OpenADP library
│   │   ├── __init__.py      # Package initialization
│   │   ├── crypto.py        # Ed25519 cryptographic functions
│   │   ├── sharing.py       # Secret sharing algorithms
│   │   ├── database.py      # SQLite database operations
│   │   └── keygen.py        # Key generation and recovery
│   ├── client/              # Client components
│   │   ├── __init__.py      # Package initialization
│   │   ├── client.py        # High-level client business logic
│   │   ├── jsonrpc_client.py # JSON-RPC transport layer
│   │   └── scrape.py        # Server discovery
│   └── server/              # Server components
│       ├── __init__.py      # Package initialization
│       ├── server.py        # Core server business logic
│       ├── jsonrpc_server.py # JSON-RPC server
│       └── grpc_server.py   # gRPC server
├── tools/                   # Command-line utilities
│   ├── encrypt.py          # File encryption tool
│   └── decrypt.py          # File decryption tool
├── tests/                   # Test files
│   ├── test_*.py           # Unit and integration tests
│   └── debug_*.py          # Debug utilities
├── proto/                   # Protocol buffer definitions
│   ├── openadp.proto       # Service definitions
│   ├── openadp_pb2.py      # Generated Python classes
│   └── openadp_pb2_grpc.py # Generated gRPC stubs
├── deployment/              # Installation and deployment
│   ├── systemd/            # Systemd service files
│   │   ├── openadp-server.service
│   │   └── openadp-server.conf
│   └── scripts/            # Installation scripts
│       ├── install-openadp-service.sh         # Debian/Ubuntu
│       ├── install-openadp-service-fedora.sh  # Fedora/RHEL
│       └── install-openadp-service-auto.sh    # Auto-detect OS
└── examples/               # Usage examples (future)
```

### File Encryption/Decryption

```bash
# Encrypt a file
python3 tools/encrypt.py myfile.txt

# Decrypt a file
python3 tools/decrypt.py myfile.txt.enc
```

## Server Installation

### Automatic Installation (Recommended)

The auto-detecting installer works on all major Linux distributions:

```bash
sudo ./deployment/scripts/install-openadp-service-auto.sh
```

**Supported distributions:**
- **Debian-based**: Ubuntu, Debian, Raspbian
- **Red Hat-based**: Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux
- **SUSE-based**: openSUSE, SLES
- **Arch-based**: Arch Linux, Manjaro

### Manual Installation by Distribution

#### Debian/Ubuntu/Raspbian
```bash
sudo ./deployment/scripts/install-openadp-service.sh
```

#### Fedora/RHEL/CentOS
```bash
sudo ./deployment/scripts/install-openadp-service-fedora.sh
```

### Post-Installation

1. **Start the service**
```bash
sudo systemctl start openadp-server
```

2. **Enable auto-start on boot**
```bash
sudo systemctl enable openadp-server
```

3. **Check service status**
```bash
sudo systemctl status openadp-server
```

4. **View logs**
```bash
sudo journalctl -u openadp-server -f
```

## Service Management

### Common Service Commands

| Command | Description |
|---------|-------------|
| `sudo systemctl start openadp-server` | Start the service |
| `sudo systemctl stop openadp-server` | Stop the service |
| `sudo systemctl restart openadp-server` | Restart the service |
| `sudo systemctl enable openadp-server` | Enable auto-start on boot |
| `sudo systemctl disable openadp-server` | Disable auto-start |
| `sudo systemctl status openadp-server` | Check service status |

### Log Management

```bash
# Follow live logs
sudo journalctl -u openadp-server -f

# View recent logs
sudo journalctl -u openadp-server --since "1 hour ago"

# View logs since last boot
sudo journalctl -u openadp-server --since "today"
```

## Configuration

The server configuration is located at `/opt/openadp/openadp-server.conf`:

```ini
[server]
port = 8080
host = 0.0.0.0
database = openadp.db

[logging]
level = INFO

[security]
max_request_size = 1048576
request_timeout = 30
enable_cors = true
```

## Database Management

To inspect the SQLite database:

```bash
# Connect to database
sudo -u openadp sqlite3 /opt/openadp/openadp.db

# View table structure
sqlite> .schema

# Dump all data as SQL
sqlite> .dump

# Exit
sqlite> .exit
```

## Security Features

- **Dedicated user**: Runs as `openadp:openadp` (not root)
- **Systemd sandboxing**: ProtectSystem, ProtectHome, PrivateTmp
- **Resource limits**: File descriptor and timeout controls
- **Cryptographic binding**: Metadata authenticated with encrypted data
- **Threshold recovery**: Need minimum servers to reconstruct secrets

## Troubleshooting

### Service Won't Start
```bash
# Check service status
sudo systemctl status openadp-server

# Check detailed logs
sudo journalctl -u openadp-server --no-pager

# Check file permissions
ls -la /opt/openadp/
```

### Port Already in Use
```bash
# Check what's using port 8080
sudo netstat -tlnp | grep :8080

# Or use ss
sudo ss -tlnp | grep :8080
```

### Database Issues
```bash
# Check database permissions
ls -la /opt/openadp/openadp.db

# Reset database (WARNING: deletes all data)
sudo rm /opt/openadp/openadp.db
sudo systemctl restart openadp-server
```
