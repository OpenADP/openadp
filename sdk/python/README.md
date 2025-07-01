# OpenADP Python SDK

A Python implementation of the OpenADP (Open Advanced Data Protection) client, providing distributed secret sharing and threshold cryptography for secure data protection.

## Overview

OpenADP is an open-source distributed secret sharing system designed to protect against nation-state attacks. This Python SDK provides complete interoperability with the Go implementation, allowing you to:

- Generate and recover encryption keys using threshold cryptography
- Communicate securely with OpenADP servers using Noise-NK protocol
- Manage multiple servers with automatic failover
- Perform Ed25519 elliptic curve operations and Shamir secret sharing

## Features

- **🔐 Cryptographic Operations**: Ed25519 elliptic curve operations, Shamir secret sharing, HKDF key derivation
- **🛡️ Secure Communication**: Noise-NK protocol implementation for encrypted client-server communication  
- **🌐 Multi-Server Support**: Automatic server discovery, failover, and load balancing
- **🔄 Cross-Language Compatibility**: Full interoperability with Go implementation
- **📡 JSON-RPC 2.0**: Standards-compliant API communication
- **🚀 Easy to Use**: Simple high-level API for common operations

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install from PyPI (when published)

```bash
pip install openadp
```

### Install from Source

```bash
git clone https://github.com/openadp/openadp.git
cd openadp/sdk/python
pip install -e .
```

### Dependencies

The SDK requires:
- `cryptography>=41.0.0` - For cryptographic operations
- `requests>=2.28.0` - For HTTP client functionality

## Quick Start

### Basic Key Generation and Recovery

```python
from openadp import MultiServerClient
from openadp.keygen import generate_encryption_key, recover_encryption_key

# Generate an encryption key with distributed backup
key, auth_code = generate_encryption_key(
    password="your_secure_password",
    uid="user@example.com",
    did="device_identifier", 
    bid="backup_identifier"
)

print(f"Generated 256-bit key: {key.hex()}")
print(f"Auth code (save this!): {auth_code}")

# Later, recover the key from a different device
client = MultiServerClient()
recovered_key = recover_encryption_key(
    password="your_secure_password",
    auth_code=auth_code,
    uid="user@example.com",
    did="device_identifier",
    bid="backup_identifier",
    client=client
)

print(f"Recovered key: {recovered_key.hex()}")
assert key == recovered_key  # Keys match!
```

### Direct Client Usage

```python
from openadp import EncryptedOpenADPClient, discover_servers

# Discover available servers
servers = discover_servers()
print(f"Found {len(servers)} servers")

# Create encrypted client with server public key
server = servers[0]
public_key = base64.b64decode(server.public_key.split(':')[1])
client = EncryptedOpenADPClient(server.url, public_key)

# Test connectivity
try:
    client.ping()
    print("✅ Connected to server successfully")
except Exception as e:
    print(f"❌ Connection failed: {e}")

# Get server information
info = client.get_server_info()
print(f"Server version: {info['version']}")
```

### Multi-Server Operations

```python
from openadp import MultiServerClient, ServerInfo

# Create client with automatic server discovery
client = MultiServerClient()
print(f"Connected to {client.get_live_server_count()} servers")

# Or specify servers manually
server_infos = [
    ServerInfo(
        url="https://server1.example.com",
        public_key="ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey1",
        country="US"
    ),
    ServerInfo(
        url="https://server2.example.com", 
        public_key="ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey2",
        country="EU"
    )
]

client = MultiServerClient.from_server_info(server_infos)

# List available backups
backups = client.list_backups("user@example.com")
for backup in backups:
    print(f"Backup: {backup['bid']}, Version: {backup['version']}")
```

## API Reference

### Core Classes

#### `MultiServerClient`
High-level client managing multiple OpenADP servers with automatic failover.

```python
client = MultiServerClient(
    servers_url="https://servers.openadp.org",  # Server registry URL
    fallback_servers=None,                      # Fallback server URLs
    echo_timeout=10,                           # Connection timeout
    max_workers=10                             # Concurrent connection limit
)
```

#### `EncryptedOpenADPClient` 
JSON-RPC client with Noise-NK encryption support.

```python
client = EncryptedOpenADPClient(
    url="https://server.example.com",
    server_public_key=public_key_bytes,  # 32-byte Ed25519 public key
    timeout=30
)
```

#### `OpenADPClient`
Basic JSON-RPC client without encryption (for testing only).

```python
client = OpenADPClient("https://server.example.com")
```

### Key Generation Functions

#### `generate_encryption_key()`
Generate a new encryption key with distributed backup.

```python
key, auth_code = generate_encryption_key(
    password="user_password",
    uid="user@example.com",      # User identifier  
    did="device_id",             # Device identifier
    bid="backup_id",             # Backup identifier
    client=None,                 # Optional: custom client
    max_guesses=10,              # Recovery attempt limit
    expiration=None              # Optional: expiration timestamp
)
```

#### `recover_encryption_key()`
Recover an encryption key from distributed backup.

```python
key = recover_encryption_key(
    password="user_password",
    auth_code="auth_code_from_generation",
    uid="user@example.com",
    did="device_id", 
    bid="backup_id",
    client=None                  # Optional: custom client
)
```

### Server Discovery

```python
from openadp import discover_servers, get_fallback_servers

# Discover servers from registry
servers = discover_servers("https://servers.openadp.org")

# Get hardcoded fallback servers
fallback = get_fallback_servers()

# Get servers by country
by_country = get_servers_by_country()
us_servers = by_country.get("US", [])
```

### Cryptographic Operations

```python
from openadp.crypto import (
    Point2D, G, H, 
    point_multiply, point_add, point_compress,
    shamir_split, shamir_recover,
    hkdf_derive
)

# Point operations
point = point_multiply(G, 12345)
compressed = point_compress(point)

# Hash to point
hash_point = H("data1", "data2", "data3")

# Shamir secret sharing
shares = shamir_split(secret_bytes, threshold=3, num_shares=5)
recovered = shamir_recover(shares[:3])  # Any 3 shares
```

## Error Handling

The SDK uses structured error handling with specific error codes:

```python
from openadp import OpenADPError, ErrorCode

try:
    key, auth_code = generate_encryption_key(...)
except OpenADPError as e:
    if e.code == ErrorCode.NO_LIVE_SERVERS:
        print("No servers available")
    elif e.code == ErrorCode.AUTHENTICATION_FAILED:
        print("Authentication failed")
    elif e.code == ErrorCode.NETWORK_FAILURE:
        print("Network error")
    else:
        print(f"Error {e.code}: {e.message}")
```

## Testing

Run the test suite to verify the installation:

```bash
# Run built-in tests
python -m openadp.test_client

# Or if installed with console script
openadp-test

# Run with pytest (if installed)
cd sdk/python
pytest tests/
```

## Security Considerations

- **Server Public Keys**: Always verify server public keys through trusted channels
- **Authentication Codes**: Store authentication codes securely - they're required for key recovery
- **Password Security**: Use strong, unique passwords for key generation
- **Network Security**: The SDK uses Noise-NK encryption, but ensure HTTPS for additional protection

## Compatibility

This Python SDK is fully compatible with:
- Go OpenADP implementation (same cryptographic operations)
- OpenADP servers (identical JSON-RPC API)
- Cross-language key recovery (keys generated in Python can be recovered in Go and vice versa)

## Development

### Running Tests

```bash
cd sdk/python
pip install -e ".[dev]"
pytest tests/ -v
```

### Code Formatting

```bash
black openadp/
isort openadp/
mypy openadp/
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

## Support

- **Documentation**: [https://docs.openadp.org](https://docs.openadp.org)
- **Issues**: [GitHub Issues](https://github.com/openadp/openadp/issues)
- **Discussions**: [GitHub Discussions](https://github.com/openadp/openadp/discussions)
- **Email**: contact@openadp.org

## Changelog

### Version 0.1.3
- Initial release with full Go compatibility
- Complete Noise-NK protocol implementation
- Multi-server client with automatic failover
- Comprehensive cryptographic operations
- Cross-language key generation and recovery 
