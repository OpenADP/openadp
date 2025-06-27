# OpenADP C++ SDK

A complete C++ implementation of the OpenADP (Open Advanced Data Protection) distributed cryptography protocol.

## Overview

This C++ SDK provides the same functionality as the Rust, Go, Python, and JavaScript implementations, enabling cross-language compatibility for distributed cryptographic operations.

## Features

- **Distributed Key Generation**: Generate encryption keys using threshold cryptography across multiple servers
- **Secure Recovery**: Recover keys using password-based authentication with rate limiting
- **Cross-Language Compatibility**: Full compatibility with other OpenADP language implementations
- **Noise Protocol**: Secure communication using Noise-NK handshake
- **Ocrypt**: Long-term secret protection with automatic backup refresh
- **Command-Line Tools**: Complete set of tools matching other implementations

## Dependencies

- **C++17** or later
- **OpenSSL** (libssl-dev)
- **libcurl** (libcurl4-openssl-dev)
- **nlohmann/json** (nlohmann-json3-dev)
- **CMake** 3.16 or later

### Ubuntu/Debian Installation

```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev libcurl4-openssl-dev nlohmann-json3-dev
```

### CentOS/RHEL Installation

```bash
sudo yum install gcc-c++ cmake openssl-devel libcurl-devel nlohmann-json-devel
```

## Building

```bash
cd sdk/cpp
mkdir build
cd build
cmake ..
make -j$(nproc)
```

## Installation

```bash
sudo make install
```

This installs:
- Headers to `/usr/local/include/openadp/`
- Library to `/usr/local/lib/libopenadp.a`
- Tools to `/usr/local/bin/`

## Command-Line Tools

### Encrypt/Decrypt Tools

#### openadp-encrypt
```bash
# Encrypt a file
./openadp-encrypt --input secret.txt --output secret.enc --metadata secret.meta --user-id alice@example.com

# With custom password
./openadp-encrypt --input data.bin --output data.enc --metadata data.meta --user-id bob --password mypin
```

#### openadp-decrypt
```bash
# Decrypt a file
./openadp-decrypt --input secret.enc --output secret.txt --metadata secret.meta --user-id alice@example.com

# With custom password
./openadp-decrypt --input data.enc --output data.bin --metadata data.meta --user-id bob --password mypin
```

### Ocrypt Tools

#### ocrypt-register
```bash
# Register a long-term secret
./ocrypt-register --user-id alice@example.com --app-id myapp --long-term-secret "my secret key"

# Save metadata to file
./ocrypt-register --user-id alice --app-id myapp --long-term-secret "secret" --output metadata.json
```

#### ocrypt-recover
```bash
# Recover a secret
./ocrypt-recover --metadata "$(cat metadata.json)"

# Save result to file
./ocrypt-recover --metadata "$(cat metadata.json)" --output result.json --password mypin
```

## Programming API

### Basic Usage

```cpp
#include <openadp.hpp>
using namespace openadp;

// Encrypt data
Identity identity("alice@example.com", "device1", "file://data.txt");
Bytes plaintext = utils::string_to_bytes("Hello, World!");
auto result = encrypt_data(plaintext, identity, "password123");

// Decrypt data
Bytes decrypted = decrypt_data(result.ciphertext, result.metadata, identity, "password123");
std::string message = utils::bytes_to_string(decrypted);
```

### Ocrypt Usage

```cpp
#include <openadp.hpp>
using namespace openadp;

// Register a secret
Bytes secret = utils::string_to_bytes("my long-term secret");
Bytes metadata = ocrypt::register_secret("alice", "myapp", secret, "pin123");

// Recover the secret
auto result = ocrypt::recover(metadata, "pin123");
std::string recovered = utils::bytes_to_string(result.secret);
```

### Advanced Usage

```cpp
#include <openadp.hpp>
using namespace openadp;

// Manual key generation
Identity identity("user", "device", "backup_id");
std::vector<ServerInfo> servers = client::get_servers();

auto gen_result = keygen::generate_encryption_key(identity, "password", 10, 0, servers);
if (gen_result.error) {
    throw OpenADPError(gen_result.error.value());
}

// Manual key recovery
auto rec_result = keygen::recover_encryption_key(identity, "password", 
                                                gen_result.auth_codes.value(), servers);
```

## Architecture

The C++ SDK is organized into several modules:

- **`openadp/types.hpp`** - Core data structures and types
- **`openadp/crypto.hpp`** - Cryptographic operations (Ed25519, AES-GCM, Shamir)
- **`openadp/client.hpp`** - HTTP client and Noise protocol communication
- **`openadp/keygen.hpp`** - Key generation and recovery
- **`openadp/ocrypt.hpp`** - Long-term secret protection
- **`openadp/noise.hpp`** - Noise-NK protocol implementation
- **`openadp/utils.hpp`** - Utility functions (base64, hex, file I/O)

## Cross-Language Compatibility

This C++ implementation is fully compatible with:
- **Rust SDK** - 100% compatible
- **Go SDK** - 100% compatible  
- **Python SDK** - 100% compatible
- **JavaScript SDK** - 100% compatible

All implementations can encrypt/decrypt each other's data and use the same ocrypt metadata format.

## Error Handling

The SDK uses exceptions for error handling:

```cpp
try {
    auto result = encrypt_data(plaintext, identity, password);
    // Success
} catch (const OpenADPError& e) {
    std::cerr << "OpenADP error: " << e.what() << std::endl;
} catch (const std::exception& e) {
    std::cerr << "General error: " << e.what() << std::endl;
}
```

## Security Features

- **Threshold Cryptography**: Requires multiple servers for key operations
- **Rate Limiting**: PIN attempt limits with server-side enforcement
- **Forward Secrecy**: Noise protocol provides forward secrecy
- **Authentication**: Server public key verification
- **Encryption**: AES-256-GCM for data encryption

## Testing

Build and run tests:

```bash
cd build
make test
```

## Examples

See the `examples/` directory for complete example programs demonstrating:
- Basic encryption/decryption
- Ocrypt secret management
- Custom server configurations
- Error handling patterns

## Contributing

This implementation exactly matches the functionality of the Rust SDK. When making changes:

1. Ensure cross-language compatibility is maintained
2. Update tests to verify compatibility with other implementations
3. Follow the existing code style and patterns
4. Update documentation for any API changes

## License

Same license as the main OpenADP project. 