# OpenADP Client

This module provides client-side functionality for interacting with OpenADP servers and performing cryptographic operations.

## Packages

### `client`
High-level client for OpenADP operations:
- Multi-server client with automatic failover
- Server discovery and health checking
- Encrypted communication with servers
- JSON-RPC client implementation

### `keygen`
Key generation and management:
- Distributed key generation using multiple servers
- Threshold key generation
- Integration with secret sharing

### `ocrypt`
Simple 2-function API for distributed password hashing:
- `Register()` - Protect secrets using distributed cryptography
- `Recover()` - Recover secrets with automatic backup refresh
- Replaces traditional password hashing (bcrypt, scrypt, Argon2, PBKDF2)
- Nation-state resistant security

## Usage

### Simple Ocrypt API

```go
import "github.com/openadp/client/ocrypt"

// Register a secret
metadata, err := ocrypt.Register("alice@example.com", "my_app", secret, "password123", 10)
if err != nil {
    log.Fatal(err)
}

// Later, recover the secret
recoveredSecret, remaining, updatedMetadata, err := ocrypt.Recover(metadata, "password123")
if err != nil {
    log.Fatal(err)
}
```

### Advanced Client Usage

```go
import "github.com/openadp/client/client"

// Create client with server discovery
client := client.NewClient("https://servers.openadp.org/servers.json", nil, 10*time.Second, 10)

// Or create with specific servers
serverInfos := []client.ServerInfo{
    {URL: "https://server1.example.com", PublicKey: "..."},
    {URL: "https://server2.example.com", PublicKey: "..."},
}
client := client.NewClientWithServerInfo(serverInfos, 10*time.Second, 10)
```

## Dependencies

- `github.com/openadp/common` - Shared cryptographic primitives
- `golang.org/x/term` - Terminal utilities 