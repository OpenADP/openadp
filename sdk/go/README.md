# Ocrypt - Distributed Oblivious Password Hashing

[![Go Reference](https://pkg.go.dev/badge/github.com/openadp/ocrypt.svg)](https://pkg.go.dev/github.com/openadp/ocrypt)
[![Go Report Card](https://goreportcard.com/badge/github.com/openadp/ocrypt)](https://goreportcard.com/report/github.com/openadp/ocrypt)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Ocrypt is a distributed password-strengthening algorithm that provides secure,
threshold-based secret recovery using a simple pin as input. It's designed as a
drop-in replacement for PBKDF2/bcrypt/Scrypt/Argon2 with enhanced security
through distributed trust and oblivious cryptography.  By "oblivious" we mean
no information about your pin ever leaves your device.  The servers are
"oblivious".

## ✨ Features

- **Simple API**: Just 2 functions - `Register()` and `Recover()`
- **Distributed Security**: Uses multiple servers for threshold-based recovery
- **Password-Based**: Familiar bcrypt-style interface
- **Cryptographically Secure**: Built on Ed25519, Noise-NK Protocol, and Shamir's Secret Sharing
- **Low Dependencies**: Self-contained cryptographic implementations

## Is this really a password hash?

Yes.  The goal of advanced password hashing algorithms is to "strengthen"" or
"stretch" your low-entropy password into a secret that is harder to brute-force
guess.  However, for a simple 4-digit pin, no self-contained password hashing
algorithm can protect you. Password hashing algorithms are used to:

1) Limit damage from password database breeches.
2) Derive encryption keys for disk encryption, password managers, etc.
3) Authenticate you with less risk of revealing your password.

Ocrypt does all of this, but more securely. Network access is required, but if
that's OK for your application, it raises your defense level significantly. An
attacker would need both access to data on your device, and also to hack a
threshold of OpenADP servers.

## 🚀 Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/openadp/ocrypt/ocrypt"
)

func main() {
    // Register a secret (like bcrypt.GenerateFromPassword)
    metadata, err := ocrypt.Register("user123", "myapp", "my-secret-data", "password123")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Secret registered! Metadata: %s\n", metadata)
    
    // Recover the secret (like bcrypt.CompareHashAndPassword)
    secret, err := ocrypt.Recover(metadata, "password123")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Recovered secret: %s\n", secret)
}
```

## 📦 Installation

```bash
go get github.com/openadp/ocrypt
```

## 🏗️ Architecture

Ocrypt consists of several focused packages:

### Core Packages

- **`ocrypt/`** - Simple 2-function API (Register/Recover)
- **`client/`** - Multi-server client with automatic failover
- **`keygen/`** - Distributed key generation and recovery

### Cryptographic Primitives

- **`crypto/`** - Ed25519 utilities and OPRF implementations
- **`noise/`** - Noise Protocol Framework for secure communications
- **`sharing/`** - Shamir's Secret Sharing implementation

## 🔧 Advanced Usage

### Custom Server Configuration

```go
import "github.com/openadp/ocrypt/keygen"

// Generate encryption key with custom servers
servers := []string{
    "https://server1.example.com",
    "https://server2.example.com", 
    "https://server3.example.com",
}

key, authCodes, err := keygen.GenerateEncryptionKey(
    "filename.txt",
    "user123", 
    5, // max guesses
    2, // threshold (2 of 3 servers needed)
    servers,
)
```

### Multi-Server Client

```go
import "github.com/openadp/ocrypt/client"

// Create client with multiple servers
client := client.NewMultiServerClient(servers, 30*time.Second)

// The client automatically handles:
// - Server discovery and health checks
// - Load balancing and failover
// - Connection pooling
// - Retry logic
```

### Direct Cryptographic Operations

```go
import (
    "github.com/openadp/ocrypt/crypto"
    "github.com/openadp/ocrypt/sharing"
)

// Generate Ed25519 keypair
privateKey, publicKey, err := crypto.GenerateKeypair()

// Create secret shares (3-of-5 threshold)
shares, err := sharing.MakeRandomShares(secret, 5, 3)

// Recover secret from shares
recovered, err := sharing.RecoverSecret(shares[:3])
```

## 🔒 Security Features

- **Threshold Cryptography**: Requires multiple servers for secret recovery
- **Forward Secrecy**: Uses ephemeral keys for each session
- **Authenticated Encryption**: All communications are authenticated and encrypted
- **Rate Limiting**: Built-in protection against brute force attacks
- **Zero-Knowledge**: Servers never see plaintext passwords or secrets

## 🌐 Server Compatibility

Ocrypt is designed to work with OpenADP servers but can be adapted to other threshold cryptography systems. The protocol is based on:

- **JSON-RPC 2.0** for API communication
- **Noise NK** for secure channel establishment
- **Ed25519** for digital signatures
- **Curve25519** for key exchange

## 📚 Documentation

- [API Reference](https://pkg.go.dev/github.com/openadp/ocrypt)
- [Security Architecture](docs/security.md)
- [Protocol Specification](docs/protocol.md)
- [Examples](examples/)

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built on the [Noise Protocol Framework](https://noiseprotocol.org/)
- Uses [Ed25519](https://ed25519.cr.yp.to/) for digital signatures
- Implements [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) 
