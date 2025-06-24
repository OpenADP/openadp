# OpenADP Common

This module contains shared cryptographic primitives and utilities used by both OpenADP client and server components.

## Packages

### `crypto`
Core cryptographic operations including:
- Ed25519 elliptic curve operations
- Point arithmetic and validation
- Cryptographic utilities for OPRF (Oblivious Pseudo-Random Function)

### `noise`
Noise protocol implementation for secure communications:
- Noise NK pattern implementation
- Secure channel establishment
- Message encryption/decryption

### `sharing`
Secret sharing implementation:
- Shamir's Secret Sharing
- Threshold cryptography utilities
- Share generation and reconstruction

## Usage

```go
import (
    "github.com/openadp/common/crypto"
    "github.com/openadp/common/noise"
    "github.com/openadp/common/sharing"
)
```

## Dependencies

- `github.com/flynn/noise` - Noise protocol implementation
- `golang.org/x/crypto` - Extended cryptographic primitives 