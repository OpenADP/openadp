# OpenADP Module Reorganization

This document describes the reorganization of the OpenADP Go library from a single monolithic module into three focused modules for better developer experience and maintainability.

## Overview

The OpenADP codebase has been reorganized from 10 packages in a single `pkg/` directory into 3 focused modules:

1. **`github.com/openadp/common`** - Shared cryptographic primitives
2. **`github.com/openadp/client`** - Client-side functionality  
3. **`github.com/openadp/server`** - Server-side functionality

## Module Structure

### Common Module (`github.com/openadp/common`)
**Purpose**: Shared cryptographic primitives used by both client and server

**Packages**:
- `crypto/` - Ed25519 operations, point arithmetic, OPRF utilities
- `noise/` - Noise protocol implementation for secure communications
- `sharing/` - Shamir's Secret Sharing and threshold cryptography

**Dependencies**: 
- `github.com/flynn/noise`
- `golang.org/x/crypto`

### Client Module (`github.com/openadp/client`)
**Purpose**: Client-side functionality for interacting with OpenADP servers

**Packages**:
- `client/` - Multi-server client with failover and server discovery
- `keygen/` - Distributed key generation using multiple servers
- `ocrypt/` - Simple 2-function API for distributed password hashing

**Dependencies**:
- `github.com/openadp/common`
- `golang.org/x/term`

### Server Module (`github.com/openadp/server`)
**Purpose**: Server-side functionality for running OpenADP servers

**Packages**:
- `server/` - Core business logic, OPRF evaluation, session management
- `database/` - SQLite storage, share management, guess tracking
- `middleware/` - HTTP middleware, authentication, logging
- `auth/` - Authentication and authorization components

**Dependencies**:
- `github.com/openadp/common`
- `github.com/gorilla/mux`
- `modernc.org/sqlite`

## Migration from Old Structure

### Old Structure (10 packages)
```
pkg/
├── ocrypt/      → client/ocrypt/
├── client/      → client/client/
├── keygen/      → client/keygen/
├── crypto/      → common/crypto/
├── noise/       → common/noise/
├── sharing/     → common/sharing/
├── server/      → server/server/
├── database/    → server/database/
├── middleware/  → server/middleware/
└── auth/        → server/auth/
```

### New Structure (3 modules)
```
common/
├── crypto/
├── noise/
└── sharing/

client/
├── client/
├── keygen/
└── ocrypt/

server/
├── server/
├── database/
├── middleware/
└── auth/
```

## Benefits

1. **Clearer Dependencies**: Each module has a focused purpose with minimal dependencies
2. **Better Developer Experience**: Developers can import only what they need
3. **Easier Discovery**: Clear separation between client and server functionality
4. **Reduced Complexity**: Smaller, focused modules are easier to understand and maintain
5. **Publishing Ready**: Each module can be published independently with semantic versioning

## Usage Examples

### For Client Developers
```go
// Simple password hashing replacement
import "github.com/openadp/client/ocrypt"

metadata, err := ocrypt.Register("user@example.com", "myapp", secret, "password", 10)
// ... store metadata ...
secret, remaining, newMetadata, err := ocrypt.Recover(metadata, "password")
```

### For Server Developers
```go
// Run an OpenADP server
import (
    "github.com/openadp/server/server"
    "github.com/openadp/server/database"
)

db, err := database.NewDatabase("server.db")
err = server.RegisterSecret(db, uid, did, bid, authCode, version, x, y, maxGuesses, expiration)
```

### For Cryptography Developers
```go
// Use low-level cryptographic primitives
import (
    "github.com/openadp/common/crypto"
    "github.com/openadp/common/sharing"
)

point := crypto.GenerateRandomPoint()
shares := sharing.GenerateShares(secret, threshold, numShares)
```

## Next Steps

1. **Publish Modules**: Publish each module to their respective GitHub repositories
2. **Update Documentation**: Update all documentation to reference the new module structure
3. **Migrate Examples**: Update all examples and demos to use the new imports
4. **Update CI/CD**: Modify build and test pipelines for the new structure
5. **Deprecate Old Structure**: Gradually deprecate the old monolithic structure

## Testing

All three modules have been verified to build successfully:
- ✅ `github.com/openadp/common` builds without errors
- ✅ `github.com/openadp/client` builds without errors  
- ✅ `github.com/openadp/server` builds without errors

The reorganization maintains all existing functionality while providing a cleaner, more maintainable structure for developers. 