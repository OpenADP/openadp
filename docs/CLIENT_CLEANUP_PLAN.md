# OpenADP Client Cleanup Plan

## Overview
This document outlines the recommended cleanup actions for the OpenADP Go client before implementing clients in other languages (Python, JavaScript, Java).

## Current Client Architecture Issues

### 1. **Multiple Overlapping Client Implementations**
- `OpenADPClient` (477 lines) - Basic JSON-RPC client
- `EncryptedOpenADPClient` (385 lines) - Extends basic client with Noise-NK encryption
- `Client` (366 lines) - High-level multi-server client  
- `ClientManager` - Legacy multi-client manager (embedded in jsonrpc_client.go)

### 2. **Inconsistent API Signatures**
Different method signatures across client types make it confusing for users:

```go
// OpenADPClient
RegisterSecret(uid, did, bid string, version, x int, y string, maxGuesses, expiration int) (bool, error)

// EncryptedOpenADPClient  
RegisterSecret(authCode, uid, did, bid string, version, x int, y string, maxGuesses, expiration int, encrypted bool, authData map[string]interface{}) (bool, error)

// High-level Client
RegisterSecret(uid, did, bid string, version, x int, y []byte, maxGuesses, expiration int, authData map[string]interface{}) (bool, error)
```

### 3. **Mixed Data Types**
- Point data: sometimes `string` (base64), sometimes `[]byte`, sometimes `*crypto.Point2D`
- Auth codes: inconsistent parameter ordering and optional vs required

### 4. **Large Files with Mixed Responsibilities**
- `jsonrpc_client.go` contains both basic client AND client manager
- `encrypted_client.go` mixes client logic with auth utilities

## Cleanup Plan

### Phase 1: Interface Standardization ✅ **COMPLETED**

**Status**: ✅ Created `pkg/client/interfaces.go` with standardized interfaces

**Benefits for Multi-Language Implementation**:
- Clear, consistent API contract
- JSON-serializable request/response types
- Standardized error codes and handling
- Language-agnostic design

### Phase 2: Remove Legacy Code (Recommended)

**Actions**:
1. **Remove `ClientManager`** from `jsonrpc_client.go` - functionality merged into high-level `Client`
2. **Remove duplicate auth methods**:
   - `ListBackupsWithAuthCode()` → use `ListBackups()` with auth parameter
   - `RegisterSecretWithAuthCode()` → standardize auth code handling
3. **Remove unused structs**:
   - `RegisterSecretParams`, `RecoverSecretParams` (replaced by interface types)

**Files to modify**:
- `pkg/client/jsonrpc_client.go` - Remove ClientManager and duplicate methods
- `pkg/client/encrypted_client.go` - Remove redundant convenience functions

### Phase 3: API Standardization (Recommended)

**Actions**:
1. **Standardize parameter types**:
   - All point data as `string` (base64 encoded) for cross-language compatibility
   - Consistent auth code parameter positioning
   - Unified response formats

2. **Update existing clients to implement new interfaces**:
   ```go
   // Make existing clients implement the new interfaces
   func (c *Client) RegisterSecret(request *RegisterSecretRequest) (*RegisterSecretResponse, error)
   func (c *EncryptedOpenADPClient) RegisterSecret(request *RegisterSecretRequest) (*RegisterSecretResponse, error)
   ```

**Files to modify**:
- `pkg/client/client.go` - Update to implement `MultiServerClientInterface`
- `pkg/client/encrypted_client.go` - Update to implement `OpenADPClientInterface`

### Phase 4: File Reorganization (Optional)

**Actions**:
1. **Split large files**:
   - `basic_client.go` - Core JSON-RPC client functionality
   - `encrypted_client.go` - Noise-NK encryption functionality only
   - `multi_server_client.go` - High-level multi-server management
   - `auth_utils.go` - Authentication utilities

2. **Consolidate utilities**:
   - Move all server discovery logic to `scrape.go`
   - Centralize error handling utilities

## Benefits for Multi-Language Implementation

### 1. **Clear API Contract**
The new interfaces provide a clear contract that can be implemented in any language:

```python
# Python example
class OpenADPClient(OpenADPClientInterface):
    def register_secret(self, request: RegisterSecretRequest) -> RegisterSecretResponse:
        # Implementation
        pass
```

### 2. **JSON-Based Communication**
All request/response types are designed for JSON serialization:

```javascript
// JavaScript example
const request = {
    auth_code: "...",
    uid: "user123",
    did: "device456", 
    bid: "backup789",
    version: 1,
    x: 42,
    y: "base64encodedpoint...",
    max_guesses: 10,
    expiration: 0
};

const response = await client.registerSecret(request);
```

### 3. **Consistent Error Handling**
Standardized error codes work across all languages:

```java
// Java example
try {
    RegisterSecretResponse response = client.registerSecret(request);
} catch (OpenADPException e) {
    if (e.getCode() == ErrorCode.AUTHENTICATION_FAILED) {
        // Handle auth failure
    }
}
```

### 4. **Server Discovery**
The server discovery mechanism in `scrape.go` provides a language-agnostic way to find servers:

```json
{
    "servers": [
        {
            "url": "https://server1.openadp.org",
            "public_key": "ed25519:ABC123...",
            "country": "US"
        }
    ]
}
```

## Implementation Priority

### **High Priority** (Essential before multi-language work):
- ✅ Interface definition (completed)
- Remove legacy/duplicate code
- Standardize API signatures

### **Medium Priority** (Helpful but not blocking):
- File reorganization
- Enhanced error handling
- Performance optimizations

### **Low Priority** (Nice to have):
- Additional server selection strategies
- Advanced caching mechanisms
- Metrics and monitoring hooks

## Next Steps

1. **Review and approve** this cleanup plan
2. **Implement Phase 2** (remove legacy code) - ~2-4 hours
3. **Implement Phase 3** (API standardization) - ~4-6 hours  
4. **Test thoroughly** with existing integration tests
5. **Begin multi-language implementations** using the standardized interfaces

## Multi-Language Implementation Guide

Once cleanup is complete, implementing clients in other languages becomes straightforward:

### Python Client Structure:
```
openadp-python/
├── openadp/
│   ├── client.py           # Main client implementation
│   ├── interfaces.py       # Interface definitions (from Go)
│   ├── crypto.py          # Ed25519 operations
│   ├── noise.py           # Noise-NK protocol
│   └── errors.py          # Error types
├── tests/
└── setup.py
```

### JavaScript Client Structure:
```
openadp-js/
├── src/
│   ├── client.js          # Main client implementation  
│   ├── interfaces.js      # Interface definitions
│   ├── crypto.js          # Ed25519 operations
│   ├── noise.js           # Noise-NK protocol
│   └── errors.js          # Error types
├── test/
└── package.json
```

The standardized interfaces ensure all language implementations provide the same API surface and behavior. 