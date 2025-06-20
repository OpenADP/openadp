# OpenADP Server API Documentation

This document describes the JSON-RPC API for OpenADP servers, including method signatures, parameters, responses, and authentication requirements.

## Overview

OpenADP servers implement a JSON-RPC 2.0 API over HTTP for distributed secret sharing operations. All methods use **positional parameters** (arrays) and **PascalCase** method names.

### Base URL
```
POST http://server:port/
Content-Type: application/json
```

### Authentication
- All methods except `Echo` and `GetServerInfo` require **Noise-NK encryption**
- Authentication uses **256-bit authentication codes** derived per-server
- Auth codes are passed as the first parameter in most methods

---

## API Methods

### 1. RegisterSecret

Registers a secret share with the server for distributed storage.

**Method:** `RegisterSecret`

**Parameters:** `[auth_code, uid, did, bid, version, x, y, max_guesses, expiration]`

| Position | Parameter | Type | Description |
|----------|-----------|------|-------------|
| 0 | `auth_code` | string | 64-char hex authentication code (SHA256) |
| 1 | `uid` | string | User identifier |
| 2 | `did` | string | Device identifier |
| 3 | `bid` | string | Backup identifier |
| 4 | `version` | int | Share version number |
| 5 | `x` | int | Shamir share X coordinate |
| 6 | `y` | string | Shamir share Y coordinate (base64 encoded) |
| 7 | `max_guesses` | int | Maximum recovery attempts allowed |
| 8 | `expiration` | int | Unix timestamp expiration |

**Response:** `boolean`
- `true` if registration successful
- `false` if registration failed

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "RegisterSecret",
  "params": [
    "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
    "user@example.com",
    "device-123",
    "file://backup.tar.gz",
    1,
    42,
    "dGVzdCBkYXRh",
    10,
    1735689600
  ],
  "id": 1
}
```

**Example Response:**
```json
{
  "jsonrpc": "2.0",
  "result": true,
  "id": 1
}
```

---

### 2. RecoverSecret

Recovers a secret share using primary key lookup and authentication verification.

**Method:** `RecoverSecret`

**Parameters:** `[auth_code, uid, did, bid, b, guess_num]`

| Position | Parameter | Type | Description |
|----------|-----------|------|-------------|
| 0 | `auth_code` | string | 64-char hex authentication code |
| 1 | `uid` | string | User identifier (primary key) |
| 2 | `did` | string | Device identifier (primary key) |
| 3 | `bid` | string | Backup identifier (primary key) |
| 4 | `b` | string | Point B (base64 encoded compressed point) |
| 5 | `guess_num` | int | Current guess number (for idempotency) |

**Response:** `object`
```json
{
  "version": int,
  "x": int,
  "si_b": string,  // base64 encoded result point
  "num_guesses": int,
  "max_guesses": int,
  "expiration": int
}
```

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "RecoverSecret",
  "params": [
    "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
    "user@example.com",
    "device-123", 
    "file://backup.tar.gz",
    "dGVzdCBwb2ludA==",
    0
  ],
  "id": 1
}
```

**Example Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "version": 1,
    "x": 42,
    "si_b": "cmVzdWx0IHBvaW50",
    "num_guesses": 1,
    "max_guesses": 10,
    "expiration": 1735689600
  },
  "id": 1
}
```

**Error Cases:**
- `"invalid auth code"` - Auth code doesn't match stored value
- `"share not found"` - No share found for UID+DID+BID
- `"too many guesses"` - Exceeded max_guesses limit
- `"expecting guess_num = N"` - Wrong guess number for idempotency

---

### 3. ListBackups

Lists all backups for a specific user.

**Method:** `ListBackups`

**Parameters:** `[uid]`

| Position | Parameter | Type | Description |
|----------|-----------|------|-------------|
| 0 | `uid` | string | User identifier |

**Response:** `array` of backup objects
```json
[
  {
    "uid": string,
    "did": string,
    "bid": string,
    "version": int,
    "num_guesses": int,
    "max_guesses": int,
    "expiration": int
  }
]
```

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "ListBackups",
  "params": ["user@example.com"],
  "id": 1
}
```

**Example Response:**
```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "uid": "user@example.com",
      "did": "device-123",
      "bid": "file://backup.tar.gz",
      "version": 1,
      "num_guesses": 2,
      "max_guesses": 10,
      "expiration": 1735689600
    }
  ],
  "id": 1
}
```

---

### 4. Echo

Simple connectivity test method (no authentication required).

**Method:** `Echo`

**Parameters:** `[message]`

| Position | Parameter | Type | Description |
|----------|-----------|------|-------------|
| 0 | `message` | string | Message to echo back |

**Response:** `string` - Same message echoed back

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "Echo",
  "params": ["ping"],
  "id": 1
}
```

**Example Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "ping",
  "id": 1
}
```

---

### 5. GetServerInfo

Retrieves server information including public keys (no authentication required).

**Method:** `GetServerInfo`

**Parameters:** `null` or `[]`

**Response:** `object`
```json
{
  "version": string,
  "noise_nk_public_key": string,  // base64 encoded public key
  "server_id": string,
  "capabilities": array
}
```

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "GetServerInfo",
  "params": null,
  "id": 1
}
```

**Example Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "version": "1.0",
    "noise_nk_public_key": "cHVibGljS2V5RGF0YQ==",
    "server_id": "server-001",
    "capabilities": ["secret_sharing", "noise_nk"]
  },
  "id": 1
}
```

---

## Authentication Details

### Authentication Codes
- **Format:** 64-character hexadecimal string (SHA256 hash)
- **Generation:** Server-specific codes derived from base code + server URL
- **Derivation:** `SHA256(base_auth_code + ":" + server_url)`
- **Validation:** Minimum 100 bits of entropy required

### Noise-NK Encryption
- **Required for:** `RegisterSecret`, `RecoverSecret`, `ListBackups`
- **Optional for:** `Echo`, `GetServerInfo`
- **Protocol:** Noise-NK with Ed25519 keys
- **Handshake:** 2-round pattern with forward secrecy

---

## Error Handling

### Standard JSON-RPC Errors
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32603,
    "message": "Internal error",
    "data": "Additional error details"
  },
  "id": 1
}
```

### Common Error Codes
- `-32700` Parse error - Invalid JSON
- `-32600` Invalid Request - Invalid JSON-RPC
- `-32601` Method not found
- `-32602` Invalid params - Wrong parameter count/type
- `-32603` Internal error - Server-side errors

### Application-Specific Errors
- `"invalid auth code"` - Authentication failed
- `"share not found"` - Record not found in database
- `"too many guesses"` - Exceeded attempt limit
- `"expecting guess_num = N"` - Idempotency check failed
- `"invalid y coordinate"` - Y value >= prime modulus
- `"RecoverSecret requires Noise-NK encryption"` - Encryption required

---

## Database Schema

### Shares Table
```sql
CREATE TABLE shares(
    UID TEXT NOT NULL,           -- User identifier
    DID TEXT NOT NULL,           -- Device identifier  
    BID TEXT NOT NULL,           -- Backup identifier
    auth_code TEXT NOT NULL,     -- Authentication code
    version INTEGER NOT NULL,    -- Share version
    x INTEGER NOT NULL,          -- Shamir X coordinate
    y BLOB NOT NULL,            -- Shamir Y coordinate (binary)
    num_guesses INTEGER NOT NULL, -- Current guess count
    max_guesses INTEGER NOT NULL, -- Maximum allowed guesses
    expiration INTEGER NOT NULL,  -- Unix timestamp
    PRIMARY KEY(UID, DID, BID)   -- Composite primary key
);
```

### Server Config Table
```sql
CREATE TABLE server_config(
    key TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
);
```

---

## Security Considerations

1. **Authentication Codes**
   - Must be cryptographically random (128+ bits entropy)
   - Server-specific derivation prevents replay attacks
   - Stored securely in database for verification

2. **Noise-NK Encryption**
   - Mandatory for sensitive operations
   - Provides forward secrecy and authentication
   - Prevents eavesdropping and tampering

3. **Rate Limiting**
   - DDoS protection with configurable limits
   - Failed attempt tracking per IP address
   - Automatic blacklisting of suspicious codes

4. **Input Validation**
   - Parameter count and type checking
   - Cryptographic point validation
   - Expiration time verification

5. **Database Security**
   - Parameterized queries prevent SQL injection
   - WAL mode for concurrent access
   - Proper transaction handling

---

## Client Implementation Notes

### Parameter Order
Always use **positional parameters** in the exact order specified. Named parameters are not supported.

### Method Names  
Use **PascalCase** method names (`RegisterSecret`, not `register_secret`).

### Point Encoding
- Points must be **base64 encoded** compressed Ed25519 points
- Y coordinates are validated against prime modulus P
- Invalid points are rejected with specific error messages

### Guess Number Tracking
- Use `ListBackups` to get current `num_guesses` before recovery
- Pass correct `guess_num` for idempotency
- Retry with server-suggested number if mismatch occurs

### Error Handling
- Always check for JSON-RPC error responses
- Handle application-specific error messages
- Implement exponential backoff for rate limiting

---

## Example Client Flow

### 1. Registration Flow
```bash
# 1. Get server info (optional)
POST /
{"jsonrpc":"2.0","method":"GetServerInfo","params":null,"id":1}

# 2. Register secret share
POST /
{"jsonrpc":"2.0","method":"RegisterSecret","params":[auth_code,uid,did,bid,version,x,y,max_guesses,expiration],"id":2}
```

### 2. Recovery Flow  
```bash
# 1. List backups to get current guess number
POST /
{"jsonrpc":"2.0","method":"ListBackups","params":[uid],"id":1}

# 2. Recover secret share
POST /
{"jsonrpc":"2.0","method":"RecoverSecret","params":[auth_code,uid,did,bid,b,guess_num],"id":2}
```

---

## Version History

- **v1.0** - Initial API with snake_case methods and named parameters
- **v2.0** - **Current** - PascalCase methods, positional parameters, improved auth flow

---

For implementation details, see:
- `cmd/openadp-server/main.go` - Server handlers
- `pkg/server/server.go` - Business logic
- `pkg/client/` - Client implementations 