# Ocrypt Password Hashing Functions - Design Document

## Overview

Ocrypt provides a drop-in replacement for traditional password hashing functions (bcrypt, scrypt, Argon2, PBKDF2) that leverages OpenADP's distributed threshold cryptography for nation-state-resistant password protection.

The name "Ocrypt" reflects the underlying **Oblivious Pseudo Random Function (OPRF)** cryptography that enables secure, distributed key protection without revealing secrets to individual servers.

## Core API

```python
# Register a long-term secret protected by a PIN
ocrypt.register(user_id: str, app_id: str, long_term_secret: bytes, pin: str, backup_id: str, max_guesses: int = 10) -> bytes

# Recover the long-term secret using the PIN with automatic backup refresh
ocrypt.recover(metadata: bytes, pin: str) -> (bytes, int, bytes)
```

The simplified API provides:
- **`register()`**: Initial registration with developer-specified backup ID
- **`recover()`**: Recovery with automatic backup refresh using two-phase commit for crash safety

## Design Principles

### 1. **User-Controlled Secrets**
Users provide their own `long_term_secret` rather than having the system generate it. This enables flexible use cases:

- **Cryptographic Keys**: Protect any binary secrets like private keys
- **API Tokens**: Secure service credentials (Stripe, AWS, GitHub)
- **Database Keys**: Protect AES encryption keys for database encryption
- **Authentication Secrets**: Replace bcrypt hashes with distributed protection

### 2. **Metadata-Based Storage**
Instead of storing salts and password hashes, applications store an opaque metadata blob:

```python
# Traditional approach
user_record = {
    "email": "alice@example.com",
    "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCO...",
    "salt": "LQv3c1yqBWVHxkd0LHAkCO"
}

# Ocrypt approach  
user_record = {
    "email": "alice@example.com", 
    "ocrypt_metadata": b"eyJzZXJ2ZXJzIjpbImh0dHBzOi8v..."  # Self-contained blob
}
```

### 3. **Instant PIN Validation**
Ocrypt enables offline PIN validation through wrapped secrets:
- Correct PIN → AES-GCM decryption succeeds → return secret
- Wrong PIN → AES-GCM decryption fails → reject immediately
- No network round-trip needed for PIN validation

### 4. **Automatic Backup Refresh with Two-Phase Commit**
Recovery automatically refreshes backups using a two-phase commit pattern for crash safety:
- **Phase 1 (PREPARE)**: Register new backup with different backup_id
- **Phase 2 (COMMIT)**: Verify new backup works by recovering from it
- **Safety**: Old backups remain valid until new ones are confirmed working
- **Resilience**: Network failures during refresh don't cause lockouts

### 5. **Load Balancing**
When more than 15 servers are available, Ocrypt randomly selects a subset of 15 servers to distribute load evenly across the OpenADP network. This prevents overloading early servers in the registry list and ensures fair resource utilization.

## Current OpenADP Architecture (Based on detailed-design.md)

### Authentication & Authorization
- **Authentication Codes**: Auto-generated 256-bit random base auth code + server-specific derived codes
- **Base Auth Code**: `secrets.token_bytes(32).hex()` (64-character hex string)
- **Server Auth Codes**: `SHA256(base_auth_code + ":" + server_url).hex()` for each server
- **Transport**: JSON-RPC 2.0 over Noise-NK encrypted channels (when public keys available)

### Cryptographic Foundation
- **Curve**: Ed25519 with field GF(2²⁵⁵ - 19)
- **Hash-to-Curve**: `U = H(UUID, DID, BID, pin)` using SHA-256 + rejection sampling
- **Secret Generation**: Random 256-bit secret `s ∈ [1, q-1]` 
- **Key Derivation**: `enc_key = HKDF(S.x | S.y)` where `S = s · U`
- **Threshold Sharing**: Shamir secret sharing with polynomial interpolation
- **Server Communication**: JSON-RPC 2.0 (`RegisterSecret`, `RecoverSecret`, `Echo`)

## Implementation Architecture

### Core Algorithm

**Ocrypt Register Flow:**
```python
# Public API - defaults to "even" backup_id for simplicity
def register(user_id: str, app_id: str, long_term_secret: bytes, pin: str, max_guesses: int = 10) -> bytes:
    return _register_with_bid(user_id, app_id, long_term_secret, pin, max_guesses, "even")

# Private implementation - handles the actual OpenADP registration
def _register_with_bid(user_id: str, app_id: str, long_term_secret: bytes, pin: str, max_guesses: int = 10, backup_id: str = "even") -> bytes:
         # 1. Auto-discover live servers from https://servers.openadp.org/api/servers.json
     all_live_servers = discover_servers()  # Tests liveness with Echo RPC + gets public keys
     
     # 2. Random server selection for load balancing
     if len(all_live_servers) > 15:
         live_servers = random.sample(all_live_servers, 15)  # Random subset of 15
     else:
         live_servers = all_live_servers  # Use all available servers
     
     N = len(live_servers)              # Number of selected servers
     T = N // 2 + 1                     # Threshold = floor(N/2) + 1
    
              # 3. Use default "even" backup ID for initial registration
     # Recovery will automatically alternate to "odd" for backup refresh
    
         # 4. Generate encryption key using identical method as openadp-encrypt
     enc_key, auth_codes = generate_encryption_key(
                 filename=f"{user_id}#{app_id}#{backup_id}",
        password=pin,
        user_id=user_id,
        max_guesses=max_guesses,
        server_infos=live_servers
    )
    
         # 5. Wrap the user's long-term secret with AES-256-GCM
     nonce = secrets.token_bytes(12)
     cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
     wrapped_secret, tag = cipher.encrypt_and_digest(long_term_secret)
     
     # 6. Create metadata blob (compatible with openadp-encrypt format + extensions)
    metadata = {
        # Standard openadp-encrypt fields
        "servers": server_urls,
        "threshold": T,
        "version": "1.0", 
        "auth_code": auth_codes.base_auth_code,
        "user_id": user_id,
        
        # Ocrypt extensions
        "wrapped_long_term_secret": {
            "nonce": base64.encode(nonce),
            "ciphertext": base64.encode(wrapped_secret),
            "tag": base64.encode(tag)
        },
                 "backup_id": backup_id,
        "app_id": app_id,
        "max_guesses": max_guesses,
        "ocrypt_version": "1.0"
    }
    
    return json.dumps(metadata).encode()
```

**Ocrypt Recover Flow:**
```python
def recover(metadata: bytes, pin: str) -> (bytes, int, bytes):
    # 1. Recover secret using existing backup
    secret, remaining = _recover_without_refresh(metadata, pin)
    
    # 2. Attempt automatic backup refresh with two-phase commit
    try:
        meta = json.loads(metadata.decode())
        current_backup_id = meta["backup_id"]
        user_id = meta["user_id"]
        app_id = meta["app_id"]
        max_guesses = meta.get("max_guesses", 10)
        
        # Two-phase commit backup refresh
        new_metadata, new_backup_id = _register_with_commit_internal(
            user_id, app_id, secret, pin, current_backup_id, max_guesses
        )
        
        # Return secret with updated metadata
        return secret, remaining, new_metadata
        
    except Exception:
        # Backup refresh failed, but recovery still succeeded
        return secret, remaining, metadata

def _recover_without_refresh(metadata: bytes, pin: str) -> (bytes, int):
    # 1. Parse metadata and validate format
    meta = json.loads(metadata.decode())
    
    # 2. Recover encryption key using identical method as openadp-decrypt
    enc_key = recover_encryption_key(
        filename=f"{meta['user_id']}#{meta['app_id']}#{meta['backup_id']}",
        password=pin,
        user_id=meta["user_id"],
        server_infos=get_server_info(meta["servers"]),
        threshold=meta["threshold"],
        auth_codes=reconstruct_auth_codes(meta["auth_code"], meta["servers"])
    )
    
    # 3. Validate PIN by attempting to unwrap long-term secret
    try:
        wrapped_data = meta["wrapped_long_term_secret"]
        nonce = base64.decode(wrapped_data["nonce"])
        ciphertext = base64.decode(wrapped_data["ciphertext"]) 
        tag = base64.decode(wrapped_data["tag"])
        
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
        long_term_secret = cipher.decrypt_and_verify(ciphertext, tag)
        
        # PIN was correct!
    except Exception:
        raise Exception("Invalid PIN or corrupted data")
    
    return long_term_secret, 0  # 0 remaining guesses = success

def _register_with_commit_internal(user_id: str, app_id: str, secret: bytes, pin: str, 
                                  current_backup_id: str, max_guesses: int) -> (bytes, str):
    # Generate next backup ID using smart strategies
    new_backup_id = _generate_next_backup_id(current_backup_id)
    
    # Phase 1: PREPARE - Register new backup (old one still exists)
    new_metadata = _register_with_bid(user_id, app_id, secret, pin, max_guesses, new_backup_id)
    
    # Phase 2: COMMIT - Verify new backup works
    recovered_secret, remaining = _recover_without_refresh(new_metadata, pin)
    
    if recovered_secret == secret:
        # New backup verified - commit the change
        return new_metadata, new_backup_id
    else:
        raise Exception("Two-phase commit verification failed")
```

### Automatic Backup Refresh with Two-Phase Commit

**Problem**: Backups should be refreshed periodically for security, but registration could crash halfway through, corrupting the ability to recover secrets.

**Solution**: Automatic backup refresh with two-phase commit safety:

```python
# Initial registration - defaults to "even" backup ID
metadata = register(user_id, app_id, secret, pin)

# Later recovery - automatic backup refresh with crash safety
secret, remaining, updated_metadata = recover(metadata, pin)
# updated_metadata now contains refreshed backup (even → odd)

# Application should store updated_metadata for future recoveries
store_metadata(user_id, updated_metadata)
```

**Two-Phase Commit Process**:
1. **Phase 1 (PREPARE)**: Register new backup with different backup_id (e.g., `v1` → `v2`)
2. **Phase 2 (COMMIT)**: Verify new backup works by recovering secret from it
3. **Safety Guarantee**: Old backup remains valid until new one is verified
4. **Failure Handling**: If refresh fails, original metadata is returned and recovery still succeeds

**Backup ID Generation Strategies**:
- **Alternation**: `even` ↔ `odd`
- **Versioning**: `v1` → `v2` → `v3`
- **Timestamped**: `production` → `production_v1750710608`

**Architecture**:
- **Public `register()`**: Initial registration with default "even" backup_id
- **Public `recover()`**: Recovery with automatic backup refresh using two-phase commit
- **Private `_register_with_commit_internal()`**: Internal two-phase commit implementation
- **Private `_recover_without_refresh()`**: Recovery without backup refresh (used internally)

**Benefits**:
- **Automatic Safety**: Two-phase commit prevents lockouts during backup refresh
- **Network Resilience**: Backup refresh failures don't prevent recovery
- **Crash Safety**: Old backups remain valid until new ones are verified
- **Simplified API**: Developers get reliable backup refresh without complexity
- **Flexible Patterns**: Supports various backup ID strategies (alternating, versioned, timestamped)

### Metadata Format

```json
{
  "servers": ["https://server1.openadp.org", "https://server2.openadp.org"],
  "threshold": 2,
  "version": "1.0",
  "auth_code": "a1b2c3d4e5f6...",
  "user_id": "alice@example.com",
  "wrapped_long_term_secret": {
    "nonce": "base64_encoded_nonce",
    "ciphertext": "base64_encoded_ciphertext", 
    "tag": "base64_encoded_tag"
  },
  "backup_id": "even",
  "app_id": "document_signing",
  "max_guesses": 10,
  "ocrypt_version": "1.0"
}
```

## Security Model

### Threat Protection
- **Server-side**: Distributed threshold shares prevent single server compromise
- **Client-side**: Wrapped secrets in metadata enable instant PIN validation  
- **Network-level**: Noise-NK encryption + DPoP prevents token replay
- **Authentication**: Auth codes + Noise-NK encryption prevent unauthorized access

### BID Alternation Benefits
- **Crash Safety**: New registration doesn't overwrite old backup until success
- **Atomic Updates**: Always have a valid backup available for recovery
- **Improved Reliability**: System remains recoverable even during registration failures

### Attack Resistance
- **Brute Force**: Limited to `max_guesses` attempts across all servers (typically 10)
- **Server Compromise**: Requires T-of-N servers to recover any user data  
- **Network Attacks**: End-to-end encryption prevents MitM and replay attacks
- **Authentication Bypass**: Auth codes + Noise-NK encryption prevent unauthorized access

### Future: Malicious Server Resistance

**Current**: System assumes "honest-but-curious" servers (may be compromised but follow protocol)

**Planned Enhancement**: Byzantine fault tolerance against actively malicious servers
- **Exhaustive Subset Testing**: Try all C(N,T) combinations of T servers from N available
- **Validation**: Use AES-GCM unwrapping success as proof of valid recovery
- **Malicious Detection**: When subset works, excluded servers contain the malicious ones
- **Health Reporting**: Report malicious servers to `health.openadp.org`
- **Automatic Exclusion**: Blacklist confirmed malicious servers from future operations

## Use Cases

### 1. **Cryptographic Key Protection**
```python
import secrets

# Generate any binary secret (e.g., AES key, ed25519 key bytes, etc.)
secret_key = secrets.token_bytes(32)  # 256-bit key

# Protect with Ocrypt
metadata = ocrypt.register(
    user_id="alice@example.com",
    app_id="encryption_key",
    long_term_secret=secret_key,
    pin="secure_pin"
)

# Later: recover and use
recovered_key, remaining, updated_metadata = ocrypt.recover(metadata, "secure_pin")
# Use recovered_key for encryption, signing, etc.
```

### 2. **API Token Storage**
```python
# Protect Stripe API key
metadata = ocrypt.register(
    user_id="service_account",
    app_id="stripe_payments",
    long_term_secret=b"sk_live_51HyperSecureToken...",
    pin="service_pin"
)

# Later: recover for API calls
api_key, remaining, updated_metadata = ocrypt.recover(metadata, "service_pin")
stripe.api_key = api_key.decode()
```

### 3. **Database Encryption**
```python
# Protect database master key
db_key = secrets.token_bytes(32)  # AES-256 key
metadata = ocrypt.register(
    user_id="db_cluster_01",
    app_id="customer_data",
    long_term_secret=db_key,
    pin="db_master_pin"
)

# Database startup: recover encryption key
recovered_key, remaining, updated_metadata = ocrypt.recover(metadata, "db_master_pin")
# Use recovered_key for database encryption/decryption
```

### 4. **Password Hash Migration**
```python
# Traditional bcrypt approach
def verify_password_old(email, password):
    user = db.get_user(email)
    return bcrypt.checkpw(password, user.password_hash)

# Ocrypt approach
def verify_password_new(email, password):
    user = db.get_user(email)
    try:
        secret, remaining, updated_metadata = ocrypt.recover(user.ocrypt_metadata, password)
        # Store updated_metadata if backup was refreshed
        if updated_metadata != user.ocrypt_metadata:
            db.update_user_metadata(email, updated_metadata)
        return True  # Password correct
    except Exception:
        return False  # Password wrong
```

## Implementation Status

### ✅ **Completed**
- Core `register()` and `recover()` functions with automatic backup refresh
- Two-phase commit pattern for crash-safe backup refresh

- Server discovery and liveness testing
- Random server selection for load balancing (when >15 servers available)
- Smart backup ID generation strategies (alternation, versioning, timestamped)
- Comprehensive test suite (16 test cases)
- Demo with 5 real-world use cases
- Integration with live OpenADP servers

### 🔄 **Current Limitations**
- Backup refresh happens on every recovery (could be optimized with timestamps)
- No malicious server resistance yet
- No health reporting integration

### 🚀 **Future Enhancements**
- Timestamp-based backup refresh optimization (avoid refresh on every recovery)
- Byzantine fault tolerance against malicious servers
- Health monitoring and reporting
- Performance optimizations for large-scale deployments
- Additional language bindings (Go, JavaScript, Rust)

## Comparison: Traditional vs Ocrypt

| Aspect | Traditional (bcrypt/scrypt) | Ocrypt |
|--------|----------------------------|---------|
| **Storage** | Salt + password hash | Metadata blob |
| **Validation** | Local hash comparison | Distributed key recovery + AES unwrapping |
| **Security** | Single point of failure | Distributed across N servers, T-of-N threshold |
| **Brute Force** | Rate limiting required | Built-in guess limiting across servers |
| **Nation-State** | Vulnerable to server compromise | Requires compromising T-of-N servers |
| **Backup** | Manual backup of database | Automatic distributed backup with refresh |
| **Recovery** | Database restore required | Recoverable from any T servers |
| **Secrets** | Only password verification | Arbitrary user secrets (keys, tokens, etc.) |

## Conclusion

Ocrypt successfully achieves the goal of making OpenADP "super-simple" for developers while providing unprecedented security through distributed threshold cryptography. The 2-function API (`register`, `recover`) is a drop-in replacement for traditional password hashing that scales from individual applications to nation-state-resistant infrastructure.

The OPRF-based foundation ensures that no individual server can compromise user secrets, while the metadata-based approach provides flexibility for protecting any type of secret data beyond just passwords. 