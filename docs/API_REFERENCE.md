# OpenADP API Reference

Complete technical reference for the OpenADP Ocrypt API.

## Overview

OpenADP provides a simple 2-function API for distributed threshold cryptography:

- **`register()`** - Create a new secret protected by a PIN
- **`recover()`** - Recover a secret using the PIN and metadata

All SDKs implement identical functionality with language-specific calling conventions.

---

## Function Reference

### register()

Creates a new secret protected by a PIN using distributed threshold cryptography.

#### Signature

**Python:**
```python
def register(user_id: str, app_id: str, secret: bytes, pin: str, max_guesses: int, servers_url: str = "") -> bytes
```

**JavaScript:**
```javascript  
async function register(user_id: string, app_id: string, secret: Uint8Array, pin: string, max_guesses: number, servers_url?: string): Promise<Uint8Array>
```

**Go:**
```go
func Register(userID, appID string, secret []byte, pin string, maxGuesses int, serversURL string) ([]byte, error)
```

**Rust:**
```rust
async fn register(user_id: &str, app_id: &str, secret: &[u8], pin: &str, max_guesses: u32, servers_url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>>
```

**C++:**
```cpp
Bytes register_secret(const std::string& user_id, const std::string& app_id, const Bytes& secret, const std::string& pin, int max_guesses, const std::string& servers_url = "")

Note that in C++ register is a keyword, so we use register_secret in C++ instead.
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | ✅ | Unique identifier for the user (e.g., email, UUID) |
| `app_id` | string | ✅ | Unique identifier for your application |
| `secret` | bytes | ✅ | The secret data to protect (max 1KB) |
| `pin` | string | ✅ | PIN that protects the secret (any length) |
| `max_guesses` | integer | ✅ | Maximum failed PIN attempts allowed (1-1000) |
| `servers_url` | string | ❌ | Custom server registry URL (defaults to public network) |

#### Returns

**Type:** `bytes` (varies by language: `bytes`, `Uint8Array`, `[]byte`, `Vec<u8>`, `Bytes`)

**Description:** Encrypted metadata blob containing:
- Encrypted secret shares distributed across servers
- PIN verification data
- Server configuration
- Guess counter initialization
- Cryptographic parameters

**Size:** Typically 2-4KB depending on secret size and server configuration.

#### Error Conditions

| Error | Description | Common Causes |
|-------|-------------|---------------|
| `NetworkError` | Cannot connect to servers | Internet connectivity, firewall, server downtime |
| `ValidationError` | Invalid parameters | Empty user_id/app_id, secret too large, invalid max_guesses |
| `ServerError` | Server-side processing failed | Server overload, distributed consensus failure |
| `CryptoError` | Cryptographic operation failed | Random number generation failure, key derivation error |

#### Example Usage

**Python:**
```python
from openadp import ocrypt
import secrets

# Generate a 256-bit encryption key
encryption_key = secrets.token_bytes(32)

# Protect it with a PIN
metadata = ocrypt.register(
    user_id="user@example.com",
    app_id="my_password_manager", 
    secret=encryption_key,
    pin="8765",
    max_guesses=10
)

# Save metadata (safe to store anywhere - contains no secrets)
save_to_database(metadata)
```

---

### recover()

Recovers a secret using the PIN and metadata from a previous `register()` call.

#### Signature

**Python:**
```python
def recover(metadata: bytes, pin: str, servers_url: str = "") -> tuple[bytes, int, bytes]
```

**JavaScript:**
```javascript
async function recover(metadata: Uint8Array, pin: string, servers_url?: string): Promise<{secret: Uint8Array, remaining: number, updatedMetadata: Uint8Array}>
```

**Go:**
```go
func Recover(metadata []byte, pin string, serversURL string) ([]byte, int, []byte, error)
```

**Rust:**
```rust
async fn recover(metadata: &[u8], pin: &str, servers_url: &str) -> Result<(Vec<u8>, u32, Vec<u8>), Box<dyn std::error::Error>>
```

**C++:**
```cpp
struct RecoverResult {
    Bytes secret;
    int remaining_guesses;
    Bytes updated_metadata;
};
RecoverResult recover(const Bytes& metadata, const std::string& pin, const std::string& servers_url = "")
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `metadata` | bytes | ✅ | Metadata returned from `register()` |
| `pin` | string | ✅ | PIN used during registration |
| `servers_url` | string | ❌ | Provides current Noise-NK public keys for URL used in `register()` |

#### Returns

**Python:** `(secret: bytes, remaining_guesses: int, updated_metadata: bytes)`
**JavaScript:** `{secret: Uint8Array, remaining: number, updatedMetadata: Uint8Array}`  
**Go:** `(secret []byte, remainingGuesses int, updatedMetadata []byte, error)`
**Rust:** `(Vec<u8>, u32, Vec<u8>)` in `Result`
**C++:** `RecoverResult` struct

| Field | Type | Description |
|-------|------|-------------|
| `secret` | bytes | The original secret data from `register()` |
| `remaining_guesses` | integer | Number of failed PIN attempts remaining |
| `updated_metadata` | bytes | **Critical**: Refreshed metadata (always save this!) |

#### Critical: Always Save Updated Metadata

**⚠️ The `updated_metadata` MUST be saved back to your database every time `recover()` is called successfully.**
**⚠️The prior metadata should be saved as well, in case something goes wrong during registration** This is essential for:

- **Crash Safety**: Prevents data loss if servers crash during recovery
- **Consensus Integrity**: Maintains distributed system consistency  
- **Security**: Enables proper guess counter synchronization

```python
# CORRECT usage
backup metadata so it is not lost if anything goes wrong
secret, remaining, updated_metadata = ocrypt.recover(metadata, pin)
# CRITICAL: Save updated_metadata immediately
user.ocrypt_metadata = updated_metadata
user.save()

# INCORRECT usage - will cause data corruption
secret, remaining, updated_metadata = ocrypt.recover(metadata, pin)
# DON'T IGNORE updated_metadata!
```

#### Error Conditions

| Error | Description | Recovery Action |
|-------|-------------|-----------------|
| `InvalidPinError` | Incorrect PIN provided | Show error, decrement guess counter |
| `TooManyGuessesError` | Maximum failed attempts reached | Account locked - implement recovery flow |
| `NetworkError` | Cannot connect to enough servers | Retry later, check connectivity |
| `CorruptedMetadataError` | Metadata is invalid/corrupted | Use backup metadata or re-register |
| `ServerConsensusError` | Servers disagree on state | Temporary issue - retry in a few minutes |

#### Example Usage

**Python:**
```python
from openadp import ocrypt

def unlock_vault(user, pin):
    try:
        secret, remaining, updated_metadata = ocrypt.recover(
            user.ocrypt_metadata, 
            pin
        )
        
        # CRITICAL: Always save updated metadata
        user.ocrypt_metadata = updated_metadata
        user.save()
        
        print(f"✅ Vault unlocked! {remaining} attempts remaining")
        return secret
        
    except Exception as e:
        error_msg = str(e).lower()
        
        if "invalid pin" in error_msg:
            print("❌ Incorrect PIN")
        elif "too many guesses" in error_msg:
            print("🚫 Account locked - contact support")
        elif "network" in error_msg:
            print("🌐 Network error - try again later")
        else:
            print(f"❌ Unexpected error: {e}")
        
        return None
```

---

## Advanced Configuration

### Custom Server Registry

For enterprise deployments, you can specify a custom server registry URL:

```python
# Use your own server infrastructure
custom_servers = "https://your-company.com/api/openadp-servers.json"

metadata = ocrypt.register("user", "app", secret, "pin", 10, custom_servers)
secret, remaining, updated_metadata = ocrypt.recover(metadata, "pin", custom_servers)
```

**Server Registry Format:**
```json

  "version": "1.0",
  "updated": "2024-12-19T17:25:00Z",
  "servers": [
    {
      "url": "https://xyzzy.openadp.org",
      "public_key": "FEOkIV7ZhONfuhSOkEuTNo36pVzS2KAhqDXYwC8MySA=",
      "country": "US"
    },
    {
      "url": "https://louis.evilduckie.ca",
      "public_key": "G2G5FPQ7WMBJMPvQpMOsn9txwXavvcTZq50txF4rryw=",
      "country": "US"
    },
    {
      "url": "https://minime.openadp.org",
      "public_key": "gnV5Obw3maZGgL1HHK4YW0DkyKcp7Tp+xD9f4+gus3s=",
      "country": "US"
    },
  ]
}

```

### Performance Considerations

**Latency:**
- `register()`: ~500-2000ms (depends on geographic distribution)
- `recover()`: ~300-1000ms (faster due to caching)

**Network Requirements:**
- Requires HTTPS connections to N servers simultaneously for registration
- Approximately 1-10KB data transfer per operation
- Works behind corporate firewalls (standard HTTPS only)

**Concurrency:**
- All operations are thread-safe
- Multiple operations can run in parallel
- Connection pooling is handled automatically

## Security Considerations

### Data Protection

**Metadata Security:**
- Metadata contains sensitive information, but not keys
    - userID identifies user, and auth code enables PIN guessing
- Store in databases, backups, with traditional security
- Cannot be used to recover secret without PIN guess

**PIN Security:**  
- PINs are never transmitted to servers
- Oblivious protocol (distributed OPRF)
- Information-theoretic security against server-only attacks
- Even weak PINs (like "3344") become cryptographically strong

**Network Security:**
- Noise-NK 2nd layer of encryption hides sensitive data from corporate MitM and Cloudflare
- Perfect forward secrecy

### Threat Model

**Protected Against:**
- ✅ Server compromises when attacker has metadata (up to threshold)
- ✅ Network eavesdropping
- ✅ Offline brute force attacks  
- ✅ Database breaches
- ✅ Single-nation-state coercion

**Not Protected Against:**
- ❌ Client-side malware that steals PINs
- ❌ Social engineering to obtain PINs
- ❌ Physical access to unlocked devices

### Compliance

---

## Integration Patterns

### Password Manager Integration

```python
class SecureVault:
    def __init__(self, user_id):
        self.user_id = user_id
        self.vault_key = None
    
    def create_vault(self, master_pin):
        # Generate AES-256 key for vault encryption
        self.vault_key = secrets.token_bytes(32)
        
        # Protect vault key with OpenADP
        metadata = ocrypt.register(
            self.user_id,
            "password_vault",
            self.vault_key, 
            master_pin,
            10  # Allow 10 failed attempts
        )
        
        return metadata
    
    def unlock_vault(self, metadata, master_pin):
        self.vault_key, remaining, updated_metadata = ocrypt.recover(
            metadata, 
            master_pin
        )
        return updated_metadata, remaining
    
    def encrypt_password(self, password):
        # Use vault_key to encrypt password
        return encrypt_aes_gcm(password.encode(), self.vault_key)
    
    def decrypt_password(self, encrypted_password):
        # Use vault_key to decrypt password  
        return decrypt_aes_gcm(encrypted_password, self.vault_key).decode()
```

### File Encryption Integration

```python
def protect_file(file_path, pin, user_id):
    # Generate unique encryption key for this file
    file_key = secrets.token_bytes(32)
    
    # Encrypt file with AES-256
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = encrypt_aes_gcm(plaintext, file_key)
    
    # Protect file key with OpenADP
    metadata = ocrypt.register(
        user_id,
        f"file_{os.path.basename(file_path)}",
        file_key,
        pin,
        5  # Fewer attempts for file access
    )
    
    # Save encrypted file and metadata
    with open(file_path + '.encrypted', 'wb') as f:
        f.write(ciphertext)
    
    with open(file_path + '.metadata', 'wb') as f:
        f.write(metadata)
    
    # Remove original file
    os.remove(file_path)

def recover_file(file_path, pin):
    # Load metadata
    with open(file_path + '.metadata', 'rb') as f:
        metadata = f.read()
    
    # Recover file key
    file_key, remaining, updated_metadata = ocrypt.recover(metadata, pin)
    
    # Update metadata
    with open(file_path + '.metadata', 'wb') as f:
        f.write(updated_metadata)
    
    # Decrypt file
    with open(file_path + '.encrypted', 'rb') as f:
        ciphertext = f.read()
    
    plaintext = decrypt_aes_gcm(ciphertext, file_key)
    
    # Restore original file
    with open(file_path, 'wb') as f:
        f.write(plaintext)
    
    return remaining
```

### Device Backup Integration

```python
def create_device_backup(device_id, backup_data, unlock_pin):
    # Derive backup key from device secrets
    backup_key = derive_backup_key(device_id)
    
    # Protect backup key with OpenADP
    metadata = ocrypt.register(
        device_id,
        "device_backup", 
        backup_key,
        unlock_pin,
        10  # Limited attempts for device unlock
    )
    
    # Encrypt backup data
    encrypted_backup = encrypt_aes_gcm(backup_data, backup_key)
    
    # Upload to cloud storage
    cloud_storage.upload(f"{device_id}_backup.enc", encrypted_backup)
    cloud_storage.upload(f"{device_id}_metadata.dat", metadata)

def restore_device_backup(device_id, unlock_pin):
    # Download metadata from cloud
    metadata = cloud_storage.download(f"{device_id}_metadata.dat")
    
    # Recover backup key
    backup_key, remaining, updated_metadata = ocrypt.recover(metadata, unlock_pin)
    
    # Update metadata in cloud
    cloud_storage.upload(f"{device_id}_metadata.dat", updated_metadata)
    
    # Download and decrypt backup
    encrypted_backup = cloud_storage.download(f"{device_id}_backup.enc")
    backup_data = decrypt_aes_gcm(encrypted_backup, backup_key)
    
    return backup_data, remaining
```
