# OpenADP SDK Guide

This guide provides detailed information about using OpenADP SDKs across all supported languages.

## SDK Overview

OpenADP provides **production-ready SDKs** in 6+ languages:

| Language | Package | Status | Install Command |
|----------|---------|--------|-----------------|
| **Python** | `openadp` | ✅ Production | `pip install openadp` |
| **JavaScript (Node.js)** | `@openadp/sdk` | ✅ Production | `npm install @openadp/sdk` |
| **JavaScript (Browser)** | ES6 Module | ✅ Production | Import from `sdk/browser-javascript/` |
| **Go** | `github.com/OpenADP/openadp/sdk/go` | ✅ Production | `go get github.com/OpenADP/openadp/sdk/go@latest` |
| **Rust** | `openadp-ocrypt` | ✅ Production | Add to `Cargo.toml` |
| **C++** | Header-only library | ✅ Production | Build from source |

## Core API Functions

### register()
Creates a new secret protected by a PIN.

**Parameters:**
- `user_id` (string): Unique identifier for the user
- `app_id` (string): Unique identifier for your application  
- `secret` (bytes): The secret data to protect
- `pin` (string): PIN that protects the secret
- `max_guesses` (integer): Maximum failed PIN attempts allowed
- `servers_url` (string, optional): Custom server registry URL

**Returns:**
- `metadata` (bytes): Encrypted metadata needed for recovery

### recover()
Recovers a secret using the PIN and metadata.

**Parameters:**
- `metadata` (bytes): Metadata returned from `register()`
- `pin` (string): PIN used during registration
- `servers_url` (string, optional): Custom server registry URL

**Returns:**
- `secret` (bytes): The original secret data
- `remaining_guesses` (integer): Remaining failed PIN attempts
- `updated_metadata` (bytes): Refreshed metadata (always save this!)

## Language-Specific Guides

### Python SDK

**Installation:**
```bash
pip install openadp
```

**Basic Usage:**
```python
from openadp import ocrypt

# Register a secret
secret = b"my-encryption-key"
metadata = ocrypt.register("user123", "myapp", secret, "1234", 10)

# Later: recover the secret
secret, remaining, updated_metadata = ocrypt.recover(metadata, "1234")
```

### JavaScript SDK (Node.js)

**Installation:**
```bash
npm install @openadp/sdk
```

**Basic Usage:**
```javascript
import { register, recover } from '@openadp/sdk';

// Register a secret
const secret = new TextEncoder().encode("my-encryption-key");
const metadata = await register("user123", "myapp", secret, "1234", 10);

// Later: recover the secret
const { secret: recoveredSecret, remaining, updatedMetadata } = 
    await recover(metadata, "1234");
```

### JavaScript SDK (Browser)

**Usage:**
```html
<script type="module">
import { register, recover } from './sdk/browser-javascript/ocrypt.js';

const secret = new TextEncoder().encode("my-encryption-key");
const metadata = await register("user123", "myapp", secret, "1234", 10);

const { secret: recovered, remaining, updatedMetadata } = 
    await recover(metadata, "1234");
</script>
```

### Go SDK

**Installation:**
```bash
go get github.com/OpenADP/openadp/sdk/go@latest
```

**Basic Usage:**
```go
import "github.com/OpenADP/openadp/sdk/go/ocrypt"

// Register a secret
secret := []byte("my-encryption-key")
metadata, err := ocrypt.Register("user123", "myapp", secret, "1234", 10, "")

// Later: recover the secret
secret, remaining, updatedMetadata, err := ocrypt.Recover(metadata, "1234", "")
```

### Rust SDK

**Installation (Cargo.toml):**
```toml
[dependencies]
openadp-ocrypt = "0.1.3"
tokio = { version = "1.0", features = ["full"] }
```

**Basic Usage:**
```rust
use openadp_ocrypt::{register, recover};

// Register a secret
let secret = b"my-encryption-key";
let metadata = register("user123", "myapp", secret, "1234", 10, "").await?;

// Later: recover the secret  
let (secret, remaining, updated_metadata) = recover(&metadata, "1234", "").await?;
```

### C++ SDK

**Installation:**
```bash
git clone https://github.com/OpenADP/openadp.git
cd openadp/sdk/cpp
mkdir build && cd build
cmake .. && make
```

**Basic Usage:**
```cpp
#include <openadp/ocrypt.hpp>
using namespace openadp;

// Register a secret
Bytes secret = {'m', 'y', '-', 'k', 'e', 'y'};
Bytes metadata = ocrypt::register_secret("user123", "myapp", secret, "1234", 10);

// Later: recover the secret
auto result = ocrypt::recover(metadata, "1234");
```

## Best Practices

### Always Save Updated Metadata
```python
# IMPORTANT: Always save the updated metadata
secret, remaining, updated_metadata = ocrypt.recover(metadata, "1234")
save_to_database(updated_metadata)  # Critical for reliability!
```

### Error Handling
```python
try:
    secret, remaining, updated_metadata = ocrypt.recover(metadata, pin)
except Exception as e:
    if "too many guesses" in str(e):
        print("Account locked - too many failed attempts")
    elif "network" in str(e):
        print("Network error - try again later")
    else:
        print(f"Recovery failed: {e}")
```

### Custom Server Configuration
```python
# Use your own server registry
custom_servers = "https://your-domain.com/api/servers.json"
metadata = ocrypt.register("user", "app", secret, "pin", 10, custom_servers)
```

## Common Integration Patterns

### Password Manager
```python
# Protect vault master key
vault_key = secrets.token_bytes(32)
metadata = ocrypt.register(user_email, "vault", vault_key, master_pin, 10)

# Later: unlock vault
vault_key, remaining, updated_metadata = ocrypt.recover(metadata, master_pin)
```

### File Encryption
```python
# Protect file encryption key
file_key = secrets.token_bytes(32)
metadata = ocrypt.register(user_id, f"file_{filename}", file_key, pin, 10)

# Later: decrypt file
file_key, remaining, updated_metadata = ocrypt.recover(metadata, pin)
```

### Device Backup
```python
# Protect backup encryption key
backup_key = derive_key_from_device()
metadata = ocrypt.register(device_id, "backup", backup_key, unlock_pin, 10)

# Later: restore from backup
backup_key, remaining, updated_metadata = ocrypt.recover(metadata, unlock_pin)
```

For more detailed examples and advanced usage, see the [Getting Started Guide](GETTING_STARTED.md). 