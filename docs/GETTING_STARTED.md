# Getting Started with OpenADP

Welcome to OpenADP! This guide will get you up and running with distributed threshold cryptography in minutes.

## What is OpenADP?

OpenADP provides **Ocrypt** - a drop-in replacement for traditional password hashing functions (bcrypt, scrypt, Argon2, PBKDF2) that uses distributed threshold cryptography for nation-state-resistant password protection.

### Key Benefits

- **🔒 Nation-State Resistant**: Your data remains safe even if governments compromise some servers
- **🔐 Information Theoretic Security**: Attackers learn nothing about your PIN, even with quantum computers
- **⚡ Drop-in Replacement**: Replace `bcrypt.hash()` with `ocrypt.register()` in just 2 lines
- **🌍 Distributed Trust**: No single point of failure across multiple countries
- **📱 PIN Protection**: Transform weak PINs like "1234" into strong encryption keys

### Perfect For

- 🪙 **Device Backups** - Protect backups from your cloud provider
- 🔐 **Password Managers** - Vault backup with distributed trust  
- 💬 **Secure Messaging** - Backup chat history without central vulnerability
- 📁 **File Storage** - End-to-end encryption without holding keys

---

## Quick Start

### Choose Your Path

| I want to... | Go to... |
|--------------|----------|
| **Integrate Ocrypt into my app** | [Application Developer Guide](#for-application-developers) |
| **Run an OpenADP server** | [Server Operator Guide](#for-server-operators) |
| **Review the security model** | [Security Model Documentation](SECURITY_MODEL.md) |

---

## For Application Developers

### Step 1: Install OpenADP SDK

Choose your language:

<details>
<summary><strong>🐍 Python</strong></summary>

```bash
pip install openadp
```

**Import and use:**
```python
from openadp import ocrypt

# Register a secret protected by PIN
metadata = ocrypt.register("user@example.com", "myapp", secret_bytes, "1234", 10)

# Later: recover the secret  
secret, remaining, updated_metadata = ocrypt.recover(metadata, "1234")
```
</details>

<details>
<summary><strong>🟨 JavaScript (Node.js)</strong></summary>

```bash
npm install @openadp/sdk
```

**Import and use:**
```javascript
import { register, recover } from '@openadp/sdk';

// Register a secret protected by PIN
const metadata = await register("user@example.com", "myapp", secretBytes, "1234", 10);

// Later: recover the secret
const { secret, remaining, updatedMetadata } = await recover(metadata, "1234");
```
</details>

<details>
<summary><strong>🌐 JavaScript (Browser)</strong></summary>

**Include the browser SDK:**
```html
<script type="module">
import { register, recover } from './sdk/browser-javascript/ocrypt.js';

// Register a secret protected by PIN
const metadata = await register("user@example.com", "myapp", secretBytes, "1234", 10);

// Later: recover the secret
const { secret, remaining, updatedMetadata } = await recover(metadata, "1234");
</script>
```

**⚠️ Important**: Always serve from HTTP server, never open HTML files directly (browsers block ES6 modules from file://)
</details>

<details>
<summary><strong>🐹 Go</strong></summary>

```bash
go get github.com/OpenADP/openadp/sdk/go@latest
```

**Import and use:**
```go
import "github.com/OpenADP/openadp/sdk/go/ocrypt"

// Register a secret protected by PIN
metadata, err := ocrypt.Register("user@example.com", "myapp", secretBytes, "1234", 10, "")

// Later: recover the secret
secret, remaining, updatedMetadata, err := ocrypt.Recover(metadata, "1234", "")
```
</details>

<details>
<summary><strong>🦀 Rust</strong></summary>

```toml
# Add to Cargo.toml
[dependencies]
openadp-ocrypt = "0.1.3"
tokio = { version = "1.0", features = ["full"] }
```

**Import and use:**
```rust
use openadp_ocrypt::{register, recover};

// Register a secret protected by PIN
let metadata = register("user@example.com", "myapp", &secret_bytes, "1234", 10, "").await?;

// Later: recover the secret
let (secret, remaining, updated_metadata) = recover(&metadata, "1234", "").await?;
```
</details>

<details>
<summary><strong>⚡ C++</strong></summary>

```bash
# Clone and build
git clone https://github.com/OpenADP/openadp.git
cd openadp/sdk/cpp
mkdir build && cd build
cmake .. && make
```

**Include and use:**
```cpp
#include <openadp/ocrypt.hpp>
using namespace openadp;

// Register a secret protected by PIN
Bytes metadata = ocrypt::register_secret("user@example.com", "myapp", secret_bytes, "1234", 10);

// Later: recover the secret
auto result = ocrypt::recover(metadata, "1234");
```
</details>

### Step 2: Test Your Integration

Create a simple test to verify everything works:

```python
# Python example - adapt for your language
from openadp import ocrypt

def test_ocrypt():
    # Test data
    test_secret = b"Hello, OpenADP!"
    test_pin = "1234"
    
    print("🧪 Testing OpenADP integration...")
    
    # Register
    metadata = ocrypt.register("test-user", "test-app", test_secret, test_pin, 10)
    print("✅ Registration successful!")
    
    # Recover
    recovered_secret, remaining, updated_metadata = ocrypt.recover(metadata, test_pin)
    print("✅ Recovery successful!")
    
    # Verify
    if recovered_secret == test_secret:
        print("🎉 Test passed! OpenADP is working correctly.")
    else:
        print("❌ Secret mismatch!")

if __name__ == "__main__":
    test_ocrypt()
```

### Step 3: Replace Your Password Hashing

Replace your existing password hashing with Ocrypt:

**Before (traditional):**
```python
# Old way with bcrypt
import bcrypt

# Storing a password
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
user_record["password_hash"] = password_hash

# Verifying a password  
if bcrypt.checkpw(password.encode(), stored_hash):
    # Authentication successful
```

**After (with Ocrypt):**
```python
# New way with Ocrypt  
from openadp import ocrypt

# Storing a secret (during user registration)
metadata = ocrypt.register(user_id, app_id, user_secret, user_pin, 10)
user_record["ocrypt_metadata"] = metadata

# Recovering a secret (during user login)
try:
    secret, remaining, updated_metadata = ocrypt.recover(metadata, user_pin)
    # Update metadata if backup was refreshed
    user_record["ocrypt_metadata"] = updated_metadata
    # Authentication successful - use the secret
except:
    # Authentication failed
```

### Step 4: Handle Production Concerns

**🔄 Backup Refresh**: Ocrypt automatically refreshes backups during recovery for crash safety. Always save the `updated_metadata`:

```python
secret, remaining, updated_metadata = ocrypt.recover(metadata, pin)
# IMPORTANT: Save updated_metadata back to your database
user.ocrypt_metadata = updated_metadata
user.save()
```

**⚠️ Guess Limiting**: Failed PIN attempts are tracked across the distributed network. Plan for lockout scenarios:

```python
try:
    secret, remaining, updated_metadata = ocrypt.recover(metadata, user_pin)
    print(f"✅ Success! {remaining} attempts remaining")
except Exception as e:
    if "too many guesses" in str(e):
        print("🚫 Account locked due to too many failed attempts")
    else:
        print(f"❌ Recovery failed: {e}")
```

**🌐 Network Resilience**: Ocrypt handles server failures automatically, but consider custom server configurations for enterprise deployments:

```python
# Use custom server registry (optional)
metadata = ocrypt.register(user_id, app_id, secret, pin, 10, 
                          servers_url="https://your-servers.com/api/servers.json")
```

---

## For Server Operators

### Quick Server Setup

**1. Install Dependencies:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install golang-go python3 python3-pip make

# macOS
brew install go python3 make
```

**2. Clone and Setup:**
```bash
git clone https://github.com/OpenADP/openadp.git
cd openadp
./scripts/setup_env.sh
```

**3. Run Tests:**
```bash
./run_all_tests.py
```

**4. Start Server:**
```bash
# For development/testing
make run-server

# For production deployment
sudo ./scripts/update-openadp-node.sh
```

**5. Verify Server Health:**
```bash
curl http://localhost:8080/health
curl https://your-domain.com/health
```

### Server Requirements

- **Hardware**: 1GB RAM, 1 CPU core, 10GB storage minimum
- **OS**: Linux (Ubuntu 20.04+ recommended)
- **Network**: Public IP, ports 80/443 open
- **Domain**: TLS certificate (Let's Encrypt recommended)
- **Monitoring**: Consider setting up health monitoring

---

## What's Next?

### 📚 Dive Deeper
- **[SDK Guide](SDK_GUIDE.md)** - Language-specific details and advanced usage
- **[API Reference](API_REFERENCE.md)** - Complete function documentation
- **[Security Model](SECURITY_MODEL.md)** - Threat model and audit results

### 🚀 Example Applications
- **[Ghost Notes Demo](../ghost-notes/README.md)** - Browser-based secure notes app
- **[Command Line Tools](../sdk/)** - CLI examples in multiple languages

### 🤝 Get Help
- **Discord**: [Join our Discord](https://discord.gg/TaHNeGsE8j) for real-time help
- **GitHub Issues**: [Report bugs or request features](https://github.com/OpenADP/openadp/issues)
- **Network Status**: [Check server health](https://health.openadp.org)

---

## Common Integration Patterns

### Password Manager Integration
```python
# Protect your vault's master key
vault_key = secrets.token_bytes(32)  # Your vault encryption key
metadata = ocrypt.register(user_email, "password_vault", vault_key, user_pin, 10)

# Store metadata with user account (safe to store anywhere)
user.vault_metadata = metadata

# Later: unlock the vault
vault_key, remaining, updated_metadata = ocrypt.recover(metadata, user_pin)
# Use vault_key to decrypt user's password vault
```

### File Encryption Integration  
```python
# Protect file encryption keys
file_key = secrets.token_bytes(32)  # AES-256 key
metadata = ocrypt.register(user_id, f"file_{filename}", file_key, user_pin, 10)

# Encrypt file with file_key, store metadata separately
encrypted_file = encrypt_file(file_data, file_key)
store_file(encrypted_file, metadata)

# Later: decrypt the file
file_key, remaining, updated_metadata = ocrypt.recover(metadata, user_pin)
file_data = decrypt_file(encrypted_file, file_key)
```

### Backup Integration
```python
# Protect device backup encryption key
backup_key = derive_key_from_device_secret()
metadata = ocrypt.register(device_id, "device_backup", backup_key, unlock_pin, 10)

# Create encrypted backup
encrypted_backup = encrypt_backup(device_data, backup_key)
upload_to_cloud(encrypted_backup, metadata)

# Later: restore from backup on new device
backup_key, remaining, updated_metadata = ocrypt.recover(metadata, unlock_pin)
device_data = decrypt_backup(encrypted_backup, backup_key)
```

Welcome to the future of password protection! 🚀 