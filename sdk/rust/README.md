# OpenADP Rust SDK

A complete Rust implementation of the OpenADP (Open Advanced Data Protection) distributed secret sharing system, designed to protect against nation-state attacks.

## Features

- **Ed25519 elliptic curve operations** with point compression/decompression
- **Shamir secret sharing** with threshold recovery
- **Noise-NK protocol** for secure server communication
- **JSON-RPC 2.0 API** with multi-server support
- **Cross-language compatibility** with Go and Python implementations
- **High-level key generation API** for file encryption
- **Simple ocrypt API** for password hashing replacement
- **Automatic server discovery** from registry
- **Load balancing** across multiple servers
- **Guess limiting** and rate limiting protection
- **Two-phase commit** backup refresh

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
openadp-ocrypt = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
```

## Quick Start

### High-Level Key Generation API

```rust
use openadp_ocrypt::{generate_encryption_key, recover_encryption_key, get_servers};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get live servers from registry
    let servers = get_servers("").await?;
    
    // Generate encryption key with distributed backup
    let result = generate_encryption_key(
        "document.pdf",
        "secure_password",
        "user@example.com",
        10, // max_guesses
        0,  // expiration (0 = never)
        servers,
    ).await?;
    
    if let Some(key) = result.encryption_key {
        println!("Generated {}-byte encryption key", key.len());
        
        // Later: recover the key
        let recovered = recover_encryption_key(
            "document.pdf",
            "secure_password", 
            "user@example.com",
            result.server_infos.unwrap(),
            result.threshold.unwrap(),
            result.auth_codes.unwrap(),
        ).await?;
        
        if let Some(recovered_key) = recovered.encryption_key {
            assert_eq!(key, recovered_key);
            println!("Successfully recovered key!");
        }
    }
    
    Ok(())
}
```

### Simple Ocrypt API (Password Hashing Replacement)

Replace bcrypt, scrypt, Argon2, or PBKDF2 with distributed threshold cryptography:

```rust
use openadp_ocrypt::{register, recover};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Protect a Stripe API key
    let api_key = b"sk_live_EXAMPLE_NOT_REAL_KEY_FOR_DEMO_PURPOSES_ONLY_123456789";
    
    // Register with distributed protection
    let metadata = register(
        "payment_service",    // user_id
        "ecommerce_platform", // app_id
        api_key,              // long_term_secret
        "admin_pin_2024",     // pin
        5,                    // max_guesses
        "",                   // servers_url (empty = default registry)
    ).await?;
    
    // Store metadata with user record in database
    println!("Store metadata ({} bytes) with user record", metadata.len());
    
    // Later: recover the API key with automatic backup refresh
    let (recovered_key, remaining_guesses, updated_metadata) = recover(
        &metadata,
        "admin_pin_2024",
        "",
    ).await?;
    
    assert_eq!(api_key, recovered_key.as_slice());
    println!("Recovered API key! Remaining guesses: {}", remaining_guesses);
    
    // Update database if backup was refreshed
    if updated_metadata != metadata {
        println!("Update database with refreshed metadata");
    }
    
    Ok(())
}
```

## Core Components

### Cryptographic Operations

```rust
use openadp_ocrypt::{hash_to_point, point_compress, derive_enc_key};

// Hash-to-point function H(uid, did, bid, pin)
let point = hash_to_point(
    b"user@example.com",
    b"device123", 
    b"backup456",
    b"pin"
)?;

// Compress point to 32 bytes
let compressed = point_compress(&point)?;

// Derive encryption key from point
let key = derive_enc_key(&point)?;
```

### Client Communication

```rust
use openadp_ocrypt::{OpenADPClient, EncryptedOpenADPClient, ServerInfo};

// Basic client (no encryption)
let client = OpenADPClient::new("https://server.openadp.org:8443".to_string(), 30);
client.ping().await?;

// Encrypted client with Noise-NK
let public_key = Some(parse_server_public_key("ed25519:..."))?;
let mut encrypted_client = EncryptedOpenADPClient::new(
    "https://secure.openadp.org:8443".to_string(),
    public_key,
    30
);

// Get server information
let info = encrypted_client.get_server_info().await?;
println!("Server version: {}", info.server_version);
```

### Server Discovery

```rust
use openadp_ocrypt::{get_servers, discover_servers};

// Get servers from default registry
let servers = get_servers("").await?;

// Use custom registry
let servers = get_servers("https://custom.registry.com/servers.json").await?;

// Discover with fallback
let servers = discover_servers("").await?; // Falls back to hardcoded servers
```

## Use Cases

### 1. API Key Protection

Replace database storage of API keys with distributed protection:

```rust
// Instead of storing API keys in database:
// database.store("user123", "stripe_key", "sk_live_...");

// Use OpenADP distributed protection:
let metadata = register("user123", "stripe", api_key, user_pin, 5, "").await?;
database.store("user123", "stripe_metadata", &metadata);

// Recovery:
let metadata = database.get("user123", "stripe_metadata");
let (api_key, _, updated_metadata) = recover(&metadata, user_pin, "").await?;
```

### 2. File Encryption

Generate encryption keys with distributed backup:

```rust
let servers = get_servers("").await?;
let result = generate_encryption_key(
    "financial_report.pdf",
    "user_password",
    "alice@company.com", 
    10, 0, servers
).await?;

// Use key for AES-256-GCM file encryption
let key = result.encryption_key.unwrap();
encrypt_file("financial_report.pdf", &key)?;
```

### 3. Private Key Protection

Protect Ed25519/RSA private keys:

```rust
let private_key = generate_ed25519_key();
let metadata = register(
    "alice@company.com",
    "document_signing",
    &private_key.to_bytes(),
    "secure_pin",
    10,
    ""
).await?;

// Later: recover for signing
let (recovered_key, _, _) = recover(&metadata, "secure_pin", "").await?;
let signing_key = SigningKey::from_bytes(&recovered_key)?;
```

### 4. Database Encryption

Protect database master keys:

```rust
let master_key = generate_random_key();
let metadata = register(
    "database_service",
    "production_db",
    &master_key,
    "db_admin_pin",
    3, // Strict limit for production
    ""
).await?;

// Store metadata in secure configuration
config.set("db_master_key_metadata", metadata);
```

## Architecture

### Distributed Secret Sharing

1. **Secret Generation**: Random 256-bit secret `s`
2. **Point Computation**: `U = H(uid, did, bid, pin)` 
3. **Shamir Sharing**: Split `s` into `n` shares with `t` threshold
4. **Server Registration**: Store shares `(i, s_i, U)` on distributed servers
5. **Key Derivation**: Final key = `derive_key(s * U)`

### Threshold Recovery

1. **Point Computation**: `U = H(uid, did, bid, pin)`
2. **Share Recovery**: Retrieve `t` shares from servers
3. **Secret Reconstruction**: Lagrange interpolation to recover `s`
4. **Key Derivation**: Compute final key from `s * U`

### Security Properties

- **Nation-state resistant**: Requires compromise of `t-of-n` servers
- **Guess limiting**: Wrong PIN attempts tracked across all servers
- **Forward security**: Backup refresh changes all server state
- **No single point of failure**: Distributed across multiple jurisdictions

## Error Handling

```rust
use openadp_ocrypt::{OpenADPError, Result};

match register("user", "app", secret, "pin", 10, "").await {
    Ok(metadata) => println!("Success!"),
    Err(OpenADPError::Network(e)) => println!("Network error: {}", e),
    Err(OpenADPError::NoServers) => println!("No servers available"),
    Err(OpenADPError::InvalidInput(msg)) => println!("Invalid input: {}", msg),
    Err(OpenADPError::Authentication(msg)) => println!("Auth failed: {}", msg),
    Err(e) => println!("Other error: {}", e),
}
```

## Testing

Run the test suite:

```bash
cargo test
```

Run examples:

```bash
# Basic usage
cargo run --example basic_usage

# API key protection
cargo run --example api_key_protection

# Full OpenADP demo
cargo run --example full_openadp_demo
```

## Cross-Language Compatibility

The Rust SDK is fully compatible with:

- **Go SDK**: `../ocrypt` (separate git repository)
- **Python SDK**: `../python/openadp/`
- **JavaScript SDK**: `../javascript/openadp/`

All implementations use the same:
- Cryptographic primitives (Ed25519, SHA-256, HKDF)
- JSON-RPC 2.0 protocol
- Server registry format
- Metadata structure

## Production Deployment

### Server Configuration

```rust
// Use custom server registry for production
let servers = get_servers("https://your-registry.com/servers.json").await?;

// Or specify servers directly
let servers = vec![
    ServerInfo {
        url: "https://server1.your-domain.com:8443".to_string(),
        public_key: "ed25519:...".to_string(),
        country: "US".to_string(),
    },
    // ... more servers
];
```

### Security Considerations

1. **Server Selection**: Use servers in different jurisdictions
2. **Threshold Setting**: Recommend `t = ⌊n/2⌋ + 1` for `n` servers
3. **Guess Limits**: Use low limits (3-10) for production secrets
4. **Backup Refresh**: Implement automatic refresh on recovery
5. **Key Rotation**: Periodically re-register secrets with new backup IDs

### Monitoring

```rust
// Monitor server health
for server in &servers {
    match client.ping().await {
        Ok(_) => println!("✅ {} is healthy", server.url),
        Err(e) => println!("❌ {} is down: {}", server.url, e),
    }
}

// Check remaining guesses
let (_, remaining, _) = recover(&metadata, pin, "").await?;
if remaining < 3 {
    alert!("Low remaining guesses: {}", remaining);
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `cargo test`
5. Submit a pull request

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Security

For security issues, please email security@openadp.org instead of using the issue tracker. 