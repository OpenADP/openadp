//! Ocrypt - Drop-in replacement for password hashing functions
//!
//! Ocrypt provides a simple 2-function API that replaces traditional password hashing functions
//! (bcrypt, scrypt, Argon2, PBKDF2) with OpenADP's distributed threshold cryptography for
//! nation-state-resistant password protection.

use crate::{OpenADPError, Result};
use crate::keygen::{generate_encryption_key, recover_encryption_key};
use crate::client::{ServerInfo, get_servers};
use serde::{Deserialize, Serialize};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use rand::Rng;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Sha256, Digest};
use hex;


/// Wrapped secret data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedSecret {
    pub nonce: String,
    pub ciphertext: String,
    pub tag: String,
}

/// Ocrypt metadata format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcryptMetadata {
    // Standard openadp-encrypt fields
    pub servers: Vec<String>,
    pub threshold: usize,
    pub version: String,
    pub auth_code: String,
    pub user_id: String,
    
    // Ocrypt-specific fields
    pub wrapped_long_term_secret: WrappedSecret,
    pub backup_id: String,
    pub app_id: String,
    pub max_guesses: i32,
    pub ocrypt_version: String,
}

/// Register a long-term secret protected by a PIN using OpenADP distributed cryptography.
///
/// This function provides a simple interface that replaces traditional password hashing
/// functions like bcrypt, scrypt, Argon2, and PBKDF2 with distributed threshold cryptography.
///
/// # Arguments
///
/// * `user_id` - Unique identifier for the user (e.g., email, username)
/// * `app_id` - Application identifier to namespace secrets per app
/// * `long_term_secret` - User-provided secret to protect (any byte sequence)
/// * `pin` - Password/PIN that will unlock the secret
/// * `max_guesses` - Maximum wrong attempts before lockout
/// * `servers_url` - Optional custom URL for server registry (empty string uses default)
///
/// # Returns
///
/// Returns metadata bytes that should be stored alongside the user record.
///
/// # Example
///
/// ```rust,no_run
/// use openadp_ocrypt::register;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let secret = b"my_api_key_or_private_key";
///     let metadata = register(
///         "alice@example.com",
///         "document_signing",
///         secret,
///         "secure_pin_123",
///         10,
///         "",
///     ).await?;
///     
///     // Store metadata with user record
///     println!("Metadata length: {} bytes", metadata.len());
///     Ok(())
/// }
/// ```
pub async fn register(
    user_id: &str,
    app_id: &str,
    long_term_secret: &[u8],
    pin: &str,
    max_guesses: i32,
    servers_url: &str,
) -> Result<Vec<u8>> {
    register_with_bid(user_id, app_id, long_term_secret, pin, max_guesses, "even", servers_url).await
}

/// Recover a long-term secret using the PIN with automatic backup refresh.
///
/// This function implements a two-phase commit pattern for safe backup refresh:
/// 1. Recovers the secret using existing backup
/// 2. Attempts to refresh backup with opposite backup ID
/// 3. Returns updated metadata if refresh succeeds, original if it fails
///
/// # Arguments
///
/// * `metadata_bytes` - Metadata blob from register()
/// * `pin` - Password/PIN to unlock the secret
/// * `servers_url` - Optional custom URL for server registry (empty string uses default)
///
/// # Returns
///
/// Returns a tuple of (secret, remaining_guesses, updated_metadata).
///
/// # Example
///
/// ```rust,no_run
/// use openadp_ocrypt::{register, recover};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // ... register first ...
///     let metadata = register("alice@example.com", "app", b"secret", "pin", 10, "").await?;
///     
///     // Later: recover with automatic backup refresh
///     let (secret, remaining, updated_metadata) = recover(&metadata, "pin", "").await?;
///     
///     // Store updated_metadata if it changed
///     if updated_metadata != metadata {
///         println!("Backup was refreshed, store updated metadata");
///     }
///     
///     Ok(())
/// }
/// ```
pub async fn recover(
    metadata_bytes: &[u8],
    pin: &str,
    servers_url: &str,
) -> Result<(Vec<u8>, u32, Vec<u8>)> {
    // Step 1: Recover secret using existing backup
    println!("📋 Step 1: Recovering with existing backup...");
    let (secret, remaining) = recover_without_refresh(metadata_bytes, pin, servers_url).await?;

    // Step 2: Attempt automatic backup refresh with two-phase commit
    let updated_metadata = match attempt_backup_refresh(&secret, metadata_bytes, pin, servers_url).await {
        Ok(new_metadata) => {
            println!("✅ Backup refresh successful");
            new_metadata
        }
        Err(e) => {
            println!("⚠️  Backup refresh failed (using original): {}", e);
            metadata_bytes.to_vec()
        }
    };

    Ok((secret, remaining, updated_metadata))
}

/// Internal function to register with specific backup ID
async fn register_with_bid(
    user_id: &str,
    app_id: &str,
    long_term_secret: &[u8],
    pin: &str,
    max_guesses: i32,
    backup_id: &str,
    servers_url: &str,
) -> Result<Vec<u8>> {
    // Input validation
    validate_inputs(user_id, app_id, long_term_secret, pin, max_guesses)?;

    println!("🔐 Protecting secret for user: {}", user_id);
    println!("📱 Application: {}", app_id);
    println!("🔑 Secret length: {} bytes", long_term_secret.len());

    // Step 1: Server discovery
    println!("🌐 Discovering OpenADP servers...");
    let server_infos = discover_servers(servers_url).await?;
    
    if server_infos.is_empty() {
        return Err(OpenADPError::NoServers);
    }

    // Random server selection for load balancing
    let selected_servers = if server_infos.len() > 15 { // MAX_SERVERS_FOR_LOAD_BALANCING
        use rand::seq::SliceRandom;
        let mut servers = server_infos;
        servers.shuffle(&mut rand::thread_rng());
        servers.into_iter().take(15).collect()
    } else {
        server_infos
    };

    println!("📋 Using {} servers for registration", selected_servers.len());

    // Step 2: Generate encryption key using OpenADP protocol
    println!("🔄 Using backup ID: {}", backup_id);
    println!("🔑 Generating encryption key using OpenADP servers...");

    // Create Identity from Ocrypt parameters
    let identity = crate::keygen::Identity::new(
        user_id.to_string(),  // UID = userID (user identifier)
        app_id.to_string(),   // DID = appID (application identifier, serves as device ID)
        backup_id.to_string() // BID = backupID (managed by Ocrypt: "even"/"odd")
    );
    
    let key_result = generate_encryption_key(&identity, pin, max_guesses, 0, selected_servers).await?;

    if key_result.encryption_key.is_none() {
        return Err(OpenADPError::Server(
            key_result.error.unwrap_or_else(|| "Key generation failed".to_string())
        ));
    }

    let encryption_key = key_result.encryption_key.unwrap();
    let auth_codes = key_result.auth_codes.unwrap();
    let server_infos = key_result.server_infos.unwrap();
    let threshold = key_result.threshold.unwrap();

    println!("✅ Generated encryption key with {} servers", server_infos.len());

    // Step 3: Wrap the long-term secret
    println!("🔐 Wrapping long-term secret...");
    let wrapped_secret = wrap_secret(long_term_secret, &encryption_key)?;

    // Step 4: Create metadata
    let server_urls: Vec<String> = server_infos.iter().map(|s| s.url.clone()).collect();
    
    let metadata = OcryptMetadata {
        servers: server_urls,
        threshold,
        version: "1.0".to_string(),
        auth_code: auth_codes.base_auth_code,
        user_id: user_id.to_string(),
        wrapped_long_term_secret: wrapped_secret,
        backup_id: backup_id.to_string(),
        app_id: app_id.to_string(),
        max_guesses,
        ocrypt_version: "1.0".to_string(),
    };

    let metadata_bytes = serde_json::to_vec(&metadata)?;
    println!("📦 Created metadata ({} bytes)", metadata_bytes.len());
    println!("🎯 Threshold: {}-of-{} recovery", metadata.threshold, metadata.servers.len());

    Ok(metadata_bytes)
}

/// Internal function to recover without backup refresh
async fn recover_without_refresh(
    metadata_bytes: &[u8],
    pin: &str,
    servers_url: &str,
) -> Result<(Vec<u8>, u32)> {
    // Parse metadata
    let metadata: OcryptMetadata = serde_json::from_slice(metadata_bytes)?;
    
    // Recover encryption key using OpenADP protocol
    // Create Identity from metadata
    let identity = crate::keygen::Identity::new(
        metadata.user_id.clone(),   // UID = userID
        metadata.app_id.clone(),    // DID = appID  
        metadata.backup_id.clone()  // BID = backupID
    );
    
    // Get server info (use custom URL if provided, otherwise use servers from metadata)
    let server_infos = if servers_url.is_empty() {
        // Use servers from metadata
        metadata.servers.iter().map(|url| ServerInfo {
            url: url.clone(),
            public_key: String::new(),
            country: String::new(),
            remaining_guesses: None,
        }).collect()
    } else {
        // Use custom registry
        discover_servers(servers_url).await?
    };

    // Create auth codes from metadata
    let mut server_auth_codes = std::collections::HashMap::new();
    
    // Reconstruct server auth codes from base auth code (same logic as other implementations)
    for server_url in &metadata.servers {
        let combined = format!("{}:{}", metadata.auth_code, server_url);
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let hash = hasher.finalize();
        let server_code = hex::encode(&hash);
        server_auth_codes.insert(server_url.clone(), server_code);
    }
    
    let auth_codes = crate::keygen::AuthCodes {
        base_auth_code: metadata.auth_code.clone(),
        server_auth_codes,
    };

    let recovery_result = recover_encryption_key(
        &identity,
        pin, 
        server_infos, 
        metadata.threshold, 
        auth_codes
    ).await?;
    
    if recovery_result.encryption_key.is_none() {
        return Err(OpenADPError::Server(
            recovery_result.error.unwrap_or_else(|| "Key recovery failed".to_string())
        ));
    }
    
    let encryption_key = recovery_result.encryption_key.unwrap();
    
    // Unwrap the long-term secret
    let secret = unwrap_secret(&metadata.wrapped_long_term_secret, &encryption_key)?;
    
    Ok((secret, 0)) // 0 remaining guesses = success
}

/// Attempt to refresh backup using two-phase commit
async fn attempt_backup_refresh(
    secret: &[u8],
    metadata_bytes: &[u8],
    pin: &str,
    servers_url: &str,
) -> Result<Vec<u8>> {
    let metadata: OcryptMetadata = serde_json::from_slice(metadata_bytes)?;
    
    // Generate next backup ID
    let new_backup_id = generate_next_backup_id(&metadata.backup_id);
    
    println!("🔄 Attempting backup refresh: {} → {}", metadata.backup_id, new_backup_id);
    
    // Phase 1: PREPARE - Register new backup (old one still exists)
    let new_metadata = register_with_bid(
        &metadata.user_id,
        &metadata.app_id,
        secret,
        pin,
        metadata.max_guesses,
        &new_backup_id,
        servers_url,
    ).await?;

    // Phase 2: COMMIT - Verify new backup works
    let (recovered_secret, _) = recover_without_refresh(&new_metadata, pin, servers_url).await?;
    
    if recovered_secret == secret {
        println!("✅ Two-phase commit verification successful");
        Ok(new_metadata)
    } else {
        Err(OpenADPError::Server("Two-phase commit verification failed".to_string()))
    }
}

/// Discover servers from registry
async fn discover_servers(servers_url: &str) -> Result<Vec<ServerInfo>> {
    let registry_url = if servers_url.is_empty() {
        crate::DEFAULT_REGISTRY_URL
    } else {
        servers_url
    };

    println!("🌐 Discovering servers from registry: {}", registry_url);

    let servers = get_servers(registry_url).await?;
    
    println!("   ✅ Successfully fetched {} servers from registry", servers.len());
    println!("   📋 {} servers are live and ready", servers.len());
    
    Ok(servers)
}

/// Wrap secret with AES-256-GCM
fn wrap_secret(secret: &[u8], key: &[u8]) -> Result<WrappedSecret> {
    if key.len() != 32 {
        return Err(OpenADPError::Crypto("Key must be 32 bytes".to_string()));
    }
    
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    
    let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, secret)
        .map_err(|e| OpenADPError::Crypto(format!("AES-GCM encryption failed: {}", e)))?;
    
    // Split ciphertext and tag (AES-GCM appends 16-byte tag)
    let (encrypted_data, tag) = ciphertext.split_at(ciphertext.len() - 16);
    
    Ok(WrappedSecret {
        nonce: BASE64.encode(&nonce_bytes),
        ciphertext: BASE64.encode(encrypted_data),
        tag: BASE64.encode(tag),
    })
}

/// Unwrap secret with AES-256-GCM
fn unwrap_secret(wrapped: &WrappedSecret, key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(OpenADPError::Crypto("Key must be 32 bytes".to_string()));
    }
    
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    
    let nonce_bytes = BASE64.decode(&wrapped.nonce)
        .map_err(|e| OpenADPError::Crypto(format!("Invalid nonce: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let encrypted_data = BASE64.decode(&wrapped.ciphertext)
        .map_err(|e| OpenADPError::Crypto(format!("Invalid ciphertext: {}", e)))?;
    let tag = BASE64.decode(&wrapped.tag)
        .map_err(|e| OpenADPError::Crypto(format!("Invalid tag: {}", e)))?;
    
    // Combine ciphertext and tag for AES-GCM
    let mut ciphertext_with_tag = encrypted_data;
    ciphertext_with_tag.extend_from_slice(&tag);
    
    let plaintext = cipher.decrypt(nonce, ciphertext_with_tag.as_slice())
        .map_err(|_| OpenADPError::Authentication("Invalid PIN or corrupted data".to_string()))?;
    
    Ok(plaintext)
}

/// Generate next backup ID using alternation strategy
fn generate_next_backup_id(current_backup_id: &str) -> String {
    match current_backup_id {
        "even" => "odd".to_string(),
        "odd" => "even".to_string(),
        _ => {
            // For versioned backup IDs, increment version
            if current_backup_id.starts_with('v') {
                let version_num: u32 = current_backup_id[1..].parse().unwrap_or(1);
                format!("v{}", version_num + 1)
            } else {
                // Fallback to timestamped
                use std::time::{SystemTime, UNIX_EPOCH};
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                format!("{}_v{}", current_backup_id, timestamp)
            }
        }
    }
}

/// Validate input parameters
fn validate_inputs(
    user_id: &str,
    app_id: &str,
    long_term_secret: &[u8],
    pin: &str,
    max_guesses: i32,
) -> Result<()> {
    if user_id.is_empty() {
        return Err(OpenADPError::InvalidInput("user_id cannot be empty".to_string()));
    }
    
    if app_id.is_empty() {
        return Err(OpenADPError::InvalidInput("app_id cannot be empty".to_string()));
    }
    
    if long_term_secret.is_empty() {
        return Err(OpenADPError::InvalidInput("long_term_secret cannot be empty".to_string()));
    }
    
    if pin.is_empty() {
        return Err(OpenADPError::InvalidInput("pin cannot be empty".to_string()));
    }
    
    if max_guesses <= 0 {
        return Err(OpenADPError::InvalidInput("max_guesses must be at least 1".to_string()));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_id_generation() {
        assert_eq!(generate_next_backup_id("even"), "odd");
        assert_eq!(generate_next_backup_id("odd"), "even");
        assert_eq!(generate_next_backup_id("v1"), "v2");
        assert_eq!(generate_next_backup_id("v42"), "v43");
        
        let timestamped = generate_next_backup_id("production");
        assert!(timestamped.starts_with("production_v"));
    }
    
    #[test]
    fn test_secret_wrapping() {
        let secret = b"test_secret";
        let key = [42u8; 32];
        
        let wrapped = wrap_secret(secret, &key).unwrap();
        let unwrapped = unwrap_secret(&wrapped, &key).unwrap();
        
        assert_eq!(secret, unwrapped.as_slice());
    }
    
    #[test]
    fn test_input_validation() {
        assert!(validate_inputs("", "app", b"secret", "pin", 10).is_err());
        assert!(validate_inputs("user", "", b"secret", "pin", 10).is_err());
        assert!(validate_inputs("user", "app", b"", "pin", 10).is_err());
        assert!(validate_inputs("user", "app", b"secret", "", 10).is_err());
        assert!(validate_inputs("user", "app", b"secret", "pin", 0).is_err());
        assert!(validate_inputs("user", "app", b"secret", "pin", 10).is_ok());
    }
    
    #[test]
    fn test_metadata_serialization() {
        let wrapped_secret = WrappedSecret {
            nonce: "test_nonce".to_string(),
            ciphertext: "test_ciphertext".to_string(),
            tag: "test_tag".to_string(),
        };
        
        let metadata = OcryptMetadata {
            servers: vec!["server1".to_string(), "server2".to_string()],
            threshold: 2,
            version: "1.0".to_string(),
            auth_code: "auth123".to_string(),
            user_id: "user@example.com".to_string(),
            wrapped_long_term_secret: wrapped_secret,
            backup_id: "even".to_string(),
            app_id: "test_app".to_string(),
            max_guesses: 10,
            ocrypt_version: "1.0".to_string(),
        };
        
        let serialized = serde_json::to_vec(&metadata).unwrap();
        let deserialized: OcryptMetadata = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(metadata.user_id, deserialized.user_id);
        assert_eq!(metadata.app_id, deserialized.app_id);
        assert_eq!(metadata.threshold, deserialized.threshold);
    }
} 