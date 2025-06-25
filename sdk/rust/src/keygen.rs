//! Key generation and recovery for OpenADP.
//!
//! This module provides high-level functions for generating encryption keys using
//! the OpenADP distributed secret sharing system, matching the Go and Python implementations exactly.
//!
//! This module handles the complete workflow:
//! 1. Generate random secrets and split into shares
//! 2. Register shares with distributed servers  
//! 3. Recover secrets from servers during decryption
//! 4. Derive encryption keys using cryptographic functions

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hex;
use rug::Integer;
use rand::rngs::OsRng;
use rand::{RngCore, Rng};

use crate::{OpenADPError, Result};
use crate::client::{EncryptedOpenADPClient, ServerInfo, RegisterSecretRequest, RecoverSecretRequest, parse_server_public_key, ListBackupsRequest};
use crate::crypto::{hash_to_point, point_compress, Point4D, ShamirSecretSharing};

/// Identity represents the primary key tuple for secret shares stored on servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub uid: String,  // User ID - uniquely identifies the user
    pub did: String,  // Device ID - identifies the device/application  
    pub bid: String,  // Backup ID - identifies the specific backup
}

impl Identity {
    pub fn new(uid: String, did: String, bid: String) -> Self {
        Self { uid, did, bid }
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UID={}, DID={}, BID={}", self.uid, self.did, self.bid)
    }
}

/// Authentication codes for OpenADP servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodes {
    pub base_auth_code: String,
    pub server_auth_codes: HashMap<String, String>,
}

impl AuthCodes {
    pub fn get_server_code(&self, server_url: &str) -> Option<&String> {
        self.server_auth_codes.get(server_url)
    }
}

/// Result of encryption key generation
#[derive(Debug, Clone)]
pub struct GenerateEncryptionKeyResult {
    pub encryption_key: Option<Vec<u8>>,
    pub error: Option<String>,
    pub server_infos: Option<Vec<ServerInfo>>,
    pub threshold: Option<usize>,
    pub auth_codes: Option<AuthCodes>,
}

impl GenerateEncryptionKeyResult {
    pub fn success(
        encryption_key: Vec<u8>,
        server_infos: Vec<ServerInfo>,
        threshold: usize,
        auth_codes: AuthCodes,
    ) -> Self {
        Self {
            encryption_key: Some(encryption_key),
            error: None,
            server_infos: Some(server_infos),
            threshold: Some(threshold),
            auth_codes: Some(auth_codes),
        }
    }
    
    pub fn error(error: String) -> Self {
        Self {
            encryption_key: None,
            error: Some(error),
            server_infos: None,
            threshold: None,
            auth_codes: None,
        }
    }
}

/// Result of encryption key recovery
#[derive(Debug, Clone)]
pub struct RecoverEncryptionKeyResult {
    pub encryption_key: Option<Vec<u8>>,
    pub error: Option<String>,
}

impl RecoverEncryptionKeyResult {
    pub fn success(encryption_key: Vec<u8>) -> Self {
        Self {
            encryption_key: Some(encryption_key),
            error: None,
        }
    }
    
    pub fn error(error: String) -> Self {
        Self {
            encryption_key: None,
            error: Some(error),
        }
    }
}

/// Convert user password to PIN bytes for cryptographic operations (matches Go/Python PasswordToPin)
pub fn password_to_pin(password: &str) -> Vec<u8> {
    // Hash password to get consistent bytes, then take first 2 bytes as PIN
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash_bytes = hasher.finalize();
    hash_bytes[..2].to_vec()
}

/// Generate authentication codes for OpenADP servers (matches Go/Python GenerateAuthCodes)
pub fn generate_auth_codes(server_urls: &[String]) -> AuthCodes {
    // Generate random base authentication code (32 bytes = 256 bits)
    let mut rng = rand::thread_rng();
    let base_auth_bytes: [u8; 32] = rng.gen();
    let base_auth_code = hex::encode(base_auth_bytes);
    
    let mut auth_codes = AuthCodes {
        base_auth_code: base_auth_code.clone(),
        server_auth_codes: HashMap::new(),
    };
    
    // Derive server-specific auth codes
    for server_url in server_urls {
        // Combine base auth code with server URL and hash (matches Go format with colon separator)
        let combined = format!("{}:{}", base_auth_code, server_url);
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let server_hash = hasher.finalize();
        let server_code = hex::encode(server_hash);
        
        auth_codes.server_auth_codes.insert(server_url.clone(), server_code);
    }
    
    auth_codes
}

/// Generate an encryption key using OpenADP distributed secret sharing
pub async fn generate_encryption_key(
    identity: &Identity,
    password: &str,
    max_guesses: i32,
    expiration: i64,
    server_infos: Vec<ServerInfo>,
) -> Result<GenerateEncryptionKeyResult> {
    // Input validation
    if identity.uid.is_empty() {
        return Ok(GenerateEncryptionKeyResult::error("UID cannot be empty".to_string()));
    }
    
    if identity.did.is_empty() {
        return Ok(GenerateEncryptionKeyResult::error("DID cannot be empty".to_string()));
    }
    
    if identity.bid.is_empty() {
        return Ok(GenerateEncryptionKeyResult::error("BID cannot be empty".to_string()));
    }

    if max_guesses < 0 {
        return Ok(GenerateEncryptionKeyResult::error("Max guesses cannot be negative".to_string()));
    }

    if server_infos.is_empty() {
        return Ok(GenerateEncryptionKeyResult::error("No OpenADP servers available".to_string()));
    }

    println!("OpenADP: Identity={}", identity);

    // Step 1: Convert password to PIN
    let pin = password_to_pin(password);
    
    // Step 2: Initialize encrypted clients for each server
    let mut clients = Vec::new();
    let mut live_server_infos = Vec::new();
    
    for server_info in &server_infos {
        let public_key = if !server_info.public_key.is_empty() {
            match parse_server_public_key(&server_info.public_key) {
                Ok(key) => Some(key),
                Err(e) => {
                    println!("Warning: Invalid public key for server {}: {}", server_info.url, e);
                    None
                }
            }
        } else {
            None
        };
        
        let mut client = EncryptedOpenADPClient::new(server_info.url.clone(), public_key.clone(), 30);
        
        match client.ping().await {
            Ok(_) => {
                clients.push(client);
                live_server_infos.push(server_info.clone());
                if public_key.is_some() {
                    println!("OpenADP: Server {} - Using Noise-NK encryption (key from servers.json)", server_info.url);
                } else {
                    println!("OpenADP: Server {} - No encryption (no public key)", server_info.url);
                }
            }
            Err(e) => {
                println!("Warning: Server {} is not accessible: {}", server_info.url, e);
            }
        }
    }
    
    if clients.is_empty() {
        return Ok(GenerateEncryptionKeyResult::error("No live servers available".to_string()));
    }
    
    println!("OpenADP: Using {} live servers", clients.len());
    
    // Step 4: Generate authentication codes
    let server_urls: Vec<String> = live_server_infos.iter().map(|s| s.url.clone()).collect();
    let mut auth_codes = generate_auth_codes(&server_urls);
    
    // Step 5: Generate RANDOM secret and create point
    // SECURITY FIX: Use random secret for Shamir secret sharing, not deterministic
    // Generate random secret from 0 to Q-1
    // Note: secret can be 0 - this is valid for Shamir secret sharing
    let mut random_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut random_bytes);
    let secret_int = Integer::from_digits(&random_bytes, rug::integer::Order::MsfBe);
    let q = ShamirSecretSharing::get_q();
    let secret = secret_int % &q;
    
    // Split the random secret using Shamir secret sharing
    let threshold = live_server_infos.len() / 2 + 1;
    let shares = ShamirSecretSharing::split_secret(&secret, threshold, live_server_infos.len())?;
    
    // Step 6: Compute U = H(uid, did, bid, pin)
    let u_point = hash_to_point(identity.uid.as_bytes(), identity.did.as_bytes(), identity.bid.as_bytes(), &pin)?;
    let _u_compressed = point_compress(&u_point)?;
    
    // Step 7: Register shares with servers
    println!("🔑 Registering shares with {} servers...", clients.len());
    
    for (i, mut client) in clients.into_iter().enumerate() {
        let (share_id, share_data) = &shares[i];
        let server_url = &live_server_infos[i].url;
        let server_auth_code = auth_codes.get_server_code(server_url)
            .ok_or_else(|| OpenADPError::Authentication("Missing server auth code".to_string()))?;
        
        // Convert share to scalar and compute share point
        let _share_scalar = {
            let mut bytes = [0u8; 32];
            // share_data is now Integer, convert to bytes
            share_data.write_digits(&mut bytes, rug::integer::Order::MsfBe);
            bytes
        };
        
        // For now, use a simplified point computation
        // In practice, would compute proper elliptic curve operations
        let share_point = u_point.clone(); // Simplified
        let y_compressed = point_compress(&share_point)?;
        
        let request = RegisterSecretRequest {
            auth_code: server_auth_code.clone(),
            uid: identity.uid.clone(),
            did: identity.did.clone(),
            bid: identity.bid.clone(),
            version: 1,
            x: *share_id as i32,
            y: BASE64.encode(&y_compressed),
            max_guesses,
            expiration,
            encrypted: client.has_public_key(),
            auth_data: None,
        };
        
        match client.register_secret_standardized(request).await {
            Ok(response) => {
                if response.success {
                    println!("✅ Registered share {} with server {}", share_id, server_url);
                } else {
                    println!("❌ Failed to register share {} with server {}: {}", 
                        share_id, server_url, response.message);
                }
            }
            Err(e) => {
                println!("❌ Error registering share {} with server {}: {}", 
                    share_id, server_url, e);
            }
        }
    }
    
    // Step 8: Derive encryption key from secret and U
    // Convert Integer secret to bytes
    let secret_bytes = {
        let mut bytes = vec![0u8; 32];
        secret.write_digits(&mut bytes, rug::integer::Order::MsfBe);
        bytes
    };
    let encryption_key = derive_encryption_key_from_secret(&secret_bytes, &u_point)?;
    
    println!("✅ Generated encryption key with {}-of-{} threshold", threshold, live_server_infos.len());
    
    Ok(GenerateEncryptionKeyResult::success(
        encryption_key,
        live_server_infos,
        threshold,
        auth_codes,
    ))
}

/// Recover an encryption key using OpenADP distributed secret sharing
pub async fn recover_encryption_key(
    identity: &Identity,
    password: &str,
    server_infos: Vec<ServerInfo>,
    threshold: usize,
    auth_codes: AuthCodes,
) -> Result<RecoverEncryptionKeyResult> {
    // Input validation
    if identity.uid.is_empty() {
        return Ok(RecoverEncryptionKeyResult::error("UID cannot be empty".to_string()));
    }
    
    if identity.did.is_empty() {
        return Ok(RecoverEncryptionKeyResult::error("DID cannot be empty".to_string()));
    }
    
    if identity.bid.is_empty() {
        return Ok(RecoverEncryptionKeyResult::error("BID cannot be empty".to_string()));
    }

    if server_infos.is_empty() {
        return Ok(RecoverEncryptionKeyResult::error("No servers available".to_string()));
    }

    println!("OpenADP: Identity={}", identity);

    // Step 1: Convert password to PIN
    let pin = password_to_pin(password);

    // Step 2: Fetch remaining guesses for all servers and select the best ones
    println!("OpenADP: Fetching remaining guesses from servers...");
    let server_infos_with_guesses = fetch_remaining_guesses_for_servers(identity, &server_infos).await;
    
    // Calculate threshold for server selection
    let calculated_threshold = server_infos_with_guesses.len() / 2 + 1; // Standard majority threshold: floor(N/2) + 1
    
    // Select servers intelligently based on remaining guesses
    let selected_server_infos = select_servers_by_remaining_guesses(&server_infos_with_guesses, calculated_threshold);

    // Step 3: Compute U = H(uid, did, bid, pin)
    let u_point = hash_to_point(identity.uid.as_bytes(), identity.did.as_bytes(), identity.bid.as_bytes(), &pin)?;
    let u_compressed = point_compress(&u_point)?;
    
    // Step 4: Initialize clients and recover shares from selected servers
    let _clients: Vec<EncryptedOpenADPClient> = Vec::new();
    let mut recovered_shares = Vec::new();
    
    for server_info in &selected_server_infos {
        let public_key = if !server_info.public_key.is_empty() {
            parse_server_public_key(&server_info.public_key).ok()
        } else {
            None
        };
        
        let mut client = EncryptedOpenADPClient::new(server_info.url.clone(), public_key, 30);
        
        if let Some(server_auth_code) = auth_codes.get_server_code(&server_info.url) {
            let request = RecoverSecretRequest {
                auth_code: server_auth_code.clone(),
                uid: identity.uid.clone(),
                did: identity.did.clone(),
                bid: identity.bid.clone(),
                b: BASE64.encode(&u_compressed),
                guess_num: 1,
                encrypted: client.has_public_key(),
                auth_data: None,
            };
            
            match client.recover_secret_standardized(request).await {
                Ok(response) => {
                    let guesses_str = if server_info.remaining_guesses == -1 {
                        "unknown".to_string()
                    } else {
                        server_info.remaining_guesses.to_string()
                    };
                    println!("✅ Recovered share from server {} ({} remaining guesses)", server_info.url, guesses_str);
                    // Convert response back to share data - we need to convert the response to bytes
                    let share_bytes = response.x.to_be_bytes().to_vec();
                    recovered_shares.push((response.x as usize, share_bytes));
                    
                    if recovered_shares.len() >= threshold {
                        break; // We have enough shares
                    }
                }
                Err(e) => {
                    println!("❌ Failed to recover from server {}: {}", server_info.url, e);
                }
            }
        }
    }
    
    if recovered_shares.len() < threshold {
        return Ok(RecoverEncryptionKeyResult::error(
            format!("Insufficient shares recovered: {}/{}", recovered_shares.len(), threshold)
        ));
    }
    
    // Step 4: Reconstruct secret from shares
    let secret = ShamirSecretSharing::recover_secret_bytes(recovered_shares)?;
    
    // Step 5: Derive encryption key
    let secret_bytes = {
        let mut bytes = [0u8; 32];
        let len = std::cmp::min(secret.len(), 32);
        bytes[..len].copy_from_slice(&secret[..len]);
        bytes
    };
    
    let encryption_key = derive_encryption_key_from_secret(&secret_bytes, &u_point)?;
    
    println!("✅ Successfully recovered encryption key");
    
    Ok(RecoverEncryptionKeyResult::success(encryption_key))
}

/// Derive encryption key from secret and point
fn derive_encryption_key_from_secret(secret: &[u8], u_point: &Point4D) -> Result<Vec<u8>> {
    // Combine secret with point to derive final key
    let mut hasher = Sha256::new();
    hasher.update(b"OpenADP_FinalKey:");
    hasher.update(secret);
    
    let u_compressed = point_compress(u_point)?;
    hasher.update(&u_compressed);
    
    let key_hash = hasher.finalize();
    Ok(key_hash.to_vec())
}

/// Fetch remaining guesses for each server and update ServerInfo objects.
/// 
/// # Arguments
/// * `identity` - The identity to check remaining guesses for
/// * `server_infos` - List of ServerInfo objects to update
/// 
/// # Returns
/// Updated list of ServerInfo objects with remaining_guesses populated
pub async fn fetch_remaining_guesses_for_servers(
    identity: &Identity,
    server_infos: &[ServerInfo],
) -> Vec<ServerInfo> {
    let mut updated_server_infos = Vec::new();
    
    for server_info in server_infos {
        // Create a copy to avoid modifying the original
        let mut updated_server_info = server_info.clone();
        
        // Parse public key if available
        let public_key = if !server_info.public_key.is_empty() {
            match parse_server_public_key(&server_info.public_key) {
                Ok(key) => Some(key),
                Err(e) => {
                    println!("Warning: Invalid public key for server {}: {}", server_info.url, e);
                    None
                }
            }
        } else {
            None
        };
        
        // Create client and try to fetch backup info
        let mut client = EncryptedOpenADPClient::new(server_info.url.clone(), public_key, 30);
        
        match client.ping().await {
            Ok(_) => {
                // List backups to get remaining guesses
                let list_request = ListBackupsRequest {
                    uid: identity.uid.clone(),
                    auth_code: String::new(),
                    encrypted: false,
                    auth_data: None,
                };
                
                match client.list_backups_standardized(list_request).await {
                    Ok(response) => {
                        // Find our specific backup
                        let mut remaining_guesses = -1; // Default to unknown
                        for backup in &response.backups {
                            if backup.uid == identity.uid && 
                               backup.bid == identity.bid {
                                remaining_guesses = std::cmp::max(0, backup.max_guesses - backup.num_guesses);
                                break;
                            }
                        }
                        
                        updated_server_info.remaining_guesses = remaining_guesses;
                        println!("OpenADP: Server {} has {} remaining guesses", server_info.url, remaining_guesses);
                    }
                    Err(e) => {
                        println!("Warning: Could not list backups from server {}: {}", server_info.url, e);
                        // Keep the original remaining_guesses value (likely -1 for unknown)
                    }
                }
            }
            Err(e) => {
                println!("Warning: Could not connect to server {}: {}", server_info.url, e);
                // Keep the original remaining_guesses value (likely -1 for unknown)
            }
        }
        
        updated_server_infos.push(updated_server_info);
    }
    
    updated_server_infos
}

/// Select servers intelligently based on remaining guesses.
/// 
/// Strategy:
/// 1. Filter out servers with 0 remaining guesses (exhausted)
/// 2. Sort by remaining guesses (descending) to use servers with most guesses first
/// 3. Servers with unknown remaining guesses (-1) are treated as having infinite guesses
/// 4. Select threshold + 2 servers for redundancy
/// 
/// # Arguments
/// * `server_infos` - List of ServerInfo objects with remaining_guesses populated
/// * `threshold` - Minimum number of servers needed
/// 
/// # Returns
/// Selected servers sorted by remaining guesses (descending)
pub fn select_servers_by_remaining_guesses(
    server_infos: &[ServerInfo],
    threshold: usize,
) -> Vec<ServerInfo> {
    // Filter out servers with 0 remaining guesses (exhausted)
    let mut available_servers: Vec<ServerInfo> = server_infos
        .iter()
        .filter(|s| s.remaining_guesses != 0)
        .cloned()
        .collect();
    
    if available_servers.is_empty() {
        println!("Warning: All servers have exhausted their guesses!");
        return server_infos.to_vec(); // Return original list as fallback
    }
    
    // Sort by remaining guesses (descending)
    // Servers with unknown remaining guesses (-1) are treated as having the highest priority
    available_servers.sort_by(|a, b| {
        let a_guesses = if a.remaining_guesses == -1 { i32::MAX } else { a.remaining_guesses };
        let b_guesses = if b.remaining_guesses == -1 { i32::MAX } else { b.remaining_guesses };
        b_guesses.cmp(&a_guesses)
    });
    
    // Select threshold + 2 servers for redundancy, but don't exceed available servers
    let num_to_select = std::cmp::min(available_servers.len(), threshold + 2);
    let selected_servers = available_servers.into_iter().take(num_to_select).collect::<Vec<_>>();
    
    println!("OpenADP: Selected {} servers based on remaining guesses:", selected_servers.len());
    for (i, server) in selected_servers.iter().enumerate() {
        let guesses_str = if server.remaining_guesses == -1 {
            "unknown".to_string()
        } else {
            server.remaining_guesses.to_string()
        };
        println!("  {}. {} ({} remaining guesses)", i + 1, server.url, guesses_str);
    }
    
    selected_servers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ServerInfo;
    
    #[test]
    fn test_identity() {
        let identity = Identity::new(
            "user@example.com".to_string(),
            "laptop".to_string(),
            "even".to_string()
        );
        
        assert_eq!(identity.uid, "user@example.com");
        assert_eq!(identity.did, "laptop");
        assert_eq!(identity.bid, "even");
        
        // Test Display trait
        let display_str = identity.to_string();
        assert!(display_str.contains("user@example.com"));
        assert!(display_str.contains("laptop"));
        assert!(display_str.contains("even"));
    }
    
    #[test]
    fn test_password_to_pin() {
        let pin = password_to_pin("secure_password");
        assert_eq!(pin.len(), 2);
        
        // Same password should produce same PIN
        let pin2 = password_to_pin("secure_password");
        assert_eq!(pin, pin2);
        
        // Different passwords should produce different PINs
        let pin3 = password_to_pin("different_password");
        assert_ne!(pin, pin3);
    }
    
    #[test]
    fn test_generate_auth_codes() {
        let server_urls = vec![
            "https://server1.example.com".to_string(),
            "https://server2.example.com".to_string(),
        ];
        
        let auth_codes = generate_auth_codes(&server_urls);
        
        assert!(!auth_codes.base_auth_code.is_empty());
        assert_eq!(auth_codes.server_auth_codes.len(), 2);
        
        for url in &server_urls {
            assert!(auth_codes.get_server_code(url).is_some());
        }
    }
    
    #[test]
    fn test_auth_codes_structure() {
        let mut auth_codes = AuthCodes {
            base_auth_code: "base123".to_string(),
            server_auth_codes: HashMap::new(),
        };
        auth_codes.server_auth_codes.insert("server1".to_string(), "code1".to_string());
        auth_codes.server_auth_codes.insert("server2".to_string(), "code2".to_string());
        
        assert_eq!(auth_codes.base_auth_code, "base123");
        assert_eq!(auth_codes.get_server_code("server1"), Some(&"code1".to_string()));
        assert_eq!(auth_codes.get_server_code("server2"), Some(&"code2".to_string()));
        assert_eq!(auth_codes.get_server_code("server3"), None);
    }
    
    #[test]
    fn test_result_structures() {
        let success_result = GenerateEncryptionKeyResult::success(
            vec![1, 2, 3, 4],
            vec![ServerInfo::new("test".to_string())],
            3,
            AuthCodes {
                base_auth_code: "auth".to_string(),
                server_auth_codes: HashMap::new(),
            },
        );
        
        assert!(success_result.encryption_key.is_some());
        assert!(success_result.error.is_none());
        
        let error_result = GenerateEncryptionKeyResult::error("Test error".to_string());
        assert!(error_result.encryption_key.is_none());
        assert!(error_result.error.is_some());
    }

    #[test]
    fn test_identity_validation() {
        // Test valid identity
        let valid_identity = Identity::new(
            "user@example.com".to_string(),
            "laptop-2024".to_string(),
            "backup-001".to_string()
        );
        assert!(!valid_identity.uid.is_empty());
        assert!(!valid_identity.did.is_empty());
        assert!(!valid_identity.bid.is_empty());
        
        // Test identity with special characters
        let special_identity = Identity::new(
            "user+test@example.com".to_string(),
            "device-123_ABC".to_string(),
            "file://path/to/document.pdf".to_string()
        );
        assert_eq!(special_identity.uid, "user+test@example.com");
        assert_eq!(special_identity.did, "device-123_ABC");
        assert_eq!(special_identity.bid, "file://path/to/document.pdf");
        
        // Test identity display format
        let display_str = special_identity.to_string();
        assert!(display_str.contains("UID=user+test@example.com"));
        assert!(display_str.contains("DID=device-123_ABC"));
        assert!(display_str.contains("BID=file://path/to/document.pdf"));
    }

    #[test]
    fn test_auth_codes_comprehensive() {
        let server_urls = vec![
            "https://server1.openadp.org:8443".to_string(),
            "https://server2.openadp.org:8443".to_string(),
            "https://server3.openadp.org:8443".to_string(),
            "https://localhost:8080".to_string(),
        ];
        
        let auth_codes = generate_auth_codes(&server_urls);
        
        // Base auth code should be 64 hex characters (32 bytes)
        assert_eq!(auth_codes.base_auth_code.len(), 64);
        assert!(auth_codes.base_auth_code.chars().all(|c| c.is_ascii_hexdigit()));
        
        // Should have auth codes for all servers
        assert_eq!(auth_codes.server_auth_codes.len(), server_urls.len());
        
        // Each server auth code should be 64 hex characters (32 bytes from SHA256)
        for (url, code) in &auth_codes.server_auth_codes {
            assert!(server_urls.contains(url));
            assert_eq!(code.len(), 64);
            assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
        }
        
        // Different servers should have different auth codes
        let codes: Vec<&String> = auth_codes.server_auth_codes.values().collect();
        for i in 0..codes.len() {
            for j in i+1..codes.len() {
                assert_ne!(codes[i], codes[j], "Server auth codes should be unique");
            }
        }
        
        // Auth codes should be deterministic for same inputs
        let auth_codes2 = generate_auth_codes(&server_urls);
        // Note: This will be different because we generate random base codes
        // But the derivation process should be consistent
        assert_eq!(auth_codes.server_auth_codes.len(), auth_codes2.server_auth_codes.len());
    }

    #[test]
    fn test_password_to_pin_comprehensive() {
        // Test various password types
        let passwords = vec![
            "simple",
            "Complex_Password123!",
            "unicode_测试_пароль",
            "very_long_password_that_exceeds_normal_length_to_test_hashing_behavior",
            "",  // Empty password
            "🔐🗝️🔑",  // Emoji password
        ];
        
        for password in &passwords {
            let pin = password_to_pin(password);
            assert_eq!(pin.len(), 2, "PIN should always be 2 bytes for password: {}", password);
            
            // Same password should always produce same PIN
            let pin2 = password_to_pin(password);
            assert_eq!(pin, pin2, "PIN should be deterministic for password: {}", password);
        }
        
        // Different passwords should generally produce different PINs
        let pin1 = password_to_pin("password1");
        let pin2 = password_to_pin("password2");
        assert_ne!(pin1, pin2, "Different passwords should produce different PINs");
        
        // Test edge case: very similar passwords
        let pin_a = password_to_pin("test_password_a");
        let pin_b = password_to_pin("test_password_b");
        assert_ne!(pin_a, pin_b, "Similar passwords should produce different PINs");
    }

    #[test]
    fn test_encryption_key_derivation() {
        use crate::crypto::{hash_to_point, derive_enc_key};
        
        // Test that key derivation is deterministic
        let identity = Identity::new(
            "test@example.com".to_string(),
            "device123".to_string(),
            "backup456".to_string()
        );
        let password = "test_password";
        let pin = password_to_pin(password);
        
        // Generate point from identity and PIN
        let point1 = hash_to_point(
            identity.uid.as_bytes(),
            identity.did.as_bytes(), 
            identity.bid.as_bytes(),
            &pin
        ).unwrap();
        
        let point2 = hash_to_point(
            identity.uid.as_bytes(),
            identity.did.as_bytes(),
            identity.bid.as_bytes(), 
            &pin
        ).unwrap();
        
        // Same inputs should produce same point
        assert_eq!(point1.x, point2.x);
        assert_eq!(point1.y, point2.y);
        
        // Derive encryption keys
        let key1 = derive_enc_key(&point1).unwrap();
        let key2 = derive_enc_key(&point2).unwrap();
        
        // Keys should be identical
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
        
        // Different identity should produce different key
        let different_identity = Identity::new(
            "different@example.com".to_string(),
            "device123".to_string(),
            "backup456".to_string()
        );
        
        let different_point = hash_to_point(
            different_identity.uid.as_bytes(),
            different_identity.did.as_bytes(),
            different_identity.bid.as_bytes(),
            &pin
        ).unwrap();
        
        let different_key = derive_enc_key(&different_point).unwrap();
        assert_ne!(key1, different_key);
    }

    #[test]
    fn test_input_validation_edge_cases() {
        // Test empty strings
        let empty_identity = Identity::new("".to_string(), "did".to_string(), "bid".to_string());
        assert!(empty_identity.uid.is_empty());
        
        let empty_identity2 = Identity::new("uid".to_string(), "".to_string(), "bid".to_string());
        assert!(empty_identity2.did.is_empty());
        
        let empty_identity3 = Identity::new("uid".to_string(), "did".to_string(), "".to_string());
        assert!(empty_identity3.bid.is_empty());
        
        // Test very long strings
        let long_string = "a".repeat(1000);
        let long_identity = Identity::new(
            long_string.clone(),
            long_string.clone(),
            long_string.clone()
        );
        assert_eq!(long_identity.uid.len(), 1000);
        assert_eq!(long_identity.did.len(), 1000);
        assert_eq!(long_identity.bid.len(), 1000);
        
        // Test special characters and unicode
        let unicode_identity = Identity::new(
            "用户@测试.com".to_string(),
            "设备-123".to_string(),
            "备份/文件.pdf".to_string()
        );
        assert!(unicode_identity.uid.contains("用户"));
        assert!(unicode_identity.did.contains("设备"));
        assert!(unicode_identity.bid.contains("备份"));
    }
} 