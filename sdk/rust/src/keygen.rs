//! Key generation and recovery functionality for OpenADP
//! 
//! This module provides the core cryptographic operations for OpenADP:
//! - Identity management (UID, DID, BID)
//! - Encryption key generation using distributed secret sharing
//! - Key recovery from distributed shares
//! - Authentication code management

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use rand::rngs::OsRng;
use rand::RngCore;
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::{OpenADPError, Result};
use crate::client::{
    EncryptedOpenADPClient, ServerInfo, parse_server_public_key,
    RegisterSecretRequest, RecoverSecretRequest, ListBackupsRequest,
};
use crate::crypto::{
    H, point_compress, ShamirSecretSharing, point_decompress, unexpand, point_mul, 
    derive_enc_key, recover_point_secret, PointShare, mod_inverse
};

/// Identity represents the three-part key for OpenADP: (UID, DID, BID)
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

/// Authentication codes for servers
#[derive(Debug, Clone)]
pub struct AuthCodes {
    pub base_auth_code: String,
    pub server_auth_codes: HashMap<String, String>,
}

impl AuthCodes {
    pub fn get_server_code(&self, server_url: &str) -> Option<&String> {
        self.server_auth_codes.get(server_url)
            .or_else(|| Some(&self.base_auth_code))
    }
}

/// Result of key generation
#[derive(Debug)]
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

/// Result of key recovery
#[derive(Debug)]
pub struct RecoverEncryptionKeyResult {
    pub encryption_key: Option<Vec<u8>>,
    pub error: Option<String>,
    pub num_guesses: i32,  // Actual number of guesses used (from server responses)
    pub max_guesses: i32,  // Maximum guesses allowed (from server responses)
}

impl RecoverEncryptionKeyResult {
    pub fn success(encryption_key: Vec<u8>, num_guesses: i32, max_guesses: i32) -> Self {
        Self {
            encryption_key: Some(encryption_key),
            error: None,
            num_guesses,
            max_guesses,
        }
    }

    pub fn error(error: String) -> Self {
        Self {
            encryption_key: None,
            error: Some(error),
            num_guesses: 0,
            max_guesses: 0,
        }
    }
}

/// Generate authentication codes for servers
pub fn generate_auth_codes(server_urls: &[String]) -> AuthCodes {
    let mut rng = OsRng;
    
    // Generate base auth code (32 random bytes = 64 hex chars, matching Go)
    let mut base_auth_bytes = [0u8; 32];
    rng.fill_bytes(&mut base_auth_bytes);
    let base_auth_code = hex::encode(base_auth_bytes);
    
    // Generate per-server codes by hashing base code with server URL
    let mut server_auth_codes = HashMap::new();
    for server_url in server_urls {
        let mut hasher = Sha256::new();
        hasher.update(base_auth_code.as_bytes());
        hasher.update(b":");
        hasher.update(server_url.as_bytes());
        let hash = hasher.finalize();
        let server_code = hex::encode(&hash);  // Use FULL hash (32 bytes = 64 hex chars) to match Go
        server_auth_codes.insert(server_url.clone(), server_code);
    }
    
    AuthCodes {
        base_auth_code,
        server_auth_codes,
    }
}

/// Generate an encryption key using OpenADP distributed secret sharing
pub async fn generate_encryption_key(
    identity: &Identity,
    password: &str,
    max_guesses: i32,
    expiration: i64,
    server_infos: Vec<ServerInfo>,
) -> Result<GenerateEncryptionKeyResult> {
    if server_infos.is_empty() {
        return Ok(GenerateEncryptionKeyResult::error("No servers available".to_string()));
    }
    
    // Step 1: Generate authentication codes
    let server_urls: Vec<String> = server_infos.iter().map(|s| s.url.clone()).collect();
    let auth_codes = generate_auth_codes(&server_urls);
    
    // Step 2: Test server connectivity and encryption capabilities
    let mut clients = Vec::new();
    let mut live_server_infos = Vec::new();
    
    for server_info in server_infos {
        // Parse public key if available
        let public_key = if !server_info.public_key.is_empty() {
            match parse_server_public_key(&server_info.public_key) {
                Ok(key) => Some(key),
                Err(_) => {
                    None
                }
            }
        } else {
            None
        };
        
        let client = EncryptedOpenADPClient::new(server_info.url.clone(), public_key, 30);
        
        // Test server connectivity
        match client.test_connection().await {
            Ok(_) => {
                clients.push(client);
                live_server_infos.push(server_info);
            }
            Err(_) => {
            }
        }
    }
    
    if live_server_infos.is_empty() {
        return Ok(GenerateEncryptionKeyResult::error("No live servers available".to_string()));
    }
    
    // Step 3: Convert password to PIN
    let pin = password.as_bytes().to_vec();
    
    // Step 4: Generate random secret using cryptographically secure RNG
    let mut random_bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut random_bytes);
    
    // Convert to rug::Integer for Shamir secret sharing
    let secret_int = rug::Integer::from_digits(&random_bytes, rug::integer::Order::MsfBe);
    let q = ShamirSecretSharing::get_q();
    let secret = secret_int % &q;
    
    // Step 5: Calculate threshold (majority threshold like Go: len/2 + 1)
    let threshold = live_server_infos.len() / 2 + 1;
    let num_shares = live_server_infos.len(); // Use ALL live servers, not threshold+2
    
    if num_shares < threshold {
        return Ok(GenerateEncryptionKeyResult::error(format!(
            "Need at least {} servers, only {} available", threshold, num_shares
        )));
    }
    
    // Split the random secret using Shamir secret sharing with ALL live servers
    let shares = ShamirSecretSharing::split_secret(&secret, threshold, num_shares)?;
    
    // Step 6: Compute U = H(uid, did, bid, pin)
    let u = H(identity.uid.as_bytes(), identity.did.as_bytes(), identity.bid.as_bytes(), &pin)?;
    let _u_2d = unexpand(&u)?;
    
    // Step 7: Register shares with servers (concurrent)
    
    let mut registration_errors = Vec::new();
    let mut successful_registrations = 0;
    
    // Create tasks for concurrent registration
    let mut registration_tasks = Vec::new();
    
    for (i, mut client) in clients.into_iter().enumerate() {
        let (share_id, share_data) = shares[i].clone();
        let server_url = live_server_infos[i].url.clone();
        let server_auth_code = match auth_codes.get_server_code(&server_url) {
            Some(code) => code.clone(),
            None => {
                registration_errors.push(format!("Server {}: Missing server auth code", i + 1));
                continue;
            }
        };
        let identity_clone = identity.clone();
        
        // Spawn async task for concurrent registration
        let task = tokio::spawn(async move {
            // Convert share Y to base64-encoded 32-byte little-endian format (per API spec)
            let y_big_int = rug::Integer::from(share_data);
            
            // Convert to 32-byte little-endian array
            let mut y_bytes = vec![0u8; 32];
            let y_digits = y_big_int.to_digits::<u8>(rug::integer::Order::LsfLe);
            let copy_len = std::cmp::min(y_digits.len(), 32);
            y_bytes[..copy_len].copy_from_slice(&y_digits[..copy_len]);
            
            // Encode as base64
            let y_string = BASE64.encode(&y_bytes);
            
            let request = RegisterSecretRequest {
                auth_code: server_auth_code,
                uid: identity_clone.uid,
                did: identity_clone.did,
                bid: identity_clone.bid,
                version: 1,
                x: share_id as i32,
                y: y_string,
                max_guesses,
                expiration,
                encrypted: client.has_public_key(),
                auth_data: None,
            };
            
            match client.register_secret_standardized(request).await {
                Ok(response) => {
                    if response.success {
                        Ok((i, server_url, client.has_public_key()))
                    } else {
                        Err(format!("Server {} ({}): Registration returned false: {}", 
                            i + 1, server_url, response.message))
                    }
                }
                Err(err) => {
                    Err(format!("Server {} ({}): {}", i + 1, server_url, err))
                }
            }
        });
        
        registration_tasks.push(task);
    }
    
    // Wait for all registration tasks to complete
    for task in registration_tasks {
        match task.await {
            Ok(Ok((_index, _server_url, has_public_key))) => {
                let _enc_status = if has_public_key { "encrypted" } else { "unencrypted" };
                successful_registrations += 1;
            }
            Ok(Err(error_msg)) => {
                registration_errors.push(error_msg);
            }
            Err(join_error) => {
                registration_errors.push(format!("Task join error: {}", join_error));
            }
        }
    }
    
    if successful_registrations == 0 {
        return Ok(GenerateEncryptionKeyResult::error(format!(
            "Failed to register any shares: {:?}", registration_errors
        )));
    }
    
    // Step 8: Derive encryption key from secret point s*U
    // Convert the secret to a BigUint and multiply with U to get the secret point
    let secret_biguint = {
        let bytes = secret.to_digits::<u8>(rug::integer::Order::MsfBe);
        BigUint::from_bytes_be(&bytes)
    };
    
    // Compute secret point: s*U
    let secret_point = point_mul(&secret_biguint, &u);
    let encryption_key = derive_enc_key(&secret_point)?;
    
    
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
    
    // Step 1: Compute U = H(uid, did, bid, pin) - same as in generation
    let pin = password.as_bytes().to_vec();
    let u = H(identity.uid.as_bytes(), identity.did.as_bytes(), identity.bid.as_bytes(), &pin)?;
    let _u_2d = unexpand(&u)?;
    
    // Step 1.5: Compute r scalar for blinding
    let r_scalar = {
        use rand::RngCore;
        let mut rng = OsRng;
        
        // Generate random bytes and convert to BigUint (matching Go rand.Int(rand.Reader, common.Q))
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        let mut r = BigUint::from_bytes_be(&r_bytes);
        
        // Ensure r < Q (curve order)
        let q = crate::crypto::Q.clone();
        r = r % &q;
        
        // Ensure r != 0 since we need to compute r^-1
        if r.is_zero() {
            r = BigUint::one();
        }
        
        r
    };
    
    
    // Step 2: Fetch remaining guesses and select best servers
    let updated_server_infos = fetch_remaining_guesses_for_servers(identity, &server_infos).await;
    let selected_server_infos = select_servers_by_remaining_guesses(&updated_server_infos, threshold);
    
    if selected_server_infos.is_empty() {
        return Ok(RecoverEncryptionKeyResult::error("No servers available".to_string()));
    }

    // Step 2.5: Fetch server public keys from registry (like Go implementation)
    let registry_servers = match crate::client::get_servers("").await {
        Ok(servers) => servers,
        Err(_) => {
            // Fallback to hardcoded servers if registry fails
            crate::client::get_fallback_server_info()
        }
    };
    
    // Create a map of URL -> public key for quick lookup
    let mut public_key_map = std::collections::HashMap::new();
    for registry_server in &registry_servers {
        if !registry_server.public_key.is_empty() {
            public_key_map.insert(registry_server.url.clone(), registry_server.public_key.clone());
        }
    }
    
    // Update selected servers with public keys from registry
    let mut selected_server_infos_with_keys = Vec::new();
    for mut server_info in selected_server_infos {
        if let Some(public_key_str) = public_key_map.get(&server_info.url) {
            server_info.public_key = public_key_str.clone();
        }
        selected_server_infos_with_keys.push(server_info);
    }
    let selected_server_infos = selected_server_infos_with_keys;
    
    // Step 3: Compute B = r * U  
    let b = point_mul(&r_scalar, &u);
    let _b_2d = unexpand(&b)?;
    
    // Compress B for transmission
    let b_compressed = point_compress(&b)?;
    let b_base64 = BASE64.encode(&b_compressed);

    // Step 4: Recover shares from servers (concurrent)
    let mut recovered_point_shares = Vec::new();
    let mut actual_num_guesses = 0i32;
    let mut actual_max_guesses = 0i32;
    
    // Create tasks for concurrent recovery
    let mut recovery_tasks = Vec::new();
    
    for server_info in selected_server_infos.iter().cloned() {
        // Parse public key if available
        let public_key = if !server_info.public_key.is_empty() {
            match parse_server_public_key(&server_info.public_key) {
                Ok(key) => Some(key),
                Err(_) => {
                    None
                }
            }
        } else {
            None
        };
        
        let client = EncryptedOpenADPClient::new(server_info.url.clone(), public_key, 30);
        
        // Get server auth code
        let server_auth_code = match auth_codes.get_server_code(&server_info.url) {
            Some(code) => code.clone(),
            None => {
                return Err(OpenADPError::Authentication("No auth code for server".to_string()));
            }
        };
        
        let identity_clone = identity.clone();
        let server_url = server_info.url.clone();
        let b_base64_clone = b_base64.clone();
        
        // Spawn async task for concurrent recovery
        let task = tokio::spawn(async move {
            let mut client = client;
            
            // Get current guess number for idempotency (prevents replay attacks)
            let mut guess_num = 0; // Default fallback
            let list_request = ListBackupsRequest {
                uid: identity_clone.uid.clone(),
                auth_code: String::new(),
                encrypted: client.has_public_key(), // Use encryption if available
                auth_data: None,
            };
            
            match client.list_backups_standardized(list_request).await {
                Ok(response) => {
                    // Find our backup in the list using the complete primary key (UID, DID, BID)
                    for backup in &response.backups {
                        if backup.uid == identity_clone.uid && 
                           backup.did == identity_clone.did &&
                           backup.bid == identity_clone.bid {
                            guess_num = backup.num_guesses;
                            break;
                        }
                    }
                }
                Err(err) => {
                    return Err(format!("Cannot get current guess number for idempotency: {}", err));
                }
            }
            
            // Create a fresh client for RecoverSecret (don't reuse the ListBackups client)
            let public_key_fresh = if !server_info.public_key.is_empty() {
                match parse_server_public_key(&server_info.public_key) {
                    Ok(key) => Some(key),
                    Err(_) => None,
                }
            } else {
                None
            };
            let mut fresh_client = EncryptedOpenADPClient::new(server_url.clone(), public_key_fresh, 30);
            
            let request = RecoverSecretRequest {
                auth_code: server_auth_code,
                uid: identity_clone.uid,
                did: identity_clone.did,
                bid: identity_clone.bid,
                guess_num: guess_num,  // Use current num_guesses directly
                b: b_base64_clone,
                encrypted: fresh_client.has_public_key(),
                auth_data: None,
            };
            
            match fresh_client.recover_secret_standardized(request).await {
                Ok(response) => {
                    if response.success {
                        // Parse the returned share
                        if let Some(si_b) = response.si_b {
                            
                            // Decode base64 to get compressed point
                            match BASE64.decode(&si_b) {
                                Ok(si_b_bytes) => {
                                    
                                                                    // Decompress the point
                                let si_b_point = point_decompress(&si_b_bytes)
                                    .map_err(|e| format!("Failed to decompress point: {}", e))?;
                                    
                                    // Return successful result
                                    Ok((response.x as usize, si_b_point, response.num_guesses, response.max_guesses))
                                }
                                Err(e) => {
                                    Err(format!("Failed to decompress point: {}", e))
                                }
                            }
                        } else {
                            Err("Server returned success but no si_b".to_string())
                        }
                    } else {
                        Err(format!("Server error: {}", response.message))
                    }
                }
                Err(err) => {
                    Err(format!("Cannot recover secret: {}", err))
                }
            }
        });
        
        recovery_tasks.push(task);
    }
    
    // Wait for all recovery tasks to complete
    for task in recovery_tasks {
        match task.await {
            Ok(Ok((x, si_b_point, num_guesses, max_guesses))) => {
                // Add to point shares for Lagrange interpolation
                recovered_point_shares.push(PointShare::new(x, si_b_point));
                
                // Capture guess information from server response (first successful server)
                if actual_num_guesses == 0 && actual_max_guesses == 0 {
                    actual_num_guesses = num_guesses;
                    actual_max_guesses = max_guesses;
                }
            }
            Ok(Err(error_msg)) => {
                // Log error but continue with other servers
                eprintln!("Recovery error: {}", error_msg);
            }
            Err(join_error) => {
                eprintln!("Task join error: {}", join_error);
            }
        }
    }
    
    // Step 5: Check if we have enough shares
    if recovered_point_shares.len() < threshold {
        return Ok(RecoverEncryptionKeyResult::error(format!(
            "Not enough shares recovered: got {}, need {}", 
            recovered_point_shares.len(), threshold
        )));
    }
    
    
    // Step 6: Recover the secret point s*U using Lagrange interpolation
    let recovered_sb_4d = recover_point_secret(recovered_point_shares)?;
    let _recovered_sb_2d = unexpand(&recovered_sb_4d)?;
    
    // Step 7: Compute r^-1 mod q 
    let r_inv = mod_inverse(&r_scalar, &crate::crypto::Q.clone());
    
    // Step 8: Compute s*U = r^-1 * (s*r*U) = r^-1 * recovered_sb_4d
    let original_su = point_mul(&r_inv, &recovered_sb_4d);
    let _original_su_2d = unexpand(&original_su)?;
    
    // Step 9: Derive encryption key from the recovered secret point
    let encryption_key = derive_enc_key(&original_su)?;
    
    
    Ok(RecoverEncryptionKeyResult::success(encryption_key, actual_num_guesses, actual_max_guesses))
}

/// Fetch remaining guesses for all servers (concurrent)
pub async fn fetch_remaining_guesses_for_servers(
    identity: &Identity,
    server_infos: &[ServerInfo],
) -> Vec<ServerInfo> {
    let mut updated_infos = Vec::new();
    
    // Create tasks for concurrent guess fetching
    let mut fetch_tasks = Vec::new();
    
    for server_info in server_infos {
        let server_info_clone = server_info.clone();
        let identity_clone = identity.clone();
        
        // Spawn async task for concurrent guess fetching
        let task = tokio::spawn(async move {
            let mut updated_info = server_info_clone;
            
            // Parse public key if available
            let public_key = if !updated_info.public_key.is_empty() {
                match parse_server_public_key(&updated_info.public_key) {
                    Ok(key) => Some(key),
                    Err(_) => {
                        None
                    }
                }
            } else {
                None
            };
            
            let mut client = EncryptedOpenADPClient::new(updated_info.url.clone(), public_key, 30);
            
            let request = ListBackupsRequest {
                uid: identity_clone.uid.clone(),
                auth_code: String::new(),
                encrypted: client.has_public_key(), // Use encryption if available
                auth_data: None,
            };
            
            match client.list_backups_standardized(request).await {
                Ok(response) => {
                    // Find our backup in the list
                    for backup in &response.backups {
                        if backup.uid == identity_clone.uid && 
                           backup.did == identity_clone.did &&
                           backup.bid == identity_clone.bid {
                            updated_info.remaining_guesses = Some(backup.max_guesses - backup.num_guesses);
                            break;
                        }
                    }
                    
                    if updated_info.remaining_guesses.is_none() {
                        updated_info.remaining_guesses = Some(0);
                    }
                }
                Err(_) => {
                    updated_info.remaining_guesses = Some(0);
                }
            }
            
            updated_info
        });
        
        fetch_tasks.push(task);
    }
    
    // Wait for all fetch tasks to complete
    for task in fetch_tasks {
        match task.await {
            Ok(updated_info) => {
                updated_infos.push(updated_info);
            }
            Err(join_error) => {
                eprintln!("Task join error: {}", join_error);
                // Add original server info with 0 remaining guesses as fallback
                let mut fallback_info = server_infos[updated_infos.len()].clone();
                fallback_info.remaining_guesses = Some(0);
                updated_infos.push(fallback_info);
            }
        }
    }
    
    updated_infos
}

/// Select servers with the most remaining guesses
pub fn select_servers_by_remaining_guesses(
    server_infos: &[ServerInfo],
    threshold: usize,
) -> Vec<ServerInfo> {
    // Filter out servers with 0 remaining guesses (exhausted)
    let mut available_servers: Vec<ServerInfo> = server_infos.iter()
        .filter(|info| info.remaining_guesses.unwrap_or(-1) != 0)
        .cloned()
        .collect();
    
    if available_servers.is_empty() {
        return server_infos.to_vec(); // Return original list as fallback
    }
    
    // Sort by remaining guesses (descending)
    // Servers with unknown remaining guesses (-1) are treated as having the highest priority
    available_servers.sort_by(|a, b| {
        let a_guesses = if a.remaining_guesses.unwrap_or(-1) == -1 { 
            i32::MAX 
        } else { 
            a.remaining_guesses.unwrap_or(0) 
        };
        let b_guesses = if b.remaining_guesses.unwrap_or(-1) == -1 { 
            i32::MAX 
        } else { 
            b.remaining_guesses.unwrap_or(0) 
        };
        b_guesses.cmp(&a_guesses)
    });
    
    // Select threshold + 2 servers for redundancy, but don't exceed available servers (matches Go)
    let num_to_select = std::cmp::min(available_servers.len(), threshold + 2);
    let selected_servers = available_servers.into_iter().take(num_to_select).collect::<Vec<_>>();
    
    for (_, server) in selected_servers.iter().enumerate() {
        let _guesses_str = if server.remaining_guesses.unwrap_or(-1) == -1 {
            "unknown".to_string()
        } else {
            server.remaining_guesses.unwrap_or(0).to_string()
        };
    }
    
    selected_servers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity() {
        let identity = Identity::new(
            "user123".to_string(),
            "device456".to_string(), 
            "backup789".to_string()
        );
        
        assert_eq!(identity.uid, "user123");
        assert_eq!(identity.did, "device456");
        assert_eq!(identity.bid, "backup789");
        
        let display = format!("{}", identity);
        assert!(display.contains("user123"));
        assert!(display.contains("device456"));
        assert!(display.contains("backup789"));
    }

    #[test]
    fn test_generate_auth_codes() {
        let servers = vec![
            "https://server1.example.com".to_string(),
            "https://server2.example.com".to_string(),
        ];
        
        let auth_codes = generate_auth_codes(&servers);
        
        assert!(!auth_codes.base_auth_code.is_empty());
        assert_eq!(auth_codes.server_auth_codes.len(), 2);
        
        let code1 = auth_codes.get_server_code("https://server1.example.com");
        let code2 = auth_codes.get_server_code("https://server2.example.com");
        let code_unknown = auth_codes.get_server_code("https://unknown.example.com");
        
        assert!(code1.is_some());
        assert!(code2.is_some());
        assert_eq!(code_unknown, Some(&auth_codes.base_auth_code));
        assert_ne!(code1, code2); // Different servers should have different codes
    }

    #[test]
    fn test_auth_codes_structure() {
        let servers = vec!["https://test.com".to_string()];
        let auth_codes = generate_auth_codes(&servers);
        
        // Base auth code should be 64 hex characters (32 bytes)
        assert_eq!(auth_codes.base_auth_code.len(), 64);
        assert!(auth_codes.base_auth_code.chars().all(|c| c.is_ascii_hexdigit()));
        
        // Server auth codes should also be 64 hex characters
        for (_, code) in &auth_codes.server_auth_codes {
            assert_eq!(code.len(), 64);
            assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_result_structures() {
        // Test success result
        let key = vec![1, 2, 3, 4];
        let servers = vec![];
        let auth_codes = AuthCodes {
            base_auth_code: "test".to_string(),
            server_auth_codes: HashMap::new(),
        };
        
        let success = GenerateEncryptionKeyResult::success(key.clone(), servers, 2, auth_codes);
        assert!(success.encryption_key.is_some());
        assert!(success.error.is_none());
        assert_eq!(success.encryption_key.unwrap(), key);
        
        // Test error result
        let error = GenerateEncryptionKeyResult::error("test error".to_string());
        assert!(error.encryption_key.is_none());
        assert!(error.error.is_some());
        assert_eq!(error.error.unwrap(), "test error");
    }

    #[test]
    fn test_identity_validation() {
        // Test normal identity
        let identity = Identity::new("user".to_string(), "device".to_string(), "backup".to_string());
        assert_eq!(identity.uid, "user");
        
        // Test with special characters
        let special_identity = Identity::new(
            "user@domain.com".to_string(),
            "device-123".to_string(),
            "file://path/to/backup".to_string()
        );
        assert!(special_identity.uid.contains("@"));
        assert!(special_identity.did.contains("-"));
        assert!(special_identity.bid.contains("://"));
        
        // Test display format
        let display = format!("{}", special_identity);
        assert!(display.contains("UID="));
        assert!(display.contains("DID="));
        assert!(display.contains("BID="));
    }

    #[test]
    fn test_auth_codes_comprehensive() {
        let servers = vec![
            "https://server1.com".to_string(),
            "https://server2.com".to_string(),
            "https://server3.com".to_string(),
        ];
        
        let auth_codes1 = generate_auth_codes(&servers);
        let auth_codes2 = generate_auth_codes(&servers);
        
        // Different generations should produce different codes
        assert_ne!(auth_codes1.base_auth_code, auth_codes2.base_auth_code);
        
        // But structure should be consistent
        assert_eq!(auth_codes1.server_auth_codes.len(), auth_codes2.server_auth_codes.len());
        
        // Test retrieval
        for server in &servers {
            let code1 = auth_codes1.get_server_code(server);
            let code2 = auth_codes1.get_server_code(server);
            assert_eq!(code1, code2); // Same auth_codes should return same code
            assert!(code1.is_some());
        }
        
        // Test fallback to base code
        let unknown_code = auth_codes1.get_server_code("https://unknown.com");
        assert_eq!(unknown_code, Some(&auth_codes1.base_auth_code));
    }

    #[test]
    fn test_encryption_key_derivation() {
        // This is more of an integration test, but we can test the basic flow
        let identity = Identity::new(
            "test-user".to_string(),
            "test-device".to_string(),
            "test-backup".to_string()
        );
        
        let password = "test-password";
        let pin = password.as_bytes().to_vec();
        
        // Test that H function works with our identity
        let result = H(
            identity.uid.as_bytes(),
            identity.did.as_bytes(), 
            identity.bid.as_bytes(),
            &pin
        );
        
        assert!(result.is_ok(), "H function should succeed with valid inputs");
        
        let point = result.unwrap();
        
        // Test that we can derive a key from the point
        let key_result = derive_enc_key(&point);
        assert!(key_result.is_ok(), "Key derivation should succeed");
        
        let key = key_result.unwrap();
        assert_eq!(key.len(), 32, "Encryption key should be 32 bytes");
        
        // Same inputs should produce same key
        let point2 = H(
            identity.uid.as_bytes(),
            identity.did.as_bytes(),
            identity.bid.as_bytes(), 
            &pin
        ).unwrap();
        let key2 = derive_enc_key(&point2).unwrap();
        assert_eq!(key, key2, "Same inputs should produce same key");
    }

    #[test]
    fn test_input_validation_edge_cases() {
        // Test empty identity components
        let empty_identity = Identity::new("".to_string(), "".to_string(), "".to_string());
        assert_eq!(empty_identity.uid, "");
        
        // Test very long identity components
        let long_string = "x".repeat(1000);
        let long_identity = Identity::new(long_string.clone(), long_string.clone(), long_string.clone());
        assert_eq!(long_identity.uid.len(), 1000);
        
        // Test identity display with empty components
        let display = format!("{}", empty_identity);
        assert!(display.contains("UID="));
        assert!(display.contains("DID="));
        assert!(display.contains("BID="));
    }
} 
