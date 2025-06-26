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
    derive_enc_key, recover_point_secret, PointShare, expand, mod_inverse
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
    println!("OpenADP: Identity={}", identity);
    
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
                Err(e) => {
                    println!("Warning: Invalid public key for server {}: {}", server_info.url, e);
                    None
                }
            }
        } else {
            None
        };
        
        let mut client = EncryptedOpenADPClient::new(server_info.url.clone(), public_key, 30);
        
        // Test server connectivity
        match client.test_connection().await {
            Ok(_) => {
                println!("✅ Server {} is reachable", server_info.url);
                clients.push(client);
                live_server_infos.push(server_info);
            }
            Err(e) => {
                println!("❌ Server {} is not reachable: {}", server_info.url, e);
            }
        }
    }
    
    if live_server_infos.len() < 2 {
        return Ok(GenerateEncryptionKeyResult::error("Need at least 2 live servers".to_string()));
    }
    
    // Step 3: Convert password to PIN
    let pin = password.as_bytes().to_vec();
    println!("🔍 DEBUG: password={}, pin={}", password, hex::encode(&pin));
    
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
    let u_2d = unexpand(&u)?;
    println!("🔍 DEBUG: U point: x={}, y={}", hex::encode(&u_2d.x.to_bytes_le()), hex::encode(&u_2d.y.to_bytes_le()));
    
    // Step 7: Register shares with servers
    println!("🔑 Registering shares with {} servers...", clients.len());
    
    let mut registration_errors = Vec::new();
    let mut successful_registrations = 0;
    
    for (i, mut client) in clients.into_iter().enumerate() {
        let (share_id, share_data) = &shares[i];
        let server_url = &live_server_infos[i].url;
        let server_auth_code = auth_codes.get_server_code(server_url)
            .ok_or_else(|| OpenADPError::Authentication("Missing server auth code".to_string()))?;
        
        // Convert share Y to string (server expects integer, not base64) - matching Go implementation
        let y_string = share_data.to_string();
        
        let request = RegisterSecretRequest {
            auth_code: server_auth_code.clone(),
            uid: identity.uid.clone(),
            did: identity.did.clone(),
            bid: identity.bid.clone(),
            version: 1,
            x: *share_id as i32,
            y: y_string,
            max_guesses,
            expiration,
            encrypted: client.has_public_key(),
            auth_data: None,
        };
        
        match client.register_secret_standardized(request).await {
            Ok(response) => {
                if response.success {
                    let enc_status = if client.has_public_key() { "encrypted" } else { "unencrypted" };
                    println!("OpenADP: Registered share {} with server {} ({}) [{}]", 
                        share_id, i + 1, server_url, enc_status);
                    successful_registrations += 1;
                } else {
                    let error_msg = format!("Server {} ({}): Registration returned false: {}", 
                        i + 1, server_url, response.message);
                    registration_errors.push(error_msg);
                    println!("❌ Failed to register share {} with server {}: {}", 
                        share_id, server_url, response.message);
                }
            }
            Err(e) => {
                let error_msg = format!("Server {} ({}): {}", i + 1, server_url, e);
                registration_errors.push(error_msg);
                println!("❌ Error registering share {} with server {}: {}", 
                    share_id, server_url, e);
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
    
    println!("OpenADP: Successfully generated encryption key");
    
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
    println!("OpenADP: Identity={}", identity);
    
    // Step 1: Compute U = H(uid, did, bid, pin) - same as in generation
    let pin = password.as_bytes().to_vec();
    let u = H(identity.uid.as_bytes(), identity.did.as_bytes(), identity.bid.as_bytes(), &pin)?;
    let u_2d = unexpand(&u)?;
    println!("🔍 DEBUG: U point: x={}, y={}", hex::encode(&u_2d.x.to_bytes_le()), hex::encode(&u_2d.y.to_bytes_le()));
    
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
    
    println!("🔍 DEBUG: r scalar: {}", hex::encode(&r_scalar.to_bytes_le()));
    
    // Step 2: Fetch remaining guesses and select best servers
    println!("OpenADP: Fetching remaining guesses from servers...");
    let updated_server_infos = fetch_remaining_guesses_for_servers(identity, &server_infos).await;
    let selected_server_infos = select_servers_by_remaining_guesses(&updated_server_infos, threshold);
    
    if selected_server_infos.is_empty() {
        return Ok(RecoverEncryptionKeyResult::error("No servers available".to_string()));
    }
    
    // Step 3: Compute B = r * U  
    let b = point_mul(&r_scalar, &u);
    let b_2d = unexpand(&b)?;
    println!("🔍 DEBUG: B point (r * U): x={}, y={}", hex::encode(&b_2d.x.to_bytes_le()), hex::encode(&b_2d.y.to_bytes_le()));
    
    // Compress B for transmission
    let b_compressed = point_compress(&b)?;
    let b_base64 = BASE64.encode(&b_compressed);
    println!("🔍 DEBUG: B compressed: {}", hex::encode(&b_compressed));
    println!("🔍 DEBUG: B base64: {}", b_base64);

    // Step 4: Recover shares from servers
    let mut recovered_point_shares = Vec::new();
    
    for server_info in &selected_server_infos {
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
        
        let mut client = EncryptedOpenADPClient::new(server_info.url.clone(), public_key, 30);
        
        // Get server auth code
        let server_auth_code = auth_codes.get_server_code(&server_info.url)
            .ok_or_else(|| OpenADPError::Authentication("No auth code for server".to_string()))?;
        
        // Get current guess number for idempotency (prevents replay attacks)
        let mut guess_num = 0; // Default fallback
        let list_request = ListBackupsRequest {
            uid: identity.uid.clone(),
            auth_code: String::new(),
            encrypted: false,
            auth_data: None,
        };
        
        match client.list_backups_standardized(list_request).await {
            Ok(response) => {
                // Find our backup in the list using the complete primary key (UID, DID, BID)
                for backup in &response.backups {
                    if backup.uid == identity.uid && 
                       backup.did == identity.did &&
                       backup.bid == identity.bid {
                        guess_num = backup.num_guesses;
                        println!("🔍 DEBUG: Found backup, current num_guesses: {}", guess_num);
                        break;
                    }
                }
            }
            Err(e) => {
                println!("Warning: Could not list backups from server {}: {}", server_info.url, e);
                return Err(OpenADPError::Server(format!("Cannot get current guess number for idempotency: {}", e)));
            }
        }
        
        println!("🔍 DEBUG: Sending guess_num = {} to server {}", guess_num, server_info.url);
        
        let request = RecoverSecretRequest {
            auth_code: server_auth_code.clone(),
            uid: identity.uid.clone(),
            did: identity.did.clone(),
            bid: identity.bid.clone(),
            guess_num: guess_num,  // Use current num_guesses directly
            b: b_base64.clone(),
            encrypted: client.has_public_key(),
            auth_data: None,
        };
        
        match client.recover_secret_standardized(request).await {
            Ok(response) => {
                if response.success {
                    println!("✅ Recovered share from server {}", server_info.url);
                    
                    // Parse the returned share
                    if let Some(si_b) = response.si_b {
                        println!("🔍 DEBUG: Server {} returned si_b: {}", server_info.url, si_b);
                        
                        // Decode base64 to get compressed point
                        match BASE64.decode(&si_b) {
                            Ok(si_b_bytes) => {
                                println!("🔍 DEBUG: si_b_bytes length: {}, data: {}", si_b_bytes.len(), hex::encode(&si_b_bytes));
                                
                                // Decompress the point
                                match point_decompress(&si_b_bytes) {
                                    Ok(si_b_point) => {
                                        let si_b_2d = unexpand(&si_b_point)?;
                                        println!("🔍 DEBUG: si_b point: x={}, y={}", 
                                            hex::encode(&si_b_2d.x.to_bytes_le()), 
                                            hex::encode(&si_b_2d.y.to_bytes_le()));
                                        
                                        // Add to point shares for Lagrange interpolation
                                        recovered_point_shares.push(PointShare::new(response.x as usize, si_b_point));
                                    }
                                    Err(e) => {
                                        println!("❌ Failed to decompress point from server {}: {}", server_info.url, e);
                                        return Err(e);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("❌ Failed to decode base64 from server {}: {}", server_info.url, e);
                                return Err(OpenADPError::Crypto(format!("Base64 decode error: {}", e)));
                            }
                        }
                    } else {
                        println!("❌ Server {} returned success but no si_b", server_info.url);
                        return Err(OpenADPError::Server("Server returned success but no si_b".to_string()));
                    }
                } else {
                    println!("❌ Server {} returned error: {}", server_info.url, response.message);
                    return Err(OpenADPError::Server(format!("Server error: {}", response.message)));
                }
            }
            Err(e) => {
                println!("❌ Error recovering from server {}: {}", server_info.url, e);
                return Err(e);
            }
        }
    }
    
    // Step 5: Check if we have enough shares
    if recovered_point_shares.len() < threshold {
        return Err(OpenADPError::SecretSharing(format!(
            "Not enough shares recovered: got {}, need {}", 
            recovered_point_shares.len(), threshold
        )));
    }
    
    println!("🔍 DEBUG: Reconstructing secret from {} point shares", recovered_point_shares.len());
    
    // Step 6: Reconstruct the secret point using Lagrange interpolation
    let recovered_sb_4d = recover_point_secret(recovered_point_shares)?;
    let recovered_sb_2d = unexpand(&recovered_sb_4d)?;
    println!("🔍 DEBUG: Recovered s*b point: x={}, y={}", 
        hex::encode(&recovered_sb_2d.x.to_bytes_le()), 
        hex::encode(&recovered_sb_2d.y.to_bytes_le()));
    
    // Step 7: Compute original secret point: s*U = (s*b) / r = (s*b) * r^(-1)
    let q = crate::crypto::Q.clone();
    let r_inv = mod_inverse(&r_scalar, &q);
    
    // Apply r^-1 to unblind: s*U = r^-1 * (s*B)
    let original_su = point_mul(&r_inv, &recovered_sb_4d);
    
    let original_su_2d = unexpand(&original_su)?;
    println!("🔍 DEBUG: Original s*U point: x={}", 
        hex::encode(&original_su_2d.x.to_bytes_le()));
    
    // Step 8: Derive encryption key from the recovered secret point
    let encryption_key = derive_enc_key(&original_su)?;
    
    println!("✅ Successfully recovered encryption key: {}", hex::encode(&encryption_key));
    
    Ok(RecoverEncryptionKeyResult::success(encryption_key))
}

/// Fetch remaining guesses for all servers
pub async fn fetch_remaining_guesses_for_servers(
    identity: &Identity,
    server_infos: &[ServerInfo],
) -> Vec<ServerInfo> {
    let mut updated_infos = Vec::new();
    
    for server_info in server_infos {
        let mut updated_info = server_info.clone();
        
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
        
        let mut client = EncryptedOpenADPClient::new(server_info.url.clone(), public_key, 30);
        
        let request = ListBackupsRequest {
            uid: identity.uid.clone(),
            auth_code: String::new(),
            encrypted: false,
            auth_data: None,
        };
        
        match client.list_backups_standardized(request).await {
            Ok(response) => {
                // Find our backup in the list
                for backup in &response.backups {
                    if backup.uid == identity.uid && 
                       backup.did == identity.did &&
                       backup.bid == identity.bid {
                        updated_info.remaining_guesses = Some(backup.max_guesses - backup.num_guesses);
                        println!("📊 Server {}: {} remaining guesses", 
                            server_info.url, updated_info.remaining_guesses.unwrap_or(0));
                        break;
                    }
                }
                
                if updated_info.remaining_guesses.is_none() {
                    println!("⚠️  Server {}: No backup found for identity", server_info.url);
                    updated_info.remaining_guesses = Some(0);
                }
            }
            Err(e) => {
                println!("❌ Failed to fetch guesses from server {}: {}", server_info.url, e);
                updated_info.remaining_guesses = Some(0);
            }
        }
        
        updated_infos.push(updated_info);
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
        println!("Warning: All servers have exhausted their guesses!");
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
    
    println!("🎯 Selected {} servers for recovery:", selected_servers.len());
    for (i, server) in selected_servers.iter().enumerate() {
        let guesses_str = if server.remaining_guesses.unwrap_or(-1) == -1 {
            "unknown".to_string()
        } else {
            server.remaining_guesses.unwrap_or(0).to_string()
        };
        println!("   {}. {} ({} remaining guesses)", i + 1, server.url, guesses_str);
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
