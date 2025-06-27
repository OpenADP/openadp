//! # OpenADP Rust SDK
//!
//! This crate provides a complete Rust implementation of the OpenADP (Open Advanced Data Protection)
//! distributed secret sharing system, designed to protect against nation-state attacks.
//!
//! ## Core Features
//!
//! - **Ed25519 elliptic curve operations** with point compression/decompression
//! - **Shamir secret sharing** with threshold recovery
//! - **Noise-NK protocol** for secure server communication
//! - **JSON-RPC 2.0 API** with multi-server support
//! - **Cross-language compatibility** with Go and Python implementations
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use openadp_ocrypt::{generate_encryption_key, recover_encryption_key, get_servers, Identity};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Get live servers
//!     let servers = get_servers("").await?;
//!     
//!     // Create Identity for the encryption operation
//!     let identity = Identity::new(
//!         "user@example.com".to_string(),  // UID - user identifier
//!         "laptop-2024".to_string(),       // DID - device identifier  
//!         "document.pdf".to_string()       // BID - backup identifier
//!     );
//!     
//!     // Generate encryption key with distributed backup
//!     let result = generate_encryption_key(
//!         &identity,
//!         "secure_password",
//!         10, // max_guesses
//!         0,  // expiration
//!         servers,
//!     ).await?;
//!     
//!     if let Some(key) = result.encryption_key {
//!         println!("Generated key: {} bytes", key.len());
//!         
//!         // Later: recover the key
//!         let recovered = recover_encryption_key(
//!             &identity,
//!             "secure_password", 
//!             result.server_infos.unwrap(),
//!             result.threshold.unwrap(),
//!             result.auth_codes.unwrap(),
//!         ).await?;
//!         
//!         if let Some(recovered_key) = recovered.encryption_key {
//!             assert_eq!(key, recovered_key);
//!             println!("Successfully recovered key!");
//!         }
//!     }
//!     
//!     Ok(())
//! }
//! ```

use std::path::Path;

/// Derive identifiers from filename, user_id, and hostname
/// This matches the Go DeriveIdentifiers function behavior
pub fn derive_identifiers(filename: &str, user_id: &str, hostname: &str) -> (String, String, String) {
    let hostname = if hostname.is_empty() {
        gethostname::gethostname().to_string_lossy().to_string()
    } else {
        hostname.to_string()
    };
    
    let bid = format!("file://{}", Path::new(filename).file_name().unwrap_or_default().to_string_lossy());
    
    (user_id.to_string(), hostname, bid)
}

pub mod crypto;
pub mod client;
pub mod keygen;
pub mod ocrypt;
pub mod recovery;

// Re-export main functionality
pub use crypto::*;
pub use client::*;
pub use keygen::*;
pub use ocrypt::*;
pub use recovery::*;

// Error types
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OpenADPError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Server error: {0}")]
    Server(String),
    
    #[error("Authentication failed: {0}")]
    Authentication(String),
    
    #[error("No servers available")]
    NoServers,
    
    #[error("Insufficient servers for threshold")]
    InsufficientServers,
    
    #[error("Invalid response from server")]
    InvalidResponse,
    
    #[error("Encryption/decryption failed")]
    EncryptionFailed,
    
    #[error("Point operation failed: {0}")]
    PointOperation(String),
    
    #[error("Secret sharing failed: {0}")]
    SecretSharing(String),
    
    #[error("I/O error: {0}")]
    Io(String),
    
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

pub type Result<T> = std::result::Result<T, OpenADPError>;

// Constants
pub const DEFAULT_REGISTRY_URL: &str = "https://servers.openadp.org/api/servers.json";
pub const FIELD_PRIME: &str = "57896044618658097711785492504343953926634992332820282019728792003956564819949"; // 2^255 - 19
pub const CURVE_ORDER: &str = "7237005577332262213973186563042994240857116359379907606001950938285454250989"; // 2^252 + 27742317777372353535851937790883648493

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Basic sanity checks
        assert!(FIELD_PRIME.len() > 50);
        assert!(CURVE_ORDER.len() > 50);
    }
    
    #[test]
    fn test_error_types() {
        let err = OpenADPError::InvalidInput("test".to_string());
        assert!(err.to_string().contains("Invalid input"));
    }
}
