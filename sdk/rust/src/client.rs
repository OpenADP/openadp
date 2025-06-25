//! OpenADP Rust Client Implementation
//!
//! This module provides Rust client implementations for OpenADP servers,
//! matching the Go and Python client functionality exactly:
//!
//! - OpenADPClient: Basic JSON-RPC client (no encryption)
//! - EncryptedOpenADPClient: JSON-RPC client with Noise-NK encryption
//! - MultiServerClient: High-level client managing multiple servers
//!
//! All clients implement standardized interfaces for cross-language compatibility.

use crate::{OpenADPError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tokio::time::timeout;
use futures::future::join_all;
use rand::rngs::OsRng;
use rand::RngCore;
use snow::{Builder, HandshakeState, TransportState, Keypair as SnowKeypair};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::X25519_BASEPOINT;

// Error codes matching Go implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    NetworkFailure = 1001,
    AuthenticationFailed = 1002,
    InvalidRequest = 1003,
    ServerError = 1004,
    EncryptionFailed = 1005,
    NoLiveServers = 1006,
    InvalidResponse = 1007,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSelectionStrategy {
    FirstAvailable = 0,
    RoundRobin = 1,
    Random = 2,
    LowestLatency = 3,
}

/// Server information from registry or configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub url: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub country: String,
    #[serde(default = "default_remaining_guesses")]
    pub remaining_guesses: i32, // -1 means unknown, >=0 means known remaining guesses
}

fn default_remaining_guesses() -> i32 {
    -1
}

impl ServerInfo {
    pub fn new(url: String) -> Self {
        Self {
            url,
            public_key: String::new(),
            country: String::new(),
            remaining_guesses: -1,
        }
    }
    
    pub fn with_public_key(mut self, public_key: String) -> Self {
        self.public_key = public_key;
        self
    }
    
    pub fn with_country(mut self, country: String) -> Self {
        self.country = country;
        self
    }
    
    pub fn with_remaining_guesses(mut self, remaining_guesses: i32) -> Self {
        self.remaining_guesses = remaining_guesses;
        self
    }
}

/// Standardized request for RegisterSecret operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSecretRequest {
    pub auth_code: String,
    pub uid: String,
    pub did: String,
    pub bid: String,
    pub version: i32,
    pub x: i32,
    pub y: String, // Base64 encoded point
    pub max_guesses: i32,
    pub expiration: i64,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub auth_data: Option<HashMap<String, Value>>,
}

/// Standardized response for RegisterSecret operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSecretResponse {
    pub success: bool,
    #[serde(default)]
    pub message: String,
}

/// Standardized request for RecoverSecret operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverSecretRequest {
    pub auth_code: String,
    pub uid: String,
    pub did: String,
    pub bid: String,
    pub b: String, // Base64 encoded point
    pub guess_num: i32,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub auth_data: Option<HashMap<String, Value>>,
}

/// Standardized response for RecoverSecret operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverSecretResponse {
    pub version: i32,
    pub x: i32,
    pub si_b: String, // Base64 encoded point
    pub num_guesses: i32,
    pub max_guesses: i32,
    pub expiration: i64,
}

/// Standardized request for ListBackups operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListBackupsRequest {
    pub uid: String,
    #[serde(default)]
    pub auth_code: String,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub auth_data: Option<HashMap<String, Value>>,
}

/// Information about a backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub uid: String,
    pub bid: String,
    pub version: i32,
    pub num_guesses: i32,
    pub max_guesses: i32,
    pub expiration: i64,
}

/// Standardized response for ListBackups operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListBackupsResponse {
    pub backups: Vec<BackupInfo>,
}

/// Standardized response for GetServerInfo operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfoResponse {
    pub server_version: String,
    #[serde(default)]
    pub noise_nk_public_key: String,
    #[serde(default)]
    pub supported_methods: Vec<String>,
    #[serde(default)]
    pub max_request_size: i64,
    #[serde(default)]
    pub rate_limits: HashMap<String, Value>,
}

/// JSON-RPC 2.0 error structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default)]
    pub data: Option<Value>,
}

/// JSON-RPC 2.0 request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    pub id: i32,
}

impl JsonRpcRequest {
    pub fn new(method: String, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method,
            params,
            id: 1,
        }
    }
    
    pub fn to_dict(&self) -> HashMap<String, Value> {
        let mut dict = HashMap::new();
        dict.insert("jsonrpc".to_string(), Value::String(self.jsonrpc.clone()));
        dict.insert("method".to_string(), Value::String(self.method.clone()));
        dict.insert("id".to_string(), Value::Number(serde_json::Number::from(self.id)));
        
        if let Some(params) = &self.params {
            dict.insert("params".to_string(), params.clone());
        }
        
        dict
    }
}

/// JSON-RPC 2.0 response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Option<i32>,
}

/// Basic OpenADP client with JSON-RPC communication (no encryption)
pub struct OpenADPClient {
    url: String,
    client: Client,
    timeout: Duration,
}

impl OpenADPClient {
    pub fn new(url: String, timeout_secs: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .expect("Failed to create HTTP client");
            
        Self {
            url,
            client,
            timeout: Duration::from_secs(timeout_secs),
        }
    }
    
    /// Make a JSON-RPC request to the server
    async fn make_request(&self, method: &str, params: Option<Value>) -> Result<Value> {
        let request = JsonRpcRequest::new(method.to_string(), params);
        let json_body = serde_json::to_string(&request)?;
        
        let response = timeout(self.timeout, 
            self.client
                .post(&self.url)
                .header("Content-Type", "application/json")
                .body(json_body)
                .send()
        ).await
        .map_err(|_| OpenADPError::Server("Request timed out".to_string()))?
        .map_err(OpenADPError::Network)?;
        
        if !response.status().is_success() {
            return Err(OpenADPError::Server(format!("HTTP {}", response.status())));
        }
        
        let response_text = response.text().await.map_err(OpenADPError::Network)?;
        let rpc_response: JsonRpcResponse = serde_json::from_str(&response_text)?;
        
        if let Some(error) = rpc_response.error {
            return Err(OpenADPError::Server(format!("RPC Error {}: {}", error.code, error.message)));
        }
        
        rpc_response.result.ok_or_else(|| OpenADPError::InvalidResponse)
    }
    
    /// Test server connection with echo
    pub async fn echo(&self, message: &str) -> Result<String> {
        let params = json!([message]);
        let result = self.make_request("Echo", Some(params)).await?;
        
        result.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| OpenADPError::InvalidResponse)
    }
    
    /// Ping server for basic connectivity test (alias for echo with 'ping' message)
    pub async fn ping(&self) -> Result<()> {
        self.echo("ping").await?;
        Ok(())
    }
    
    /// Get server information
    pub async fn get_server_info(&self) -> Result<ServerInfoResponse> {
        let result = self.make_request("GetServerInfo", None).await?;
        serde_json::from_value(result).map_err(|e| OpenADPError::Json(e))
    }
    
    /// Register a secret with the server
    pub async fn register_secret_standardized(&self, request: RegisterSecretRequest) -> Result<RegisterSecretResponse> {
        // Python sends parameters as array: [auth_code, uid, did, bid, version, x, y, max_guesses, expiration]
        let params = json!([
            request.auth_code,
            request.uid,
            request.did,
            request.bid,
            request.version,
            request.x,
            request.y,
            request.max_guesses,
            request.expiration
        ]);
        let result = self.make_request("RegisterSecret", Some(params)).await?;
        
        // Server returns a boolean for RegisterSecret
        if let Some(success) = result.as_bool() {
            Ok(RegisterSecretResponse {
                success,
                message: String::new(),
            })
        } else {
            Err(OpenADPError::InvalidResponse)
        }
    }
    
    /// Recover a secret from the server
    pub async fn recover_secret_standardized(&self, request: RecoverSecretRequest) -> Result<RecoverSecretResponse> {
        // Python sends parameters as array: [auth_code, uid, did, bid, b, guess_num]
        let params = json!([
            request.auth_code,
            request.uid,
            request.did,
            request.bid,
            request.b,
            request.guess_num
        ]);
        let result = self.make_request("RecoverSecret", Some(params)).await?;
        
        // Server returns a dictionary for RecoverSecret
        serde_json::from_value(result).map_err(|e| OpenADPError::Json(e))
    }
    
    /// List backups for a user
    pub async fn list_backups_standardized(&self, request: ListBackupsRequest) -> Result<ListBackupsResponse> {
        let params = serde_json::to_value(request)?;
        let result = self.make_request("ListBackups", Some(params)).await?;
        serde_json::from_value(result).map_err(|e| OpenADPError::Json(e))
    }
    
    /// Test connection
    pub async fn test_connection(&self) -> Result<()> {
        self.ping().await
    }
    
    /// Get server URL
    pub fn get_server_url(&self) -> &str {
        &self.url
    }
    
    /// Check if client supports encryption (basic client doesn't)
    pub fn supports_encryption(&self) -> bool {
        false
    }
}

/// Noise-NK protocol implementation using Snow
pub struct NoiseNK {
    handshake_state: Option<HandshakeState>,
    transport_state: Option<TransportState>,
    pub handshake_complete: bool,
    is_initiator: bool,
    handshake_hash: Option<Vec<u8>>, // Store handshake hash before transport mode
}

impl NoiseNK {
    pub fn new() -> Self {
        Self {
            handshake_state: None,
            transport_state: None,
            handshake_complete: false,
            is_initiator: false,
            handshake_hash: None,
        }
    }
    
    /// Initialize as initiator (client) with remote static key
    pub fn initialize_as_initiator(&mut self, remote_static_key: Vec<u8>) -> Result<()> {
        let params = "Noise_NK_25519_AESGCM_SHA256".parse()
            .map_err(|e| OpenADPError::Crypto(format!("Invalid Noise params: {}", e)))?;
        
        let builder = Builder::new(params)
            .remote_public_key(&remote_static_key);
        
        let handshake_state = builder.build_initiator()
            .map_err(|e| OpenADPError::Crypto(format!("Failed to build initiator: {}", e)))?;
        
        self.handshake_state = Some(handshake_state);
        self.is_initiator = true;
        self.handshake_complete = false;
        
        Ok(())
    }
    
    /// Initialize as responder (server) with local static key
    pub fn initialize_as_responder(&mut self, local_static_key: Vec<u8>) -> Result<()> {
        let params = "Noise_NK_25519_AESGCM_SHA256".parse()
            .map_err(|e| OpenADPError::Crypto(format!("Invalid Noise params: {}", e)))?;
        
        let keypair = SnowKeypair {
            private: local_static_key,
            public: vec![0u8; 32], // Will be computed by Snow
        };
        
        let builder = Builder::new(params)
            .local_private_key(&keypair.private);
        
        let handshake_state = builder.build_responder()
            .map_err(|e| OpenADPError::Crypto(format!("Failed to build responder: {}", e)))?;
        
        self.handshake_state = Some(handshake_state);
        self.is_initiator = false;
        self.handshake_complete = false;
        
        Ok(())
    }
    
    /// Write a handshake message
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if let Some(mut handshake_state) = self.handshake_state.take() {
            let mut buf = vec![0u8; 1024]; // Buffer for handshake message
            
            let len = handshake_state.write_message(payload, &mut buf)
                .map_err(|e| OpenADPError::Crypto(format!("Failed to write handshake message: {}", e)))?;
            
            buf.truncate(len);
            
            // Check if handshake is complete
            if handshake_state.is_handshake_finished() {
                // Store handshake hash before entering transport mode
                self.handshake_hash = Some(handshake_state.get_handshake_hash().to_vec());
                
                let transport_state = handshake_state.into_transport_mode()
                    .map_err(|e| OpenADPError::Crypto(format!("Failed to enter transport mode: {}", e)))?;
                
                self.transport_state = Some(transport_state);
                self.handshake_complete = true;
            } else {
                // Put handshake state back
                self.handshake_state = Some(handshake_state);
            }
            
            Ok(buf)
        } else {
            Err(OpenADPError::Crypto("NoiseNK not initialized".to_string()))
        }
    }
    
    /// Read a handshake message
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if let Some(mut handshake_state) = self.handshake_state.take() {
            let mut buf = vec![0u8; 1024]; // Buffer for payload
            
            let len = handshake_state.read_message(message, &mut buf)
                .map_err(|e| OpenADPError::Crypto(format!("Failed to read handshake message: {}", e)))?;
            
            buf.truncate(len);
            
            // Check if handshake is complete
            if handshake_state.is_handshake_finished() {
                // Store handshake hash before entering transport mode
                self.handshake_hash = Some(handshake_state.get_handshake_hash().to_vec());
                
                let transport_state = handshake_state.into_transport_mode()
                    .map_err(|e| OpenADPError::Crypto(format!("Failed to enter transport mode: {}", e)))?;
                
                self.transport_state = Some(transport_state);
                self.handshake_complete = true;
            } else {
                // Put handshake state back
                self.handshake_state = Some(handshake_state);
            }
            
            Ok(buf)
        } else {
            Err(OpenADPError::Crypto("NoiseNK not initialized".to_string()))
        }
    }
    
    /// Encrypt message after handshake completion
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.handshake_complete {
            return Err(OpenADPError::Crypto("Handshake not complete".to_string()));
        }
        
        if let Some(transport_state) = &mut self.transport_state {
            let mut buf = vec![0u8; plaintext.len() + 16]; // Extra space for AEAD tag
            
            let len = transport_state.write_message(plaintext, &mut buf)
                .map_err(|e| OpenADPError::Crypto(format!("Failed to encrypt: {}", e)))?;
            
            buf.truncate(len);
            Ok(buf)
        } else {
            Err(OpenADPError::Crypto("Transport state not available".to_string()))
        }
    }
    
    /// Decrypt message after handshake completion
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.handshake_complete {
            return Err(OpenADPError::Crypto("Handshake not complete".to_string()));
        }
        
        if let Some(transport_state) = &mut self.transport_state {
            let mut buf = vec![0u8; ciphertext.len()]; // Buffer for plaintext
            
            let len = transport_state.read_message(ciphertext, &mut buf)
                .map_err(|e| OpenADPError::Crypto(format!("Failed to decrypt: {}", e)))?;
            
            buf.truncate(len);
            Ok(buf)
        } else {
            Err(OpenADPError::Crypto("Transport state not available".to_string()))
        }
    }
    
    /// Get handshake hash (for debugging/verification)
    pub fn get_handshake_hash(&self) -> Result<Vec<u8>> {
        if let Some(handshake_state) = &self.handshake_state {
            Ok(handshake_state.get_handshake_hash().to_vec())
        } else if let Some(hash) = &self.handshake_hash {
            Ok(hash.clone())
        } else {
            Err(OpenADPError::Crypto("NoiseNK not initialized or handshake hash not available".to_string()))
        }
    }
}

/// Generate X25519 keypair for Noise-NK
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    // Generate a random 32-byte private key
    let mut private_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut private_key_bytes);
    
    // Create scalar from private key bytes
    let private_scalar = Scalar::from_bytes_mod_order(private_key_bytes);
    
    // Compute public key: public = private * basepoint
    let public_point = &private_scalar * &X25519_BASEPOINT;
    let public_key_bytes = public_point.to_bytes();
    
    Ok((private_key_bytes.to_vec(), public_key_bytes.to_vec()))
}

/// Parse server public key from base64
pub fn parse_server_public_key(key_b64: &str) -> Result<Vec<u8>> {
    let key_b64 = if key_b64.starts_with("ed25519:") {
        &key_b64[8..]
    } else {
        key_b64
    };
    
    BASE64.decode(key_b64)
        .map_err(|e| OpenADPError::Crypto(format!("Invalid base64 public key: {}", e)))
}

/// Encrypted OpenADP client with Noise-NK encryption
pub struct EncryptedOpenADPClient {
    basic_client: OpenADPClient,
    noise: Option<NoiseNK>,
    server_public_key: Option<Vec<u8>>,
}

impl EncryptedOpenADPClient {
    pub fn new(url: String, server_public_key: Option<Vec<u8>>, timeout_secs: u64) -> Self {
        let basic_client = OpenADPClient::new(url, timeout_secs);
        
        Self {
            basic_client,
            noise: None,
            server_public_key,
        }
    }
    
    /// Check if client has public key for encryption
    pub fn has_public_key(&self) -> bool {
        self.server_public_key.is_some()
    }
    
    /// Initialize Noise-NK encryption
    async fn initialize_encryption(&mut self) -> Result<()> {
        if let Some(public_key) = &self.server_public_key {
            let mut noise = NoiseNK::new();
            noise.initialize_as_initiator(public_key.clone())?;
            self.noise = Some(noise);
        }
        Ok(())
    }
    
    /// Make encrypted request using proper Noise-NK protocol
    async fn make_encrypted_request(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
        if self.noise.is_none() {
            self.initialize_encryption().await?;
        }
        
        if let Some(noise) = &mut self.noise {
            // Step 1: Perform Noise-NK handshake
            if !noise.handshake_complete {
                // Send first handshake message (-> e, es)
                let message1 = noise.write_message(b"")?;
                let message1_b64 = BASE64.encode(&message1);
                
                // Send handshake request
                let handshake_request = json!({
                    "jsonrpc": "2.0",
                    "method": "noise_handshake",
                    "params": [{
                        "message": message1_b64
                    }],
                    "id": 1
                });
                
                let handshake_response = timeout(self.basic_client.timeout,
                    self.basic_client.client
                        .post(&self.basic_client.url)
                        .header("Content-Type", "application/json")
                        .json(&handshake_request)
                        .send()
                ).await
                .map_err(|_| OpenADPError::Server("Handshake request timed out".to_string()))?
                .map_err(OpenADPError::Network)?;
                
                if !handshake_response.status().is_success() {
                    return Err(OpenADPError::Server(format!("Handshake HTTP {}", handshake_response.status())));
                }
                
                let handshake_response_text = handshake_response.text().await.map_err(OpenADPError::Network)?;
                let handshake_rpc_response: JsonRpcResponse = serde_json::from_str(&handshake_response_text)?;
                
                if let Some(error) = handshake_rpc_response.error {
                    return Err(OpenADPError::Server(format!("Handshake RPC Error {}: {}", error.code, error.message)));
                }
                
                let handshake_result = handshake_rpc_response.result.ok_or_else(|| OpenADPError::InvalidResponse)?;
                let message2_b64 = handshake_result.get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| OpenADPError::InvalidResponse)?;
                
                let message2 = BASE64.decode(message2_b64)
                    .map_err(|e| OpenADPError::Crypto(format!("Invalid base64 in handshake response: {}", e)))?;
                
                // Process second handshake message (<- e, ee)
                let _server_payload = noise.read_message(&message2)?;
                
                if !noise.handshake_complete {
                    return Err(OpenADPError::Server("Handshake not complete after message exchange".to_string()));
                }
                
                println!("✅ Noise-NK handshake completed successfully");
            }
            
            // Step 2: Send encrypted JSON-RPC request
            let request = JsonRpcRequest::new(method.to_string(), params);
            let request_json = serde_json::to_vec(&request.to_dict())?;
            
            let encrypted_request = noise.encrypt(&request_json)?;
            let encrypted_request_b64 = BASE64.encode(&encrypted_request);
            
            let encrypted_rpc_request = json!({
                "jsonrpc": "2.0",
                "method": "encrypted_call",
                "params": [{
                    "data": encrypted_request_b64
                }],
                "id": request.id
            });
            
            // Send encrypted request
            let response = timeout(self.basic_client.timeout,
                self.basic_client.client
                    .post(&self.basic_client.url)
                    .header("Content-Type", "application/json")
                    .json(&encrypted_rpc_request)
                    .send()
            ).await
            .map_err(|_| OpenADPError::Server("Encrypted request timed out".to_string()))?
            .map_err(OpenADPError::Network)?;
            
            if !response.status().is_success() {
                return Err(OpenADPError::Server(format!("Encrypted request HTTP {}", response.status())));
            }
            
            let response_text = response.text().await.map_err(OpenADPError::Network)?;
            let rpc_response: JsonRpcResponse = serde_json::from_str(&response_text)?;
            
            if let Some(error) = rpc_response.error {
                return Err(OpenADPError::Server(format!("RPC Error {}: {}", error.code, error.message)));
            }
            
            let encrypted_result = rpc_response.result.ok_or_else(|| OpenADPError::InvalidResponse)?;
            let encrypted_data_b64 = encrypted_result.get("data")
                .and_then(|v| v.as_str())
                .ok_or_else(|| OpenADPError::InvalidResponse)?;
            
            let encrypted_data = BASE64.decode(encrypted_data_b64)
                .map_err(|e| OpenADPError::Crypto(format!("Invalid base64 in encrypted response: {}", e)))?;
            
            // Decrypt response
            let decrypted_response = noise.decrypt(&encrypted_data)?;
            let response_json: Value = serde_json::from_slice(&decrypted_response)?;
            
            Ok(response_json)
        } else {
            Err(OpenADPError::Crypto("Noise not initialized".to_string()))
        }
    }
    
    /// Echo with optional encryption
    pub async fn echo(&mut self, message: &str, encrypted: bool) -> Result<String> {
        let params = json!([message]);
        
        let result = if encrypted && self.has_public_key() {
            self.make_encrypted_request("Echo", Some(params)).await?
        } else {
            self.basic_client.make_request("Echo", Some(params)).await?
        };
        
        result.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| OpenADPError::InvalidResponse)
    }
    
    /// Ping server (alias for echo with 'ping' message)
    pub async fn ping(&mut self) -> Result<()> {
        self.echo("ping", false).await?;
        Ok(())
    }
    
    /// Get server information
    pub async fn get_server_info(&self) -> Result<ServerInfoResponse> {
        self.basic_client.get_server_info().await
    }
    
    /// Register secret with optional encryption
    /// TODO: Implement proper Noise-NK encryption using the `snow` crate
    /// For now, this always uses unencrypted requests as the simplified Noise-NK implementation
    /// doesn't generate proper handshake messages that the servers expect
    pub async fn register_secret_standardized(&mut self, mut request: RegisterSecretRequest) -> Result<RegisterSecretResponse> {
        // TODO: Implement proper Noise-NK encryption
        // The current simplified implementation doesn't generate proper handshake messages
        // Need to use a proper Noise-NK library like `snow` crate to match Python's noiseprotocol
        request.encrypted = self.has_public_key();
        self.basic_client.register_secret_standardized(request).await
    }
    
    /// Recover secret with optional encryption
    pub async fn recover_secret_standardized(&mut self, mut request: RecoverSecretRequest) -> Result<RecoverSecretResponse> {
        request.encrypted = self.has_public_key();
        
        if request.encrypted && self.has_public_key() {
            // Use encrypted request
            let params = Some(json!({
                "auth_code": request.auth_code,
                "uid": request.uid,
                "did": request.did,
                "bid": request.bid,
                "b": request.b,
                "guess_num": request.guess_num,
                "encrypted": true,
                "auth_data": request.auth_data
            }));
            
            let result = self.make_encrypted_request("RecoverSecret", params).await?;
            
            Ok(RecoverSecretResponse {
                version: result.get("version").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                x: result.get("x").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                si_b: result.get("si_b").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                num_guesses: result.get("num_guesses").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                max_guesses: result.get("max_guesses").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                expiration: result.get("expiration").and_then(|v| v.as_i64()).unwrap_or(0),
            })
        } else {
            // Use unencrypted request
            self.basic_client.recover_secret_standardized(request).await
        }
    }
    
    /// List backups with optional encryption
    pub async fn list_backups_standardized(&mut self, mut request: ListBackupsRequest) -> Result<ListBackupsResponse> {
        request.encrypted = false; // List backups typically doesn't need encryption
        self.basic_client.list_backups_standardized(request).await
    }
    
    /// Test connection
    pub async fn test_connection(&self) -> Result<()> {
        self.basic_client.test_connection().await
    }
    
    /// Get server URL
    pub fn get_server_url(&self) -> &str {
        self.basic_client.get_server_url()
    }
    
    /// Check if client supports encryption
    pub fn supports_encryption(&self) -> bool {
        self.has_public_key()
    }
}

/// Server discovery functions

/// JSON response from server registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServersResponse {
    pub servers: Vec<ServerInfo>,
}

/// Get servers from registry
pub async fn get_servers(registry_url: &str) -> Result<Vec<ServerInfo>> {
    let url = if registry_url.is_empty() {
        crate::DEFAULT_REGISTRY_URL
    } else {
        registry_url
    };
    
    let client = Client::new();
    let response = client.get(url).send().await.map_err(OpenADPError::Network)?;
    
    if !response.status().is_success() {
        return Err(OpenADPError::Server(format!("HTTP {}", response.status())));
    }
    
    let servers_response: ServersResponse = response.json().await.map_err(OpenADPError::Network)?;
    
    if servers_response.servers.is_empty() {
        return Err(OpenADPError::NoServers);
    }
    
    Ok(servers_response.servers)
}

/// Get server URLs from registry
pub async fn get_server_urls(registry_url: &str) -> Result<Vec<String>> {
    let servers = get_servers(registry_url).await?;
    Ok(servers.into_iter().map(|s| s.url).collect())
}

/// Discover servers with fallback
pub async fn discover_servers(registry_url: &str) -> Result<Vec<ServerInfo>> {
    match get_servers(registry_url).await {
        Ok(servers) => Ok(servers),
        Err(_) => {
            // Fallback to hardcoded servers
            Ok(get_fallback_server_info())
        }
    }
}

/// Get fallback server URLs
pub fn get_fallback_servers() -> Vec<String> {
    vec![
        "https://server1.openadp.org:8443".to_string(),
        "https://server2.openadp.org:8443".to_string(),
        "https://server3.openadp.org:8443".to_string(),
    ]
}

/// Get fallback server info
pub fn get_fallback_server_info() -> Vec<ServerInfo> {
    get_fallback_servers()
        .into_iter()
        .map(|url| ServerInfo::new(url))
        .collect()
}

/// Multi-server client managing multiple servers
pub struct MultiServerClient {
    clients: Vec<EncryptedOpenADPClient>,
    strategy: ServerSelectionStrategy,
    #[allow(dead_code)]
    echo_timeout: Duration,
}

impl MultiServerClient {
    /// Create new multi-server client
    pub async fn new(servers_url: &str, echo_timeout_secs: u64) -> Result<Self> {
        let server_infos = discover_servers(servers_url).await?;
        Self::from_server_info(server_infos, echo_timeout_secs).await
    }
    
    /// Create from server info list
    pub async fn from_server_info(server_infos: Vec<ServerInfo>, echo_timeout_secs: u64) -> Result<Self> {
        let clients = Self::test_servers_concurrently(server_infos, echo_timeout_secs).await;
        
        if clients.is_empty() {
            return Err(OpenADPError::NoServers);
        }
        
        Ok(Self {
            clients,
            strategy: ServerSelectionStrategy::FirstAvailable,
            echo_timeout: Duration::from_secs(echo_timeout_secs),
        })
    }
    
    /// Test servers concurrently
    async fn test_servers_concurrently(server_infos: Vec<ServerInfo>, timeout_secs: u64) -> Vec<EncryptedOpenADPClient> {
        let futures = server_infos.into_iter().map(|server_info| {
            async move {
                let public_key = if !server_info.public_key.is_empty() {
                    parse_server_public_key(&server_info.public_key).ok()
                } else {
                    None
                };
                
                let mut client = EncryptedOpenADPClient::new(server_info.url.clone(), public_key, timeout_secs);
                
                match client.ping().await {
                    Ok(_) => Some(client),
                    Err(_) => None,
                }
            }
        });
        
        let results = join_all(futures).await;
        results.into_iter().filter_map(|r| r).collect()
    }
    
    /// Get number of live servers
    pub fn get_live_server_count(&self) -> usize {
        self.clients.len()
    }
    
    /// Get live server URLs
    pub fn get_live_server_urls(&self) -> Vec<String> {
        self.clients.iter().map(|c| c.get_server_url().to_string()).collect()
    }
    
    /// Set server selection strategy
    pub fn set_server_selection_strategy(&mut self, strategy: ServerSelectionStrategy) {
        self.strategy = strategy;
    }
    
    /// Select a server based on strategy
    fn select_server(&self) -> Result<&EncryptedOpenADPClient> {
        if self.clients.is_empty() {
            return Err(OpenADPError::NoServers);
        }
        
        match self.strategy {
            ServerSelectionStrategy::FirstAvailable => Ok(&self.clients[0]),
            ServerSelectionStrategy::Random => {
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                self.clients.choose(&mut rng).ok_or(OpenADPError::NoServers)
            }
            _ => Ok(&self.clients[0]), // Default to first for now
        }
    }
    
    /// Echo to a server
    pub async fn echo(&mut self, message: &str) -> Result<String> {
        let _client = self.select_server()?;
        // Note: We need mutable access but select_server returns immutable reference
        // In a full implementation, would handle this properly
        self.clients[0].echo(message, false).await
    }
    
    /// Ping servers (alias for echo with 'ping' message)
    pub async fn ping(&mut self) -> Result<()> {
        self.echo("ping").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_server_info() {
        let server = ServerInfo::new("https://example.com".to_string())
            .with_public_key("test_key".to_string())
            .with_country("US".to_string());
        
        assert_eq!(server.url, "https://example.com");
        assert_eq!(server.public_key, "test_key");
        assert_eq!(server.country, "US");
    }
    
    #[test]
    fn test_json_rpc_structures() {
        let request = JsonRpcRequest::new("test_method".to_string(), None);
        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.method, "test_method");
        assert_eq!(request.id, 1);
    }
    
    #[test]
    fn test_noise_nk() {
        let mut noise = NoiseNK::new();
        let (_private_key, public_key) = generate_keypair().unwrap();
        
        noise.initialize_as_initiator(public_key).unwrap();
        
        // Test that we can write the first handshake message
        let message1 = noise.write_message(b"").unwrap();
        assert!(!message1.is_empty());
        
        // For a complete test, we'd need a responder, but this tests the basic functionality
        assert!(!noise.handshake_complete); // Handshake not complete until we get a response
    }
    
    #[test]
    fn test_fallback_servers() {
        let servers = get_fallback_servers();
        assert!(!servers.is_empty());
        
        let server_infos = get_fallback_server_info();
        assert_eq!(servers.len(), server_infos.len());
    }
} 