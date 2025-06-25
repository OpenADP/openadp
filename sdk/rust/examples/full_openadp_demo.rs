//! Full OpenADP Demo
//! 
//! This example demonstrates the complete OpenADP functionality:
//! - Server discovery from registry
//! - High-level key generation and recovery API
//! - Simple ocrypt API for password hashing replacement
//! - Error handling and production patterns

use openadp_ocrypt::{
    // High-level API
    generate_encryption_key, recover_encryption_key, get_servers,
    // Simple ocrypt API
    register as ocrypt_register, recover as ocrypt_recover,
    // Crypto functions
    hash_to_point, point_compress, derive_enc_key,
    // Client types
    ServerInfo, OpenADPClient, EncryptedOpenADPClient,
    // Error handling
    OpenADPError, Result,
    Identity,
};

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 OpenADP Rust SDK - Full Demo");
    println!("=====================================\n");

    // Demo 1: Server Discovery
    demo_server_discovery().await?;
    
    // Demo 2: High-level Key Generation API
    demo_high_level_api().await?;
    
    // Demo 3: Simple Ocrypt API
    demo_ocrypt_api().await?;
    
    // Demo 4: Cryptographic Primitives
    demo_crypto_primitives().await?;
    
    // Demo 5: Client Communication
    demo_client_communication().await?;

    println!("\n✅ All demos completed successfully!");
    Ok(())
}

/// Demo 1: Server Discovery and Registry
async fn demo_server_discovery() -> Result<()> {
    println!("📡 Demo 1: Server Discovery");
    println!("---------------------------");
    
    // Try to get servers from default registry
    println!("🌐 Discovering servers from default registry...");
    
    match get_servers("").await {
        Ok(servers) => {
            println!("✅ Found {} servers:", servers.len());
            for (i, server) in servers.iter().enumerate() {
                println!("   {}. {} ({})", i + 1, server.url, 
                    if server.public_key.is_empty() { "No encryption" } else { "Encrypted" });
            }
        }
        Err(e) => {
            println!("⚠️  Registry unavailable ({}), using fallback servers", e);
            
            // Use fallback servers for demo
            let fallback_servers = vec![
                ServerInfo {
                    url: "https://demo1.openadp.org:8443".to_string(),
                    public_key: "".to_string(),
                    country: "US".to_string(),
                },
                ServerInfo {
                    url: "https://demo2.openadp.org:8443".to_string(),
                    public_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                    country: "EU".to_string(),
                },
                ServerInfo {
                    url: "https://demo3.openadp.org:8443".to_string(),
                    public_key: "".to_string(),
                    country: "AS".to_string(),
                },
            ];
            
            println!("📋 Using {} fallback servers for demo", fallback_servers.len());
        }
    }
    
    println!();
    Ok(())
}

/// Demo 2: High-level Key Generation and Recovery API
async fn demo_high_level_api() -> Result<()> {
    println!("🔑 Demo 2: High-level Key Generation API");
    println!("----------------------------------------");
    
    // Create demo servers for testing
    let demo_servers = create_demo_servers();
    
    println!("📄 Generating encryption key for document: 'financial_report.pdf'");
    println!("👤 User: alice@company.com");
    println!("🔐 Password: secure_password_123");
    
    // Create Identity for the encryption operation
    let identity = Identity::new(
        "alice@company.com".to_string(),     // UID - user identifier
        "laptop-2024".to_string(),           // DID - device identifier  
        "financial_report.pdf".to_string()   // BID - backup identifier
    );
    
    // Generate encryption key
    let key_result = generate_encryption_key(
        &identity,
        "secure_password_123", 
        10, // max_guesses
        0,  // expiration (0 = never)
        demo_servers.clone(),
    ).await?;
    
    if let Some(encryption_key) = &key_result.encryption_key {
        println!("✅ Generated {}-byte encryption key", encryption_key.len());
        println!("🎯 Threshold: {}-of-{} recovery", 
            key_result.threshold.unwrap(), 
            key_result.server_infos.as_ref().unwrap().len());
        
        // Demonstrate key recovery
        println!("\n🔓 Recovering encryption key...");
        
        let recovery_result = recover_encryption_key(
            &identity,
            "secure_password_123",
            key_result.server_infos.unwrap(),
            key_result.threshold.unwrap(),
            key_result.auth_codes.unwrap(),
        ).await?;
        
        if let Some(recovered_key) = recovery_result.encryption_key {
            if recovered_key == *encryption_key {
                println!("✅ Successfully recovered identical encryption key!");
                println!("🔒 Key can now be used for AES-256-GCM file encryption");
            } else {
                println!("❌ Recovered key doesn't match original");
                return Err(OpenADPError::Crypto("Key mismatch".to_string()));
            }
        } else {
            println!("❌ Key recovery failed: {}", 
                recovery_result.error.unwrap_or_else(|| "Unknown error".to_string()));
        }
    } else {
        println!("❌ Key generation failed: {}", 
            key_result.error.unwrap_or_else(|| "Unknown error".to_string()));
    }
    
    println!();
    Ok(())
}

/// Demo 3: Simple Ocrypt API (Password Hashing Replacement)
async fn demo_ocrypt_api() -> Result<()> {
    println!("🔐 Demo 3: Ocrypt API (Password Hashing Replacement)");
    println!("---------------------------------------------------");
    
    println!("🎯 Use Case: Protecting Stripe API key with distributed backup");
    println!("👤 User: payment_service");
    println!("📱 App: ecommerce_platform");
    
    // Simulate a Stripe API key
    let stripe_api_key = b"sk_live_EXAMPLE_NOT_REAL_KEY_FOR_DEMO_PURPOSES_ONLY_123456789";
    let user_pin = "secure_admin_pin_2024";
    
    println!("🔑 Secret length: {} bytes", stripe_api_key.len());
    
    // Register the API key with distributed protection
    println!("\n📝 Registering API key with OpenADP distributed protection...");
    
    match ocrypt_register(
        "payment_service",
        "ecommerce_platform", 
        stripe_api_key,
        user_pin,
        5, // max_guesses (stricter for production keys)
        "", // use default registry
    ).await {
        Ok(metadata) => {
            println!("✅ API key protected with OpenADP");
            println!("📦 Metadata size: {} bytes (store with user record)", metadata.len());
            
            // Simulate storing metadata in database
            println!("💾 Storing metadata in database...");
            
            // Later: recover the API key
            println!("\n🔓 Recovering API key from distributed backup...");
            
            match ocrypt_recover(&metadata, user_pin, "").await {
                Ok((recovered_key, remaining_guesses, updated_metadata)) => {
                    if recovered_key == stripe_api_key {
                        println!("✅ Successfully recovered Stripe API key!");
                        println!("🎯 Remaining guesses: {}", remaining_guesses);
                        
                        // Check if metadata was updated (backup refresh)
                        if updated_metadata != metadata {
                            println!("🔄 Backup was refreshed - update database with new metadata");
                        } else {
                            println!("📋 Backup is current - no database update needed");
                        }
                        
                        // Demonstrate usage
                        println!("🚀 API key ready for Stripe operations:");
                        let key_preview = format!("{}...{}", 
                            std::str::from_utf8(&recovered_key[..8]).unwrap_or("???"),
                            std::str::from_utf8(&recovered_key[recovered_key.len()-8..]).unwrap_or("???"));
                        println!("   Key: {}", key_preview);
                        
                    } else {
                        println!("❌ Recovered key doesn't match original!");
                        return Err(OpenADPError::Crypto("Key mismatch".to_string()));
                    }
                }
                Err(e) => {
                    println!("❌ API key recovery failed: {}", e);
                    return Err(e);
                }
            }
        }
        Err(e) => {
            println!("❌ API key registration failed: {}", e);
            return Err(e);
        }
    }
    
    println!();
    Ok(())
}

/// Demo 4: Cryptographic Primitives
async fn demo_crypto_primitives() -> Result<()> {
    println!("🧮 Demo 4: Cryptographic Primitives");
    println!("-----------------------------------");
    
    // Demonstrate hash-to-point function
    let uid = b"alice@company.com";
    let did = b"laptop-2024";
    let bid = b"file://financial_report.pdf";
    let pin = b"secure_password_123";
    
    println!("🎯 Computing H(uid, did, bid, pin)...");
    println!("   UID: {}", String::from_utf8_lossy(uid));
    println!("   DID: {}", String::from_utf8_lossy(did));
    println!("   BID: {}", String::from_utf8_lossy(bid));
    println!("   PIN: [REDACTED]");
    
    let point = hash_to_point(uid, did, bid, pin)?;
    println!("✅ Generated curve point");
    
    // Compress the point
    let compressed = point_compress(&point)?;
    println!("🗜️  Compressed to {} bytes: {}", compressed.len(), hex::encode(&compressed[..8]));
    
    // Derive encryption key
    let enc_key = derive_enc_key(&point)?;
    println!("🔑 Derived {}-byte encryption key: {}", enc_key.len(), hex::encode(&enc_key[..8]));
    
    // Demonstrate deterministic property
    let point2 = hash_to_point(uid, did, bid, pin)?;
    let compressed2 = point_compress(&point2)?;
    
    if compressed == compressed2 {
        println!("✅ Hash-to-point is deterministic (same inputs → same output)");
    } else {
        println!("❌ Hash-to-point is not deterministic!");
        return Err(OpenADPError::Crypto("Non-deterministic hash-to-point".to_string()));
    }
    
    println!();
    Ok(())
}

/// Demo 5: Client Communication
async fn demo_client_communication() -> Result<()> {
    println!("🌐 Demo 5: Client Communication");
    println!("------------------------------");
    
    // Note: This demo shows the client API structure
    // In practice, these would connect to real OpenADP servers
    
    println!("📡 Basic OpenADP Client (no encryption):");
    let basic_client = OpenADPClient::new("https://demo.openadp.org:8443".to_string(), 30);
    println!("   URL: {}", basic_client.get_server_url());
    println!("   Encryption: {}", if basic_client.supports_encryption() { "Yes" } else { "No" });
    
    println!("\n🔐 Encrypted OpenADP Client (with Noise-NK):");
    let demo_public_key = vec![0u8; 32]; // Demo key
    let encrypted_client = EncryptedOpenADPClient::new(
        "https://secure.openadp.org:8443".to_string(), 
        Some(demo_public_key), 
        30
    );
    println!("   URL: {}", encrypted_client.get_server_url());
    println!("   Encryption: {}", if encrypted_client.supports_encryption() { "Yes" } else { "No" });
    
    // In a real scenario, you would:
    // 1. client.ping().await?;
    // 2. client.get_server_info().await?;
    // 3. client.register_secret_standardized(request).await?;
    // 4. client.recover_secret_standardized(request).await?;
    
    println!("📋 Client methods available:");
    println!("   • ping() - Test basic connectivity");
    println!("   • echo(message) - Test round-trip communication");
    println!("   • get_server_info() - Get server capabilities");
    println!("   • register_secret_standardized() - Store secret share");
    println!("   • recover_secret_standardized() - Retrieve secret share");
    println!("   • list_backups_standardized() - List user backups");
    
    println!();
    Ok(())
}

/// Create demo servers for testing
fn create_demo_servers() -> Vec<ServerInfo> {
    vec![
        ServerInfo {
            url: "https://demo1.openadp.org:8443".to_string(),
            public_key: "".to_string(),
            country: "US".to_string(),
        },
        ServerInfo {
            url: "https://demo2.openadp.org:8443".to_string(), 
            public_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            country: "EU".to_string(),
        },
        ServerInfo {
            url: "https://demo3.openadp.org:8443".to_string(),
            public_key: "".to_string(),
            country: "AS".to_string(),
        },
        ServerInfo {
            url: "https://demo4.openadp.org:8443".to_string(),
            public_key: "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string(),
            country: "US".to_string(),
        },
        ServerInfo {
            url: "https://demo5.openadp.org:8443".to_string(),
            public_key: "".to_string(),
            country: "EU".to_string(),
        },
    ]
} 