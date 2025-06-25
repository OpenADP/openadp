//! API Key Protection Example
//!
//! This example demonstrates using Ocrypt to protect sensitive API keys
//! like Stripe, AWS, GitHub tokens, etc. instead of storing them in
//! environment variables or configuration files.

use openadp_ocrypt::{register, recover};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 OpenADP Ocrypt - API Key Protection Example");
    println!("==============================================");

    // Simulate a service that needs to protect multiple API keys
    let service_id = "payment_service_v1";
    let master_pin = "service_master_pin_2024";

    // Different API keys to protect
    let api_keys: Vec<(&str, &[u8])> = vec![
        ("stripe", b"sk_live_51HyperSecureStripeKey..."),
        ("aws", b"AKIA1234567890ABCDEF"),
        ("github", b"ghp_1234567890abcdef..."),
        ("sendgrid", b"SG.1234567890abcdef..."),
    ];

    println!("\n📝 Protecting {} API keys...", api_keys.len());

    // Storage for metadata (in real app, this would be a database)
    let mut metadata_storage: HashMap<String, Vec<u8>> = HashMap::new();

    // Step 1: Register all API keys
    for (service_name, api_key) in &api_keys {
        println!("\n🔑 Registering {} API key...", service_name);
        
        match register(
            service_id,
            &format!("{}_api", service_name),
            *api_key,
            master_pin,
            5, // Lower guess limit for production services
            "", // Use default registry
        ).await {
            Ok(metadata) => {
                println!("   ✅ {} key protected ({} bytes metadata)", service_name, metadata.len());
                metadata_storage.insert(service_name.to_string(), metadata);
            }
            Err(e) => {
                println!("   ❌ Failed to protect {} key: {}", service_name, e);
                // In production, you might want to fail fast here
            }
        }
    }

    // Step 2: Later, recover API keys when needed
    println!("\n🔓 Service startup - recovering API keys...");
    
    let mut recovered_keys: HashMap<String, Vec<u8>> = HashMap::new();
    
    for (service_name, metadata) in &metadata_storage {
        match recover(metadata, master_pin, "").await {
            Ok((api_key, remaining_guesses, updated_metadata)) => {
                println!("   ✅ {} API key recovered", service_name);
                println!("      Remaining guesses: {}", remaining_guesses);
                
                // Store updated metadata if backup was refreshed
                if &updated_metadata != metadata {
                    println!("      🔄 Backup refreshed - updating storage");
                    // In real app: database.update_metadata(service_name, updated_metadata)
                }
                
                recovered_keys.insert(service_name.clone(), api_key);
            }
            Err(e) => {
                println!("   ❌ Failed to recover {} key: {}", service_name, e);
                // In production, this might prevent service startup
            }
        }
    }

    // Step 3: Use the recovered API keys
    println!("\n🚀 Service ready with {} API keys!", recovered_keys.len());
    
    // Simulate using the keys (don't print actual keys!)
    for (service_name, api_key) in &recovered_keys {
        println!("   📡 {} service: API key ready ({} bytes)", service_name, api_key.len());
        
        // Example usage patterns:
        match service_name.as_str() {
            "stripe" => {
                println!("      💳 Stripe payments initialized");
                // stripe::set_api_key(std::str::from_utf8(api_key)?);
            }
            "aws" => {
                println!("      ☁️  AWS SDK configured");
                // aws_sdk::configure_credentials(api_key);
            }
            "github" => {
                println!("      🐙 GitHub API client ready");
                // github_client.authenticate(api_key);
            }
            "sendgrid" => {
                println!("      📧 SendGrid email service ready");
                // sendgrid::set_api_key(api_key);
            }
            _ => {}
        }
    }

    // Security best practices
    println!("\n🛡️  Security Best Practices:");
    println!("   ✅ API keys protected by distributed cryptography");
    println!("   ✅ No keys stored in environment variables");
    println!("   ✅ No keys in configuration files");
    println!("   ✅ Automatic backup refresh for resilience");
    println!("   ✅ Guess limiting prevents brute force attacks");
    println!("   ✅ Nation-state resistant (requires T-of-N server compromise)");

    // Cleanup (zero out sensitive data)
    for (_, mut api_key) in recovered_keys {
        api_key.fill(0); // Zero out memory
    }
    
    println!("\n🎉 API Key Protection Example completed!");
    Ok(())
}

/// Example of integrating with a web service configuration
#[allow(dead_code)]
struct ServiceConfig {
    stripe_key: Option<Vec<u8>>,
    aws_key: Option<Vec<u8>>,
    github_token: Option<Vec<u8>>,
    sendgrid_key: Option<Vec<u8>>,
}

#[allow(dead_code)]
impl ServiceConfig {
    async fn load_from_ocrypt(service_id: &str, master_pin: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // This would load from your metadata storage (database, etc.)
        let metadata_storage = load_metadata_from_database(service_id).await?;
        
        let mut config = ServiceConfig {
            stripe_key: None,
            aws_key: None,
            github_token: None,
            sendgrid_key: None,
        };
        
        // Recover each key
        if let Some(metadata) = metadata_storage.get("stripe") {
            let (key, _, _) = recover(metadata, master_pin, "").await?;
            config.stripe_key = Some(key);
        }
        
        // ... recover other keys similarly
        
        Ok(config)
    }
}

// Mock database function
#[allow(dead_code)]
async fn load_metadata_from_database(_service_id: &str) -> Result<HashMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    // In real implementation, this would query your database
    // SELECT service_name, ocrypt_metadata FROM api_keys WHERE service_id = ?
    Ok(HashMap::new())
} 