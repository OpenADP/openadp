//! Basic usage example for OpenADP Ocrypt
//!
//! This example demonstrates the core Ocrypt API:
//! 1. Register a secret protected by a PIN
//! 2. Recover the secret using the PIN
//! 3. Handle automatic backup refresh

use openadp_ocrypt::{register, recover, OpenADPError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 OpenADP Ocrypt - Basic Usage Example");
    println!("==========================================");

    // Example secret to protect (could be API key, private key, etc.)
    let secret = b"sk_live_51HyperSecureStripeAPIKey...";
    let user_id = "alice@example.com";
    let app_id = "payment_processor";
    let pin = "secure_pin_123";
    let max_guesses = 10;

    println!("\n📝 Registering secret...");
    println!("User ID: {}", user_id);
    println!("App ID: {}", app_id);
    println!("Secret length: {} bytes", secret.len());
    println!("Max guesses: {}", max_guesses);

    // For this example, we'll use a test registry URL
    // In production, you'd use "" for the default registry
    let test_registry_url = ""; // Empty = use default registry

    // Step 1: Register the secret
    match register(user_id, app_id, secret, pin, max_guesses, test_registry_url).await {
        Ok(metadata) => {
            println!("✅ Registration successful!");
            println!("📦 Metadata size: {} bytes", metadata.len());
            println!("💾 Store this metadata with your user record");

            // Step 2: Later, recover the secret
            println!("\n🔓 Recovering secret...");
            match recover(&metadata, pin, test_registry_url).await {
                Ok((recovered_secret, remaining_guesses, updated_metadata)) => {
                    println!("✅ Recovery successful!");
                    println!("🔑 Secret recovered: {} bytes", recovered_secret.len());
                    println!("🎯 Remaining guesses: {}", remaining_guesses);
                    
                    // Verify the secret matches
                    if recovered_secret == secret {
                        println!("✅ Secret verification: MATCH");
                    } else {
                        println!("❌ Secret verification: MISMATCH");
                    }

                    // Check if backup was refreshed
                    if updated_metadata != metadata {
                        println!("🔄 Backup was automatically refreshed");
                        println!("💾 Store the updated metadata");
                    } else {
                        println!("📋 Backup refresh not needed");
                    }
                }
                Err(e) => {
                    println!("❌ Recovery failed: {}", e);
                    handle_recovery_error(&e);
                }
            }
        }
        Err(e) => {
            println!("❌ Registration failed: {}", e);
            handle_registration_error(&e);
        }
    }

    println!("\n🎉 Example completed!");
    Ok(())
}

fn handle_registration_error(error: &OpenADPError) {
    match error {
        OpenADPError::InvalidInput(msg) => {
            println!("💡 Fix input validation: {}", msg);
        }
        OpenADPError::Network(e) => {
            println!("💡 Check network connectivity: {}", e);
            println!("   - Are you connected to the internet?");
            println!("   - Is the registry URL correct?");
        }
        OpenADPError::NoServers => {
            println!("💡 No OpenADP servers available");
            println!("   - Check if servers are running");
            println!("   - Try a different registry URL");
        }
        _ => {
            println!("💡 Unexpected error during registration");
        }
    }
}

fn handle_recovery_error(error: &OpenADPError) {
    match error {
        OpenADPError::Authentication(msg) => {
            println!("💡 Authentication failed: {}", msg);
            println!("   - Check the PIN is correct");
            println!("   - Consider guess limiting");
        }
        OpenADPError::Network(e) => {
            println!("💡 Network error during recovery: {}", e);
        }
        OpenADPError::Server(msg) => {
            println!("💡 Server error: {}", msg);
        }
        _ => {
            println!("💡 Unexpected error during recovery");
        }
    }
} 