use clap::Parser;
use openadp_ocrypt::{RecoverEncryptionKeyResult, Identity, ServerInfo, get_servers, get_fallback_server_info, OpenADPClient, AuthCodes};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::process;
use std::path::Path;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use hex;

const VERSION: &str = "0.1.2";
const NONCE_SIZE: usize = 12; // AES-GCM nonce size

// Metadata represents the metadata stored with encrypted files
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metadata {
    servers: Vec<String>,
    threshold: usize,
    version: String,
    auth_code: String, // Single base auth code (32 bytes hex)
    user_id: String,
}

// AuthCodesMetadata represents authentication codes in metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthCodesMetadata {
    base_auth_code: String,
    server_auth_codes: HashMap<String, String>,
}

#[derive(Parser)]
#[command(name = "openadp-decrypt")]
#[command(about = "OpenADP File Decryption Tool")]
#[command(version = VERSION)]
struct Args {
    /// File to decrypt (required)
    #[arg(long)]
    file: String,

    /// Password for key derivation (will prompt if not provided)
    #[arg(long)]
    password: Option<String>,

    /// User ID override (will use metadata or prompt if not provided)
    #[arg(long = "user-id")]
    user_id: Option<String>,

    /// Comma-separated list of server URLs to override metadata servers
    #[arg(long)]
    servers: Option<String>,


}

#[tokio::main]
async fn main() {
    let args = Args::parse();





    if args.file.is_empty() {
        eprintln!("Error: --file is required");
        show_help();
        process::exit(1);
    }

    // Check if input file exists
    if !Path::new(&args.file).exists() {
        eprintln!("Error: Input file '{}' not found.", args.file);
        process::exit(1);
    }

    // Get password (priority: flag > environment > prompt)
    let password = match args.password {
        Some(password) => {
            eprintln!("⚠️  Warning: Password provided via command line (visible in process list)");
            password
        }
        None => {
            match std::env::var("OPENADP_PASSWORD") {
                Ok(password) => {
                    eprintln!("Using password from environment variable");
                    password
                }
                Err(_) => {
                    eprint!("Enter password: ");
                    io::stderr().flush().unwrap();
                    
                    // For now, use environment variable or error
                    eprintln!("\nError: Password input not implemented. Use --password flag or OPENADP_PASSWORD environment variable");
                    process::exit(1);
                }
            }
        }
    };

    // Parse override servers if provided
    let override_servers = if let Some(servers_flag) = args.servers {
        Some(servers_flag
            .split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>())
    } else {
        None
    };

    // Decrypt the file
    if let Err(e) = decrypt_file(&args.file, &password, args.user_id.as_deref(), override_servers.as_deref()).await {
        eprintln!("❌ Decryption failed: {}", e);
        process::exit(1);
    }

    println!("✅ File decrypted successfully!");
}

fn show_help() {
    print!(r#"OpenADP File Decryption Tool

USAGE:
    openadp-decrypt --file <filename> [OPTIONS]

OPTIONS:
    --file <path>          File to decrypt (required)
    --password <password>  Password for key derivation (will prompt if not provided)
    --user-id <id>         User ID override (will use metadata or prompt if not provided)
    --servers <urls>       Comma-separated list of server URLs to override metadata servers
    --version              Show version information
    --help                 Show this help message

USER ID HANDLING:
    The tool will use the User ID in this priority order:
    1. Command line flag (--user-id)
    2. User ID stored in the encrypted file metadata
    3. OPENADP_USER_ID environment variable
    4. Interactive prompt

    You only need to specify a User ID if it's missing from the file metadata
    or if you want to override it for some reason.

EXAMPLES:
    # Decrypt a file using servers from metadata
    openadp-decrypt --file document.txt.enc

    # Decrypt using override servers
    openadp-decrypt --file document.txt.enc --servers "https://server1.com,https://server2.com"

    # Override user ID (useful for corrupted metadata)
    openadp-decrypt --file document.txt.enc --user-id "myuserid"

    # Use environment variables
    export OPENADP_PASSWORD="mypassword"
    export OPENADP_USER_ID="myuserid"
    openadp-decrypt --file document.txt.enc

The decrypted file will be saved without the .enc extension
"#);
}

async fn decrypt_file(
    input_filename: &str,
    password: &str,
    user_id: Option<&str>,
    override_servers: Option<&[String]>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Determine output filename
    let output_filename = if input_filename.ends_with(".enc") {
        input_filename.trim_end_matches(".enc").to_string()
    } else {
        format!("{}.dec", input_filename)
    };

    if !input_filename.ends_with(".enc") {
        println!("Warning: Input file doesn't end with .enc, using '{}' for output", output_filename);
    }

    // Read the encrypted file
    let file_data = fs::read(input_filename)
        .map_err(|e| format!("failed to read input file: {}", e))?;

    // Validate file size
    let min_size = 4 + 1 + NONCE_SIZE + 1; // metadata_length + minimal_metadata + nonce + minimal_ciphertext
    if file_data.len() < min_size {
        return Err(format!("file is too small to be a valid encrypted file (expected at least {} bytes, got {})", min_size, file_data.len()).into());
    }

    // Extract metadata length (first 4 bytes, little endian)
    let metadata_length = u32::from_le_bytes([file_data[0], file_data[1], file_data[2], file_data[3]]) as usize;

    // Validate metadata length
    if metadata_length > file_data.len() - 4 - NONCE_SIZE {
        return Err(format!("invalid metadata length {}", metadata_length).into());
    }

    // Extract components: [metadata_length][metadata][nonce][encrypted_data]
    let metadata_start = 4;
    let metadata_end = metadata_start + metadata_length;
    let nonce_start = metadata_end;
    let nonce_end = nonce_start + NONCE_SIZE;

    let metadata_json = &file_data[metadata_start..metadata_end];
    let nonce_bytes = &file_data[nonce_start..nonce_end];
    let ciphertext = &file_data[nonce_end..];

    // Parse metadata
    let metadata: Metadata = serde_json::from_slice(metadata_json)
        .map_err(|e| format!("failed to parse metadata: {}", e))?;

    let mut server_urls = metadata.servers.clone();
    if server_urls.is_empty() {
        return Err("no server URLs found in metadata".into());
    }

    println!("Found metadata with {} servers, threshold {}", server_urls.len(), metadata.threshold);
    println!("File version: {}", metadata.version);

    // Show servers from metadata
    println!("📋 Servers from encrypted file metadata:");
    for (i, url) in server_urls.iter().enumerate() {
        println!("   {}. {}", i + 1, url);
    }

    // Use override servers if provided
    let server_infos = if let Some(override_server_urls) = override_servers {
        println!("🔄 Overriding metadata servers with {} custom servers", override_server_urls.len());
        println!("📋 Override servers:");
        for (i, url) in override_server_urls.iter().enumerate() {
            println!("   {}. {}", i + 1, url);
        }

        // Get public keys directly from each override server via GetServerInfo
        println!("   🔍 Querying override servers for public keys...");
        let mut server_infos = Vec::new();
        for url in override_server_urls {
            // Create a basic client to call GetServerInfo
            let basic_client = OpenADPClient::new(url.clone(), 30);
            match basic_client.get_server_info().await {
                Ok(server_info) => {
                    // Extract public key from server info
                    let public_key = if !server_info.noise_nk_public_key.is_empty() {
                        format!("ed25519:{}", server_info.noise_nk_public_key)
                    } else {
                        String::new()
                    };

                    server_infos.push(ServerInfo {
                        url: url.clone(),
                        public_key: public_key.clone(),
                        country: "Unknown".to_string(),
                        remaining_guesses: None,
                    });

                    let key_status = if public_key.is_empty() {
                        "❌ No public key"
                    } else {
                        "🔐 Public key available"
                    };
                    println!("   ✅ {} - {}", url, key_status);
                }
                Err(e) => {
                    println!("   ⚠️  Failed to get server info from {}: {}", url, e);
                    // Add server without public key as fallback
                    server_infos.push(ServerInfo {
                        url: url.clone(),
                        public_key: String::new(),
                        country: "Unknown".to_string(),
                        remaining_guesses: None,
                    });
                }
            }
        }

        server_urls = override_server_urls.to_vec();
        server_infos
    } else {
        // Get server information from the secure registry (servers.json) instead of querying each server individually
        println!("   🔍 Fetching server information from secure registry...");

        // Use the default servers.json registry URL
        let servers_url = "https://servers.openadp.org";

        // Try to get full server information including public keys from the registry
        let registry_server_infos = match get_servers(servers_url).await {
            Ok(server_infos) if !server_infos.is_empty() => {
                println!("   ✅ Successfully fetched {} servers from registry", server_infos.len());
                server_infos
            }
            Ok(_) | Err(_) => {
                println!("   ⚠️  Failed to fetch from registry");
                println!("   🔄 Falling back to hardcoded servers...");
                get_fallback_server_info()
            }
        };

        // Match servers from metadata with registry servers to get public keys
        let mut server_infos = Vec::new();
        for metadata_url in &server_urls {
            // Find matching server in registry
            let matched_server = registry_server_infos.iter()
                .find(|s| s.url == *metadata_url);

            if let Some(matched_server) = matched_server {
                // Use server info from registry (includes public key)
                server_infos.push(matched_server.clone());
                let key_status = if matched_server.public_key.is_empty() {
                    "❌ No public key"
                } else {
                    "🔐 Public key available (from registry)"
                };
                println!("   ✅ {} - {}", metadata_url, key_status);
            } else {
                // Server not found in registry, add without public key as fallback
                println!("   ⚠️  Server {} not found in registry, adding without public key", metadata_url);
                server_infos.push(ServerInfo {
                    url: metadata_url.clone(),
                    public_key: String::new(),
                    country: "Unknown".to_string(),
                    remaining_guesses: None,
                });
            }
        }
        server_infos
    };

    // Check authentication requirements
    if metadata.auth_code.is_empty() {
        println!("ℹ️  File was encrypted without authentication (legacy), but using auth for decryption");
    } else {
        println!("🔒 File was encrypted with authentication (standard)");
    }

    // Extract authentication codes and user ID from metadata
    let (base_auth_code, user_id_from_metadata) = get_auth_codes_from_metadata(&metadata)?;

    // Determine final user ID (priority: flag > metadata > environment > prompt)
    let final_user_id = if let Some(user_id) = user_id {
        println!("🔐 Using user ID from command line: {}", user_id);
        user_id.to_string()
    } else if !user_id_from_metadata.is_empty() {
        println!("🔐 Using user ID from file metadata: {}", user_id_from_metadata);
        user_id_from_metadata
    } else if let Ok(env_user_id) = std::env::var("OPENADP_USER_ID") {
        println!("🔐 Using user ID from environment variable");
        env_user_id
    } else {
        eprint!("Enter your user ID (same as used during encryption): ");
        io::stderr().flush().unwrap();
        
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return Err("Error reading user ID".into());
        }
        
        let user_id = input.trim().to_string();
        if user_id.is_empty() {
            return Err("user ID cannot be empty".into());
        }
        user_id
    };

    // Recover encryption key using OpenADP
    println!("🔄 Recovering encryption key from OpenADP servers...");
    let enc_key = recover_encryption_key_with_server_info(
        &output_filename,
        password,
        &final_user_id,
        &base_auth_code,
        &server_infos,
        metadata.threshold,
    ).await?;

    // Decrypt the file using metadata as additional authenticated data
    let key = Key::<Aes256Gcm>::from_slice(&enc_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    use aes_gcm::aead::AeadInPlace;
    let mut ciphertext_copy = ciphertext.to_vec();
    cipher.decrypt_in_place(nonce, metadata_json, &mut ciphertext_copy)
        .map_err(|e| format!("decryption failed: {} (wrong password or corrupted file)", e))?;
    let plaintext = ciphertext_copy;

    // Write the decrypted file
    fs::write(&output_filename, &plaintext)
        .map_err(|e| format!("failed to write output file: {}", e))?;

    println!("📁 Input:  {} ({} bytes)", input_filename, file_data.len());
    println!("📁 Output: {} ({} bytes)", output_filename, plaintext.len());
    println!("🌐 Servers: {} servers used", server_urls.len());
    println!("🎯 Threshold: {}-of-{} recovery", metadata.threshold, server_urls.len());
    println!("🔐 Authentication: Enabled (Authentication Codes)");

    // Show final server list used for recovery
    println!("📋 Servers used for decryption:");
    for (i, url) in server_urls.iter().enumerate() {
        println!("   {}. {}", i + 1, url);
    }

    Ok(())
}

async fn recover_encryption_key_with_server_info(
    filename: &str,
    password: &str,
    user_id: &str,
    base_auth_code: &str,
    server_infos: &[ServerInfo],
    threshold: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create Identity struct for the new API
    let identity = Identity {
        uid: user_id.to_string(),
        did: get_hostname(),                                                    // Use hostname as device ID (should match encryption)
        bid: format!("file://{}", Path::new(filename).file_name().unwrap().to_string_lossy()), // Use file path as backup ID (should match encryption)
    };
    println!("🔑 Recovering with UID={}, DID={}, BID={}", identity.uid, identity.did, identity.bid);

    // Regenerate server auth codes from base auth code
    let mut server_auth_codes = HashMap::new();
    for server_info in server_infos {
        // Derive server-specific code using SHA256 (same as GenerateAuthCodes)
        let combined = format!("{}:{}", base_auth_code, server_info.url);
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let hash = hasher.finalize();
        server_auth_codes.insert(server_info.url.clone(), format!("{:x}", hash));
    }

    // Create AuthCodes structure from metadata (without UserID field)
    let auth_codes = AuthCodes {
        base_auth_code: base_auth_code.to_string(),
        server_auth_codes,
    };

    // Recover encryption key using the full distributed protocol with new API
    let result = openadp_ocrypt::recover_encryption_key_with_server_info(
        &identity,
        password,
        server_infos.to_vec(),
        threshold,
        auth_codes,
    ).await?;

    if let Some(error) = result.error {
        return Err(format!("key recovery failed: {}", error).into());
    }

    let encryption_key = result.encryption_key.ok_or("No encryption key returned")?;
    println!("✅ Key recovered successfully");
    println!("🔍 DEBUG: Recovered encryption key: {}", hex::encode(&encryption_key[..16.min(encryption_key.len())]));
    Ok(encryption_key)
}

fn get_auth_codes_from_metadata(metadata: &Metadata) -> Result<(String, String), Box<dyn std::error::Error>> {
    if metadata.auth_code.is_empty() {
        return Err("no authentication code found in metadata".into());
    }

    if metadata.user_id.is_empty() {
        return Err("no user ID found in metadata".into());
    }

    Ok((metadata.auth_code.clone(), metadata.user_id.clone()))
}

fn get_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
} 