use clap::Parser;
use openadp_ocrypt::{GenerateEncryptionKeyResult, Identity, ServerInfo, get_servers, get_fallback_server_info, OpenADPClient};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::process;
use std::path::Path;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use rand::RngCore;
use std::collections::HashMap;

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
#[command(name = "openadp-encrypt")]
#[command(about = "OpenADP File Encryption Tool")]
#[command(version = VERSION)]
struct Args {
    /// File to encrypt (required)
    #[arg(long)]
    file: String,

    /// Password for key derivation (will prompt if not provided)
    #[arg(long)]
    password: Option<String>,

    /// User ID for secret ownership (will prompt if not provided)
    #[arg(long = "user-id")]
    user_id: Option<String>,

    /// Comma-separated list of server URLs (optional)
    #[arg(long)]
    servers: Option<String>,

    /// URL to scrape for server list
    #[arg(long = "servers-url", default_value = "https://servers.openadp.org")]
    servers_url: String,


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

    // Get user ID (priority: flag > environment > prompt)
    let user_id = match args.user_id {
        Some(user_id) => {
            eprintln!("⚠️  Warning: User ID provided via command line (visible in process list)");
            user_id
        }
        None => {
            match std::env::var("OPENADP_USER_ID") {
                Ok(user_id) => {
                    eprintln!("Using user ID from environment variable");
                    user_id
                }
                Err(_) => {
                    eprint!("Enter your user ID (this identifies your secrets): ");
                    io::stderr().flush().unwrap();
                    
                    let mut input = String::new();
                    if io::stdin().read_line(&mut input).is_err() {
                        eprintln!("Error reading user ID");
                        process::exit(1);
                    }
                    
                    let user_id = input.trim().to_string();
                    if user_id.is_empty() {
                        eprintln!("Error: User ID cannot be empty");
                        process::exit(1);
                    }
                    user_id
                }
            }
        }
    };

    // Validate user ID
    if user_id.len() < 3 {
        eprintln!("Error: User ID must be at least 3 characters long");
        process::exit(1);
    }
    if user_id.len() > 64 {
        eprintln!("Error: User ID must be at most 64 characters long");
        process::exit(1);
    }

    // Get server list
    let server_infos = if let Some(servers_flag) = args.servers {
        println!("📋 Using manually specified servers...");
        let server_urls: Vec<String> = servers_flag
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        
        println!("   Servers specified: {}", server_urls.len());
        for (i, url) in server_urls.iter().enumerate() {
            println!("   {}. {}", i + 1, url);
        }

        // Get public keys directly from each server via GetServerInfo
        println!("   🔍 Querying servers for public keys...");
        let mut server_infos = Vec::new();
        for url in server_urls {
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
        server_infos
    } else {
        println!("🌐 Discovering servers from registry: {}", args.servers_url);

        // Try to get full server information including public keys
        match get_servers(&args.servers_url).await {
            Ok(server_infos) if !server_infos.is_empty() => {
                println!("   ✅ Successfully fetched {} servers from registry", server_infos.len());
                
                println!("   📋 Server list with public keys:");
                for (i, server) in server_infos.iter().enumerate() {
                    let key_status = if server.public_key.is_empty() {
                        "❌ No public key"
                    } else {
                        "🔐 Public key available"
                    };
                    println!("      {}. {} [{}] - {}", i + 1, server.url, server.country, key_status);
                }
                server_infos
            }
            Ok(_) | Err(_) => {
                println!("   ⚠️  Failed to fetch from registry");
                println!("   🔄 Falling back to hardcoded servers...");
                let fallback_servers = get_fallback_server_info();
                println!("   Fallback servers: {}", fallback_servers.len());
                fallback_servers
            }
        }
    };

    if server_infos.is_empty() {
        eprintln!("❌ Error: No servers available");
        process::exit(1);
    }

    // Encrypt the file
    if let Err(e) = encrypt_file(&args.file, &password, &user_id, &server_infos, &args.servers_url).await {
        eprintln!("❌ Encryption failed: {}", e);
        process::exit(1);
    }

    println!("✅ File encrypted successfully!");
}

fn show_help() {
    print!(r#"OpenADP File Encryption Tool

USAGE:
    openadp-encrypt --file <filename> [OPTIONS]

OPTIONS:
    --file <path>          File to encrypt (required)
    --password <password>  Password for key derivation (will prompt if not provided)
    --user-id <id>         User ID for secret ownership (will prompt if not provided)
    --servers <urls>       Comma-separated list of server URLs (optional)
    --servers-url <url>    URL to scrape for server list (default: https://servers.openadp.org)
    --version              Show version information
    --help                 Show this help message

USER ID SECURITY:
    Your User ID uniquely identifies your secrets on the servers. It is critical that:
    • You use the same User ID for all your files
    • You keep your User ID private (anyone with it can overwrite your secrets)
    • You choose a unique User ID that others won't guess
    • You remember your User ID for future decryption

    You can set the OPENADP_USER_ID environment variable to avoid typing it repeatedly.

SERVER DISCOVERY:
    By default, the tool fetches the server list from servers.openadp.org/api/servers.json
    If the registry is unavailable, it falls back to hardcoded servers.
    Use -servers to specify your own server list and skip discovery.

EXAMPLES:
    # Encrypt a file using discovered servers (fetches from servers.openadp.org)
    openadp-encrypt --file document.txt

    # Encrypt using specific servers (skip discovery)
    openadp-encrypt --file document.txt --servers "https://server1.com,https://server2.com"

    # Use a different server registry
    openadp-encrypt --file document.txt --servers-url "https://my-registry.com"

    # Use environment variables to avoid prompts
    export OPENADP_PASSWORD="mypassword"
    export OPENADP_USER_ID="myuserid"
    openadp-encrypt --file document.txt

The encrypted file will be saved as <filename>.enc
"#);
}

async fn encrypt_file(
    input_filename: &str,
    password: &str,
    user_id: &str,
    server_infos: &[ServerInfo],
    _servers_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_filename = format!("{}.enc", input_filename);

    // Create Identity struct for the new API
    let identity = Identity {
        uid: user_id.to_string(),
        did: get_hostname(),                                                    // Use hostname as device ID
        bid: format!("file://{}", Path::new(input_filename).file_name().unwrap().to_string_lossy()), // Use file path as backup ID
    };

    // Generate encryption key using OpenADP with full distributed protocol
    println!("🔄 Generating encryption key using OpenADP servers...");
    let result = openadp_ocrypt::generate_encryption_key(
        &identity,
        password,
        10,
        0,
        server_infos.to_vec(),
    ).await?;

    if let Some(error) = result.error {
        return Err(format!("failed to generate encryption key: {}", error).into());
    }

    // Extract information from the result
    let enc_key = result.encryption_key.ok_or("No encryption key returned")?;
    let auth_codes = result.auth_codes.ok_or("No auth codes returned")?;
    let actual_server_infos = result.server_infos.ok_or("No server infos returned")?;
    let threshold = result.threshold.ok_or("No threshold returned")?;

    let actual_server_urls: Vec<String> = actual_server_infos.iter().map(|s| s.url.clone()).collect();

    println!("🔑 Generated authentication codes for {} servers", auth_codes.server_auth_codes.len());
    println!("🔑 Key generated successfully (UID={}, DID={}, BID={})", 
             identity.uid, identity.did, identity.bid);

    // Show which servers were actually used for key generation
    if !actual_server_urls.is_empty() && actual_server_urls.len() != server_infos.len() {
        println!("📋 Servers actually used for key generation ({}):", actual_server_urls.len());
        for (i, url) in actual_server_urls.iter().enumerate() {
            println!("   {}. {}", i + 1, url);
        }
    }

    // Read input file
    let plaintext = fs::read(input_filename)
        .map_err(|e| format!("failed to read input file: {}", e))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create metadata using the actual results from keygen
    let metadata = Metadata {
        servers: actual_server_urls.clone(),
        threshold,
        version: "1.0".to_string(),
        auth_code: auth_codes.base_auth_code,
        user_id: user_id.to_string(),
    };

    let metadata_json = serde_json::to_vec(&metadata)
        .map_err(|e| format!("failed to marshal metadata: {}", e))?;

    // Encrypt the file using metadata as additional authenticated data
    let key = Key::<Aes256Gcm>::from_slice(&enc_key);
    let cipher = Aes256Gcm::new(key);

    use aes_gcm::aead::AeadInPlace;
    let mut plaintext_copy = plaintext.clone();
    cipher.encrypt_in_place(nonce, &metadata_json, &mut plaintext_copy)
        .map_err(|e| format!("failed to encrypt: {}", e))?;
    let ciphertext = plaintext_copy;

    // Write encrypted file: [metadata_length][metadata][nonce][encrypted_data]
    let mut output_data = Vec::new();

    // Write metadata length (4 bytes, little endian)
    let metadata_len = metadata_json.len() as u32;
    output_data.extend_from_slice(&metadata_len.to_le_bytes());

    // Write metadata
    output_data.extend_from_slice(&metadata_json);

    // Write nonce
    output_data.extend_from_slice(&nonce_bytes);

    // Write encrypted data
    output_data.extend_from_slice(&ciphertext);

    fs::write(&output_filename, output_data)
        .map_err(|e| format!("failed to create output file: {}", e))?;

    println!("📁 Input:  {} ({} bytes)", input_filename, plaintext.len());
    println!("📁 Output: {} ({} bytes)", output_filename, 4 + metadata_json.len() + NONCE_SIZE + ciphertext.len());
    println!("🔐 Encryption: AES-GCM");
    println!("🌐 Servers: {} servers used", actual_server_urls.len());
    println!("🎯 Threshold: {}-of-{} recovery", threshold, actual_server_urls.len());

    // Show final server list stored in metadata
    println!("📋 Servers stored in encrypted file metadata:");
    for (i, url) in actual_server_urls.iter().enumerate() {
        println!("   {}. {}", i + 1, url);
    }

    Ok(())
}

fn get_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
} 