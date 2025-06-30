use clap::Parser;
use openadp_ocrypt::recover_and_reregister;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::process;

#[derive(Parser)]
#[command(name = "ocrypt-recover")]
#[command(about = "Recover a long-term secret and reregister with fresh cryptographic material.

This tool performs two steps:
1. Recovers the secret from existing metadata
2. Reregisters with completely fresh cryptographic material

The recovered secret is printed to stderr for verification, and the new metadata
is written to the specified output file (or stdout).")]
#[command(version = "0.1.3")]
struct Args {
    /// Metadata blob from registration (required)
    #[arg(long)]
    metadata: String,

    /// Password/PIN to unlock the secret (will prompt if not provided)
    #[arg(long)]
    password: Option<String>,

    /// Custom URL for server registry (default: https://servers.openadp.org/api/servers.json)
    #[arg(long, default_value = "")]
    servers_url: String,

    /// File to write new metadata to (writes to stdout if not specified)
    #[arg(long)]
    output: Option<String>,

    /// Enable test mode (outputs JSON with secret and metadata)
    #[arg(long)]
    test_mode: bool,
}

/// Safely write data to a file, backing up existing file first.
fn safe_write_file(filename: &str, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(filename);
    
    // Check if file exists
    if path.exists() {
        // File exists, create backup
        let backup_name = format!("{}.old", filename);
        eprintln!("📋 Backing up existing {} to {}", filename, backup_name);
        
        fs::rename(filename, &backup_name)?;
        eprintln!("✅ Backup created: {}", backup_name);
    }
    
    // Write new file
    fs::write(filename, data)?;
    eprintln!("✅ New metadata written to: {}", filename);
    
    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Handle password input
    let pin = match args.password {
        Some(password) => password,
        None => {
            // Check environment variable
            match std::env::var("OCRYPT_PASSWORD") {
                Ok(password) => password,
                Err(_) => {
                    eprintln!("Error: --password is required (or set OCRYPT_PASSWORD environment variable)");
                    eprintln!("Note: Interactive password prompting not yet implemented in Rust version");
                    process::exit(1);
                }
            }
        }
    };

    if pin.is_empty() {
        eprintln!("Error: password cannot be empty");
        process::exit(1);
    }

    // Use default servers URL if none provided
    let servers_url = if args.servers_url.is_empty() {
        "https://servers.openadp.org/api/servers.json"
    } else {
        &args.servers_url
    };

    // Call ocrypt::recover_and_reregister
    eprintln!("🔄 Starting recovery and re-registration...");
    let (secret, new_metadata) = match recover_and_reregister(
        args.metadata.as_bytes(),
        &pin,
        servers_url,
    ).await {
        Ok(result) => result,
        Err(e) => {
            eprintln!("❌ Recovery failed: {}", e);
            process::exit(1);
        }
    };

    // Handle test mode
    if args.test_mode {
        let secret_str = String::from_utf8_lossy(&secret);
        let new_metadata_str = String::from_utf8_lossy(&new_metadata);
        
        let test_result = json!({
            "secret": secret_str,
            "new_metadata": new_metadata_str
        });
        
        println!("{}", test_result);
        return;
    }

    // Normal mode: Print recovered secret to stderr for verification
    let secret_str = String::from_utf8_lossy(&secret);
    eprintln!("🔓 Recovered secret: {}", secret_str);

    // Convert new metadata to string
    let new_metadata_str = String::from_utf8_lossy(&new_metadata);

    // Output new metadata  
    match args.output {
        Some(output_path) => {
            // Write to file with backup
            if let Err(e) = safe_write_file(&output_path, &new_metadata_str) {
                eprintln!("❌ Failed to write metadata to file {}: {}", output_path, e);
                process::exit(1);
            }
        }
        None => {
            // Write to stdout
            println!("{}", new_metadata_str);
        }
    }

    eprintln!("✅ Recovery and re-registration complete!");
    eprintln!("📝 New metadata contains completely fresh cryptographic material");
} 