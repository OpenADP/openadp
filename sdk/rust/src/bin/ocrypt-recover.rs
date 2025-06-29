use clap::Parser;
use openadp_ocrypt::recover;
use serde_json::json;
use std::fs;
use std::process;

#[derive(Parser)]
#[command(name = "ocrypt-recover")]
#[command(about = "Recover a long-term secret using Ocrypt distributed cryptography")]
#[command(version = "0.1.2")]
struct Args {
    /// Metadata blob from registration (required)
    #[arg(long)]
    metadata: String,

    /// Password/PIN to unlock the secret (will prompt if not provided)
    #[arg(long)]
    password: Option<String>,

    /// Custom URL for server registry (empty uses default)
    #[arg(long, default_value = "")]
    servers_url: String,

    /// File to write recovery result JSON (writes to stdout if not specified)
    #[arg(long)]
    output: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Handle password input - exactly like other versions
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

    // Call ocrypt::recover
    let (secret, remaining_guesses, updated_metadata) = match recover(
        args.metadata.as_bytes(),
        &pin,
        &args.servers_url,
    ).await {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Recovery failed: {}", e);
            process::exit(1);
        }
    };

    // Create JSON tuple output - exactly like other versions
    let output_data = json!({
        "secret": String::from_utf8_lossy(&secret),
        "remaining_guesses": remaining_guesses,
        "updated_metadata": String::from_utf8_lossy(&updated_metadata)
    });

    let output_json = match serde_json::to_string(&output_data) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("JSON encoding failed: {}", e);
            process::exit(1);
        }
    };

    // Output result as JSON - exactly like other versions
    match args.output {
        Some(output_path) => {
            // Write to file
            if let Err(e) = fs::write(&output_path, &output_json) {
                eprintln!("Failed to write result to file {}: {}", output_path, e);
                process::exit(1);
            }
            eprintln!("✅ Recovery result written to {}", output_path);
        }
        None => {
            // Write to stdout
            println!("{}", output_json);
        }
    }
} 