use clap::Parser;
use openadp_ocrypt::register;
use std::fs;
use std::io::{self, Write};
use std::process;

#[derive(Parser)]
#[command(name = "ocrypt-register")]
#[command(about = "Register a long-term secret using Ocrypt distributed cryptography")]
#[command(version = "0.1.3")]
struct Args {
    /// Unique identifier for the user (required)
    #[arg(long)]
    user_id: String,

    /// Application identifier to namespace secrets per app (required)
    #[arg(long)]
    app_id: String,

    /// Long-term secret to protect (required)
    #[arg(long)]
    long_term_secret: String,

    /// Password/PIN to unlock the secret (will prompt if not provided)
    #[arg(long)]
    password: Option<String>,

    /// Maximum wrong PIN attempts before lockout
    #[arg(long, default_value = "10")]
    max_guesses: i32,

    /// Custom URL for server registry (empty uses default)
    #[arg(long, default_value = "")]
    servers_url: String,

    /// File to write metadata JSON (writes to stdout if not specified)
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

    // Validate max_guesses
    if args.max_guesses < 1 {
        eprintln!("Error: --max-guesses must be a positive number");
        process::exit(1);
    }

    // Call ocrypt::register
    let metadata = match register(
        &args.user_id,
        &args.app_id,
        args.long_term_secret.as_bytes(),
        &pin,
        args.max_guesses,
        &args.servers_url,
    ).await {
        Ok(metadata) => metadata,
        Err(e) => {
            eprintln!("Registration failed: {}", e);
            process::exit(1);
        }
    };

    // Output metadata as JSON - exactly like other versions
    match args.output {
        Some(output_path) => {
            // Write to file
            if let Err(e) = fs::write(&output_path, &metadata) {
                eprintln!("Failed to write metadata to file {}: {}", output_path, e);
                process::exit(1);
            }
            eprintln!("✅ Metadata written to {}", output_path);
        }
        None => {
            // Write to stdout
            if let Err(e) = io::stdout().write_all(&metadata) {
                eprintln!("Failed to write to stdout: {}", e);
                process::exit(1);
            }
        }
    }
} 