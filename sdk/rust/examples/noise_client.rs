/**
 * Rust Noise-NK TCP Client
 * 
 * A Rust client that uses Noise-NK protocol to connect to the Python server
 * and demonstrate cross-platform compatibility.
 */

use openadp_ocrypt::client::{NoiseNK, generate_keypair};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::env;
use std::fs;

async fn send_message(stream: &mut TcpStream, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Send length prefix (4 bytes, big-endian)
    let length = data.len() as u32;
    stream.write_u32(length).await?;
    
    // Send data
    stream.write_all(data).await?;
    Ok(())
}

async fn receive_message(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Receive length prefix
    let length = stream.read_u32().await? as usize;
    
    // Receive data
    let mut buffer = vec![0u8; length];
    stream.read_exact(&mut buffer).await?;
    
    Ok(buffer)
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hex = hex.trim();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(bytes)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🦀 Rust Noise-NK Client");
    println!("========================");
    
    // Get server info from command line or file
    let server_public_key = if let Some(key_arg) = env::args().nth(1) {
        hex_to_bytes(&key_arg)?
    } else if let Ok(server_info) = fs::read_to_string("server_info.json") {
        let json: serde_json::Value = serde_json::from_str(&server_info)?;
        let key_hex = json["public_key"].as_str()
            .ok_or("No public_key in server_info.json")?;
        hex_to_bytes(key_hex)?
    } else {
        return Err("Usage: cargo run --example noise_client <server_public_key_hex> or create server_info.json".into());
    };
    
    println!("🔑 Server public key: {}", bytes_to_hex(&server_public_key));
    
    // Connect to server
    println!("🔗 Connecting to localhost:8888...");
    let mut stream = TcpStream::connect("localhost:8888").await?;
    println!("✅ TCP connection established");
    
    // Initialize Noise-NK as initiator
    println!("🔒 Starting Noise-NK handshake...");
    let mut noise = NoiseNK::new();
    noise.initialize_as_initiator(server_public_key)?;
    
    // Send first handshake message (-> e, es)
    let message1 = noise.write_message(b"")?;
    println!("📤 Sending handshake message 1: {} bytes", message1.len());
    println!("🔍 Raw message 1 hex: {}", bytes_to_hex(&message1));
    
    // Print handshake hash after first message
    let hash1 = noise.get_handshake_hash()?;
    println!("🔑 Handshake hash after message 1: {}", bytes_to_hex(&hash1));
    
    send_message(&mut stream, &message1).await?;
    
    // Receive second handshake message (<- e, ee)
    let message2 = receive_message(&mut stream).await?;
    println!("📨 Received handshake message 2: {} bytes", message2.len());
    
    // Process second handshake message
    let _server_payload = noise.read_message(&message2)?;
    
    // Print final handshake hash
    let final_hash = noise.get_handshake_hash()?;
    println!("🔑 Final handshake hash: {}", bytes_to_hex(&final_hash));
    
    if !noise.handshake_complete {
        return Err("Handshake not complete".into());
    }
    
    println!("✅ Noise-NK handshake completed successfully!");
    println!("🔐 Secure channel established");
    
    // Send secure messages
    for i in 1..=3 {
        let message = format!("Hello from Rust client, message {}", i);
        println!("📤 Sending secure message: {}", message);
        
        // Encrypt message
        let plaintext = message.as_bytes();
        let encrypted = noise.encrypt(plaintext)?;
        
        // Send encrypted message
        send_message(&mut stream, &encrypted).await?;
        
        // Receive encrypted response
        let encrypted_response = receive_message(&mut stream).await?;
        
        // Decrypt response
        let decrypted_response = noise.decrypt(&encrypted_response)?;
        let response = String::from_utf8(decrypted_response)?;
        
        println!("📨 Received secure response: {}", response);
        
        // Wait a bit between messages
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
    
    println!("🎉 Test completed successfully!");
    println!("🔗 Rust client and Python server are fully compatible!");
    
    Ok(())
} 