#!/usr/bin/env python3
"""
OpenADP File Encryption Utility

This module provides file encryption functionality using ChaCha20-Poly1305 AEAD cipher
with OpenADP distributed secret sharing for key derivation using authentication codes.

The encryption process:
1. Generate authentication codes for server access
2. Uses OpenADP servers to generate a strong encryption key
3. Encrypts the file with ChaCha20-Poly1305 
4. Stores encrypted file with format: [metadata_length][metadata][nonce][encrypted_data]

The key derivation is distributed across multiple servers for enhanced security
and recovery properties compared to traditional password-based approaches.

Usage:
    python3 encrypt.py <filename_to_encrypt>
    
Note: Uses authentication codes instead of OAuth for server access.
"""

import os
import sys
import json
import getpass
import argparse
from typing import NoReturn, Optional, Dict, Any, List, Tuple
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from openadp import keygen
from openadp.auth_code_manager import AuthCodeManager

# --- Configuration ---
# Nonce (Number used once) is required for ChaCha20. It must be unique for each
# encryption operation with the same key. 12 bytes is the standard size.
NONCE_SIZE: int = 12

# Default server configuration
DEFAULT_SERVERS = [
    "https://xyzzy.openadp.org",
    "https://sky.openadp.org", 
    "https://minime.openadp.org"
]

def get_auth_codes(servers: List[str], password: str, filename: str) -> Tuple[Dict[str, str], str]:
    """
    Generate deterministic authentication codes for server access based on password and filename.
    This ensures the same codes can be regenerated during decryption.
    
    Args:
        servers: List of server URLs
        password: User password (used as seed for deterministic generation)
        filename: Filename being encrypted (used as additional entropy)
        
    Returns:
        Tuple of (dictionary mapping server URLs to authentication codes, base_auth_code)
    """
    print("🔐 Generating deterministic authentication codes...")
    
    # Create deterministic seed from password and filename
    import hashlib
    seed_data = f"{password}:{filename}".encode('utf-8')
    seed_hash = hashlib.sha256(seed_data).hexdigest()
    
    # Generate base auth code deterministically from seed (32 hex chars = 128 bits)
    base_seed = f"base:{seed_hash}"
    base_hash = hashlib.sha256(base_seed.encode()).hexdigest()
    base_auth_code = base_hash[:32]  # Take first 32 hex chars (128 bits)
    
    # Generate server-specific codes deterministically (64 hex chars = SHA256)
    server_auth_codes = {}
    for server_url in servers:
        # Use same derivation method as AuthCodeManager
        combined = f"{base_auth_code}:{server_url}"
        server_code = hashlib.sha256(combined.encode()).hexdigest()  # Full 64 hex chars
        server_auth_codes[server_url] = server_code
    
    print(f"🔑 Generated deterministic base authentication code: {base_auth_code}")
    print(f"🌐 Derived {len(server_auth_codes)} server-specific codes")
    
    return server_auth_codes, base_auth_code

def encrypt_file(input_filename: str, password: str, 
                servers: Optional[List[str]] = None, servers_url: str = "https://servers.openadp.org") -> None:
    """
    Encrypt the specified file using ChaCha20-Poly1305 with OpenADP key derivation.

    The output file will have the format: [metadata_length][metadata][nonce][encrypted_data]
    The metadata contains the server URLs used during encryption and is bound 
    cryptographically as additional authenticated data.
    
    Args:
        input_filename: Path to the file to encrypt
        password: Password for OpenADP key derivation
        servers: Optional list of custom server URLs (bypasses scraping)
        servers_url: URL to scrape for server list if servers not provided
        
    Raises:
        SystemExit: If file operations fail or key generation fails
    """
    # 1. Sanity checks and file setup
    if not os.path.exists(input_filename):
        print(f"Error: Input file '{input_filename}' not found.")
        sys.exit(1)
    
    output_filename = input_filename + ".enc"

    # 2. Use default servers if none provided
    if not servers:
        servers = DEFAULT_SERVERS
        print(f"🌐 Using default servers: {len(servers)} servers")
    
    # 3. Generate authentication codes
    server_auth_codes, base_auth_code = get_auth_codes(servers, password, input_filename)
    
    # 4. Generate user ID from authentication codes (for consistency)
    import hashlib
    user_id = hashlib.sha256(base_auth_code.encode()).hexdigest()[:32]  # 32-char UUID-like ID
    print(f"🔐 Generated user ID: {user_id}")

    # 5. Generate encryption key using custom OpenADP implementation with auth codes
    print("Generating encryption key using OpenADP servers...")
    
    enc_key, error, server_urls_used, threshold = generate_encryption_key_with_auth_codes(
        input_filename, password, user_id, server_auth_codes, servers
    )
    
    if error:
        print(f"❌ Failed to generate encryption key: {error}")
        print("Check that:")
        print("  • The OpenADP servers are running and accessible")
        print("  • Your network connection is working")
        print("  • The authentication codes are valid")
        sys.exit(1)

    # 6. Read the input file
    try:
        with open(input_filename, 'rb') as f_in:
            plaintext = f_in.read()
    except IOError as e:
        print(f"Error reading from '{input_filename}': {e}")
        sys.exit(1)

    # 7. Generate random nonce
    import secrets
    nonce = secrets.token_bytes(NONCE_SIZE)

    # 8. Create metadata
    metadata = {
        "servers": server_urls_used,
        "threshold": threshold,
        "auth_enabled": True,
        "version": "2.0"  # Version 2.0 uses authentication codes
    }
    metadata_json = json.dumps(metadata, separators=(',', ':')).encode('utf-8')

    # 9. Encrypt the file using metadata as additional authenticated data
    try:
        chacha = ChaCha20Poly1305(enc_key)
        ciphertext = chacha.encrypt(nonce, plaintext, metadata_json)
    except Exception as e:
        print(f"Error during encryption: {e}")
        sys.exit(1)

    # 10. Write the encrypted file: [metadata_length][metadata][nonce][encrypted_data]
    try:
        with open(output_filename, 'wb') as f_out:
            # Write metadata length (4 bytes, little endian)
            f_out.write(len(metadata_json).to_bytes(4, 'little'))
            # Write metadata
            f_out.write(metadata_json)
            # Write nonce
            f_out.write(nonce)
            # Write encrypted data
            f_out.write(ciphertext)
    except IOError as e:
        print(f"Error writing to '{output_filename}': {e}")
        sys.exit(1)

    print(f"✅ File encrypted successfully!")
    print(f"   Input:  {input_filename} ({len(plaintext)} bytes)")
    print(f"   Output: {output_filename} ({len(metadata_json) + 4 + NONCE_SIZE + len(ciphertext)} bytes)")
    print(f"   Servers: {len(server_urls_used)} servers used")
    print(f"   Threshold: {threshold}-of-{len(server_urls_used)} recovery")
    print(f"   Authentication: Enabled (Authentication Codes)")


def generate_encryption_key_with_auth_codes(filename: str, password: str, user_id: str, 
                                           server_auth_codes: Dict[str, str], servers: List[str]) -> Tuple[bytes, Optional[str], List[str], int]:
    """
    Generate an encryption key using OpenADP with authentication codes.
    
    This is a custom implementation that uses authentication codes instead of OAuth.
    """
    from openadp import crypto, sharing
    from client.jsonrpc_client import OpenADPClient
    import secrets
    
    # Step 1: Derive identifiers
    uid, did, bid = keygen.derive_identifiers(filename, user_id)
    print(f"OpenADP: UID={uid}, DID={did}, BID={bid}")
    
    # Step 2: Convert password to PIN
    pin = keygen.password_to_pin(password)
    
    # Step 3: Initialize clients for each server
    clients = []
    for server_url in servers:
        try:
            client = OpenADPClient(server_url)
            clients.append((server_url, client))
        except Exception as e:
            print(f"Failed to connect to {server_url}: {e}")
            continue
    
    if not clients:
        return None, "No servers available", [], 0
    
    print(f"OpenADP: Using {len(clients)} live servers")
    
    # Step 4: Generate random secret and create point
    secret = secrets.randbelow(crypto.q)
    U = crypto.H(uid.encode(), did.encode(), bid.encode(), pin)
    S = crypto.point_mul(secret, U)
    
    # Step 5: Create shares using secret sharing
    threshold = max(1, min(2, len(clients)))  # At least 1, prefer 2 if available
    num_shares = len(clients)
    
    shares = sharing.make_random_shares(secret, threshold, num_shares)
    print(f"OpenADP: Created {len(shares)} shares with threshold {threshold}")
    
    # Step 6: Register shares with servers using authentication codes
    version = 1
    registration_errors = []
    server_urls_used = []
    
    for i, ((server_url, client), (x, y)) in enumerate(zip(clients, shares)):
        auth_code = server_auth_codes[server_url]
        y_str = str(y)
        
        try:
            # Use the base client (no encryption) with auth codes
            result, error = client.register_secret(
                auth_code=auth_code,
                did=did,
                bid=bid,
                version=version,
                x=str(x),
                y=y_str,
                max_guesses=10,
                expiration=0,
                encrypted=False  # Use auth codes, not encryption
            )
            
            if error:
                registration_errors.append(f"Server {i+1}: {error}")
            elif not result:
                registration_errors.append(f"Server {i+1}: Registration returned false")
            else:
                print(f"OpenADP: Registered share {x} with server {i+1}")
                server_urls_used.append(server_url)
                
        except Exception as e:
            registration_errors.append(f"Server {i+1}: Exception: {str(e)}")
    
    if len(server_urls_used) == 0:
        return None, f"Failed to register any shares: {'; '.join(registration_errors)}", [], 0
    
    # Step 7: Derive encryption key
    enc_key = crypto.deriveEncKey(S)
    print("OpenADP: Successfully generated encryption key")
    
    return enc_key, None, server_urls_used, threshold


def get_password_securely() -> str:
    """
    Get password from user with confirmation.
    
    Returns:
        User-provided password
    """
    while True:
        password = getpass.getpass("Enter password: ")
        if not password:
            print("Password cannot be empty. Please try again.")
            continue
        
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match. Please try again.")
            continue
        
        return password


def main() -> NoReturn:
    """Main function to handle command line arguments and encrypt files."""
    parser = argparse.ArgumentParser(
        description="Encrypt files using OpenADP distributed secret sharing with authentication codes",
        epilog="This utility encrypts files using OpenADP with authentication codes for enhanced security and recovery properties."
    )
    
    parser.add_argument('filename', help='File to encrypt')
    parser.add_argument('--password', help='Password for key derivation (will prompt if not provided)')
    parser.add_argument('--servers', nargs='+', help='Custom server URLs (space-separated)')
    parser.add_argument('--servers-url', default="https://servers.openadp.org",
                       help='URL to scrape for server list (default: https://servers.openadp.org)')
    
    args = parser.parse_args()
    
    # Get password
    if args.password:
        password = args.password
        print("⚠️  Warning: Password provided via command line (visible in process list)")
    else:
        password = get_password_securely()
    
    # Encrypt the file
    encrypt_file(args.filename, password, args.servers, args.servers_url)
    
    sys.exit(0)


if __name__ == '__main__':
    main() 