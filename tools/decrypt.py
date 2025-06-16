#!/usr/bin/env python3
"""
OpenADP File Decryption Utility

This module provides file decryption functionality for files encrypted with ChaCha20-Poly1305
using OpenADP distributed secret sharing for key recovery using authentication codes.

The decryption process:
1. Reads metadata from the encrypted file to determine which servers were used
2. Generate authentication codes for server access
3. Uses those specific OpenADP servers to recover the encryption key 
4. Decrypts the file with ChaCha20-Poly1305 using metadata as additional authenticated data
5. Restores the original file format

Usage:
    python3 decrypt.py <filename_to_decrypt>
    
Note: Uses authentication codes instead of OAuth for server access.
"""

import os
import sys
import json
import getpass
import argparse
from typing import NoReturn, Dict, Any, Optional, List, Tuple
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from openadp import keygen
from openadp.auth_code_manager import AuthCodeManager

# --- Configuration ---
# These must match the values used during encryption
NONCE_SIZE: int = 12

def decrypt_file(input_filename: str, password: str,
                override_servers: Optional[List[str]] = None) -> None:
    """
    Decrypt the specified file using ChaCha20-Poly1305 with OpenADP key recovery.

    Expected file format: [metadata_length][metadata][nonce][encrypted_data]
    The metadata contains server URLs and is used as additional authenticated data.
    The output file will have the same name but without the .enc extension.
    
    Args:
        input_filename: Path to the encrypted file to decrypt
        password: Password for OpenADP key recovery (must match encryption password)
        override_servers: Optional list of server URLs to use instead of metadata servers
        
    Raises:
        SystemExit: If file operations fail or key recovery fails
    """
    # 1. Sanity checks and file setup
    if not os.path.exists(input_filename):
        print(f"Error: Input file '{input_filename}' not found.")
        sys.exit(1)

    # Determine output filename (remove .enc extension if present)
    if input_filename.endswith('.enc'):
        output_filename = input_filename[:-4]  # Remove '.enc'
    else:
        output_filename = input_filename + '.dec'
        print(f"Warning: Input file doesn't end with .enc, using '{output_filename}' for output")

    # 2. Read the encrypted file
    try:
        with open(input_filename, 'rb') as f_in:
            file_data = f_in.read()
    except IOError as e:
        print(f"Error reading from '{input_filename}': {e}")
        sys.exit(1)

    # 3. Validate file size and extract components
    # Need at least: 4 bytes (metadata_length) + 1 byte (minimal metadata) + NONCE_SIZE + 1 byte (minimal ciphertext)
    min_size = 4 + 1 + NONCE_SIZE + 1
    if len(file_data) < min_size:
        print(f"Error: File is too small to be a valid encrypted file")
        print(f"Expected at least {min_size} bytes, got {len(file_data)}")
        sys.exit(1)

    # Extract metadata length (first 4 bytes)
    metadata_length = int.from_bytes(file_data[:4], 'little')
    
    # Validate metadata length
    if metadata_length > len(file_data) - 4 - NONCE_SIZE:
        print(f"Error: Invalid metadata length {metadata_length}")
        sys.exit(1)
    
    # Extract components from file format: [metadata_length][metadata][nonce][encrypted_data]
    metadata_start = 4
    metadata_end = metadata_start + metadata_length
    nonce_start = metadata_end
    nonce_end = nonce_start + NONCE_SIZE
    
    metadata_json = file_data[metadata_start:metadata_end]
    nonce = file_data[nonce_start:nonce_end]
    ciphertext = file_data[nonce_end:]
    
    # Parse metadata
    try:
        metadata = json.loads(metadata_json.decode('utf-8'))
        server_urls = metadata.get('servers', [])
        auth_enabled = metadata.get('auth_enabled', False)
        threshold = metadata.get('threshold', 2)  # Default to 2 for older files
        version = metadata.get('version', '1.0')
        
        if not server_urls:
            print("Error: No server URLs found in metadata")
            sys.exit(1)
        print(f"Found metadata with {len(server_urls)} servers, threshold {threshold}")
        print(f"File version: {version}")
        
        # Use override servers if provided
        if override_servers:
            print(f"Overriding metadata servers with {len(override_servers)} custom servers")
            server_urls = override_servers
        
        # Check authentication requirements
        if auth_enabled:
            print("🔒 File was encrypted with authentication (standard)")
        else:
            print("ℹ️  File was encrypted without authentication (legacy), but using auth for decryption")
            
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Error: Failed to parse metadata: {e}")
        sys.exit(1)

    # 4. Extract authentication codes and user ID from metadata
    try:
        server_auth_codes, base_auth_code, user_id = get_auth_codes_from_metadata(metadata)
    except ValueError as e:
        print(f"Error: {e}")
        print("This file may have been encrypted with an older version that doesn't store auth codes.")
        sys.exit(1)

    # 5. Recover encryption key using custom OpenADP implementation with auth codes
    print("Recovering encryption key from the original OpenADP servers...")
    
    enc_key, error = recover_encryption_key_with_auth_codes(
        output_filename, password, user_id, server_auth_codes, server_urls, threshold
    )
    
    if error:
        print(f"❌ Failed to recover encryption key: {error}")
        print("Check that:")
        print("  • The original OpenADP servers are running and accessible")
        print("  • The password matches the one used during encryption")
        print("  • The file was encrypted with the same authentication context")
        print("  • Authentication codes are valid")
        sys.exit(1)

    # 6. Decrypt the file using metadata as additional authenticated data
    try:
        chacha = ChaCha20Poly1305(enc_key)
        plaintext = chacha.decrypt(nonce, ciphertext, metadata_json)
    except Exception as e:
        print(f"Error during decryption: {e}")
        print("This could indicate:")
        print("  • Wrong password")
        print("  • Corrupted encrypted file")
        print("  • Mismatched authentication context")
        sys.exit(1)

    # 7. Write the decrypted file
    try:
        with open(output_filename, 'wb') as f_out:
            f_out.write(plaintext)
    except IOError as e:
        print(f"Error writing to '{output_filename}': {e}")
        sys.exit(1)

    print(f"✅ File decrypted successfully!")
    print(f"   Input:  {input_filename} ({len(file_data)} bytes)")
    print(f"   Output: {output_filename} ({len(plaintext)} bytes)")
    print(f"   Servers: {len(server_urls)} servers used")
    print(f"   Threshold: {threshold}-of-{len(server_urls)} recovery")
    print(f"   Authentication: Enabled (Authentication Codes)")


def recover_encryption_key_with_auth_codes(filename: str, password: str, user_id: str, 
                                          server_auth_codes: Dict[str, str], server_urls: List[str], 
                                          threshold: int) -> Tuple[bytes, Optional[str]]:
    """
    Recover an encryption key using OpenADP with authentication codes.
    
    This is a custom implementation that uses authentication codes instead of OAuth.
    """
    from openadp import crypto, sharing
    from client.jsonrpc_client import OpenADPClient
    import secrets
    
    # Step 1: Derive same identifiers as during encryption
    uid, did, bid = keygen.derive_identifiers(filename, user_id)
    print(f"OpenADP: Recovering with UID={uid}, DID={did}, BID={bid}")
    
    # Step 2: Convert password to same PIN
    pin = keygen.password_to_pin(password)
    
    # Step 3: Initialize clients for each server
    clients = []
    for server_url in server_urls:
        try:
            client = OpenADPClient(server_url)
            clients.append((server_url, client))
        except Exception as e:
            print(f"Failed to connect to {server_url}: {e}")
            continue
    
    if not clients:
        return None, "No servers from metadata are accessible"
    
    # Step 4: Create cryptographic context (same as encryption)
    U = crypto.H(uid.encode(), did.encode(), bid.encode(), pin)
    
    # Generate random r and compute B for recovery protocol
    p = crypto.q
    r = secrets.randbelow(p - 1) + 1
    r_inv = pow(r, -1, p)
    B = crypto.point_mul(r, U)
    
    # Step 5: Recover shares from servers using authentication codes
    print("OpenADP: Recovering shares from servers...")
    recovered_shares = []
    
    for i, (server_url, client) in enumerate(clients):
        auth_code = server_auth_codes[server_url]
        
        try:
            # Get current guess number for this backup from this specific server
            backups, error = client.list_backups(auth_code, encrypted=False)
            if error:
                print(f"Warning: Could not list backups from server {i+1}: {error}")
                guess_num = 0  # Start with 0 if we can't determine current state
            else:
                # Find our backup in the list from this server
                guess_num = 0
                for backup in backups:
                    backup_bid = backup[1] if len(backup) > 1 else ""
                    if backup_bid == bid:
                        guess_num = backup[3] if len(backup) > 3 else 0  # num_guesses field
                        break
            
            # Attempt recovery from this specific server
            result, error = client.recover_secret(
                auth_code=auth_code,
                did=did,
                bid=bid,
                b=crypto.unexpand(B),
                guess_num=guess_num,
                encrypted=False  # Use auth codes, not encryption
            )
            
            if error:
                print(f"Server {i+1} recovery failed: {error}")
                continue
                
            version, x, si_b_unexpanded, num_guesses, max_guesses, expiration = result
            recovered_shares.append((x, si_b_unexpanded))
            print(f"OpenADP: Recovered share {x} from server {i+1}")
            
        except Exception as e:
            print(f"Exception recovering from server {i+1}: {e}")
            continue
    
    if len(recovered_shares) < threshold:
        return None, f"Could not recover enough shares (got {len(recovered_shares)}, need at least {threshold})"
    
    # Step 6: Reconstruct secret using recovered shares
    print(f"OpenADP: Reconstructing secret from {len(recovered_shares)} shares...")
    rec_sb = sharing.recover_sb(recovered_shares)
    rec_s_point = crypto.point_mul(r_inv, crypto.expand(rec_sb))
    
    # Step 7: Derive same encryption key
    enc_key = crypto.deriveEncKey(rec_s_point)
    print("OpenADP: Successfully recovered encryption key")
    
    return enc_key, None

def get_password_securely() -> str:
    """
    Get password from user securely.
    
    Returns:
        User-provided password
    """
    password = getpass.getpass("Enter password: ")
    if not password:
        print("Password cannot be empty.")
        sys.exit(1)
    return password

def get_auth_codes_from_metadata(metadata: dict) -> Tuple[Dict[str, str], str, str]:
    """
    Extract authentication codes from file metadata.
    
    Args:
        metadata: Parsed metadata from encrypted file
        
    Returns:
        Tuple of (server_auth_codes, base_auth_code, user_id)
    """
    print("🔐 Reading authentication codes from metadata...")
    
    # Extract auth codes from metadata
    auth_codes_data = metadata.get('auth_codes', {})
    base_auth_code = auth_codes_data.get('base_auth_code')
    server_auth_codes = auth_codes_data.get('server_auth_codes', {})
    user_id = metadata.get('user_id')
    
    if not base_auth_code:
        raise ValueError("No base authentication code found in metadata")
    if not server_auth_codes:
        raise ValueError("No server authentication codes found in metadata")
    if not user_id:
        raise ValueError("No user ID found in metadata")
    
    print(f"🔑 Retrieved base authentication code: {base_auth_code}")
    print(f"🔐 Retrieved user ID: {user_id}")
    print(f"🌐 Retrieved {len(server_auth_codes)} server-specific codes")
    
    return server_auth_codes, base_auth_code, user_id

def main() -> NoReturn:
    """Main function to handle command line arguments and decrypt files."""
    parser = argparse.ArgumentParser(
        description="Decrypt files that were encrypted using OpenADP with authentication codes",
        epilog="This utility decrypts files that were encrypted using OpenADP with authentication codes."
    )
    
    parser.add_argument('filename', help='File to decrypt')
    parser.add_argument('--password', help='Password for key recovery (will prompt if not provided)')
    parser.add_argument('--servers', nargs='+', help='Override server URLs (space-separated)')
    
    args = parser.parse_args()
    
    # Get password
    if args.password:
        password = args.password
        print("⚠️  Warning: Password provided via command line (visible in process list)")
    else:
        password = get_password_securely()
    
    # Decrypt the file
    decrypt_file(args.filename, password, args.servers)
    
    sys.exit(0)


if __name__ == '__main__':
    main() 