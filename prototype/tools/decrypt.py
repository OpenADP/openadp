#!/usr/bin/env python3
"""
OpenADP File Decryption Utility

This module provides file decryption functionality for files encrypted with ChaCha20-Poly1305
using OpenADP distributed secret sharing for key recovery instead of traditional 
password-based key derivation.

The decryption process:
1. Reads metadata from the encrypted file to determine which servers were used
2. Uses those specific OpenADP servers to recover the encryption key 
3. Decrypts the file with ChaCha20-Poly1305 using metadata as additional authenticated data
4. Restores the original file format

The key recovery uses the specific servers from encryption metadata, providing
more reliable decryption than re-scraping the server list.

Usage:
    python3 decrypt.py <filename_to_decrypt> [--auth]
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
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import keygen

# --- Configuration ---
# These must match the values used during encryption
NONCE_SIZE: int = 12

# Authentication configuration - Global IdP (same as encrypt.py)
DEFAULT_ISSUER_URL = "https://auth.openadp.org/realms/openadp"
DEFAULT_CLIENT_ID = "cli-test"
TOKEN_CACHE_DIR = os.path.expanduser("~/.openadp")
PRIVATE_KEY_PATH = os.path.join(TOKEN_CACHE_DIR, "dpop_key.pem")
TOKEN_CACHE_PATH = os.path.join(TOKEN_CACHE_DIR, "tokens.json")


def decrypt_file(input_filename: str, password: str,
                override_servers: Optional[List[str]] = None, 
                issuer_url: str = DEFAULT_ISSUER_URL, client_id: str = DEFAULT_CLIENT_ID) -> None:
    """
    Decrypt the specified file using ChaCha20-Poly1305 with OpenADP key recovery.

    Expected file format: [metadata_length][metadata][nonce][encrypted_data]
    The metadata contains server URLs and is used as additional authenticated data.
    The output file will have the same name but without the .enc extension.
    
    Args:
        input_filename: Path to the encrypted file to decrypt
        password: Password for OpenADP key recovery (must match encryption password)
        override_servers: Optional list of server URLs to use instead of metadata servers
        issuer_url: OAuth issuer URL for authentication
        client_id: OAuth client ID for authentication
        
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
        
        if not server_urls:
            print("Error: No server URLs found in metadata")
            sys.exit(1)
        print(f"Found metadata with {len(server_urls)} servers, threshold {threshold}")
        
        # Use override servers if provided
        if override_servers:
            print(f"Overriding metadata servers with {len(override_servers)} custom servers")
            server_urls = override_servers
        
        # Always show authentication status (Phase 4: auth always enabled)
        if auth_enabled:
            print("🔒 Authentication was enabled during encryption")
        else:
            print("ℹ️  File was encrypted without authentication, but will use auth for decryption")
            
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Error: Failed to parse metadata: {e}")
        sys.exit(1)

    # 4. Handle authentication (always enabled in Phase 4)
    try:
        # Get auth token for decryption
        token_data = get_auth_token(issuer_url, client_id)
        if not token_data:
            print("❌ Authentication required for decryption but failed. Exiting.")
            sys.exit(1)
        
        # Extract user_id from JWT token for Phase 4
        try:
            import jwt
            # Decode token to extract user_id (sub claim) - don't verify signature here
            # as we'll send the full token to the server for verification
            payload = jwt.decode(token_data['access_token'], options={"verify_signature": False})
            user_id = payload.get('sub')
            if not user_id:
                print("❌ JWT token missing 'sub' claim. Invalid token.")
                sys.exit(1)
            print(f"🔐 Authenticated as user: {user_id}")
        except Exception as e:
            print(f"❌ Failed to extract user ID from token: {e}")
            sys.exit(1)
        
        # Create auth_data for Phase 3.5 encrypted authentication
        auth_data = {
            "needs_signing": True,
            "access_token": token_data['access_token'],
            "private_key": token_data['private_key'],
            "public_key_jwk": token_data['jwk_public']
        }
        print("🔐 Using Phase 3.5 encrypted authentication")
        
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        sys.exit(1)

    # 5. Recover encryption key using OpenADP with specific servers from metadata
    # Derive original filename for BID (backup identifier)
    original_filename = output_filename
    print("Recovering encryption key from the original OpenADP servers...")
    
    enc_key, error = keygen.recover_encryption_key(original_filename, password, user_id, server_urls, 
                                                   auth_data, threshold)
    
    if error:
        print(f"❌ Failed to recover encryption key: {error}")
        print("Check that:")
        print("  • The original OpenADP servers are running and accessible")
        print("  • The password matches the one used during encryption")
        print("  • The file was encrypted with the same user/device context")
        print("  • Authentication credentials are valid")
        sys.exit(1)

    # 6. Decrypt the file using metadata as additional authenticated data
    try:
        chacha = ChaCha20Poly1305(enc_key)
        plaintext = chacha.decrypt(nonce, ciphertext, metadata_json)
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        print("This could mean:")
        print("  • Wrong password")
        print("  • File has been corrupted or tampered with")
        print("  • Metadata has been modified")
        print("  • File was not encrypted with OpenADP encrypt.py")
        sys.exit(1)

    # 7. Write the decrypted data to the output file
    try:
        with open(output_filename, 'wb') as f_out:
            f_out.write(plaintext)
        print(f"✅ Decryption successful. File saved to '{output_filename}'")
        print(f"   Encrypted size: {len(file_data)} bytes") 
        print(f"   Decrypted size: {len(plaintext)} bytes")
        print(f"   Authentication: Enabled (DPoP)")
    except IOError as e:
        print(f"Error writing to '{output_filename}': {e}")
        sys.exit(1)


def get_password_securely() -> str:
    """
    Get password from user without echoing to terminal.
    
    Returns:
        User-entered password
        
    Raises:
        SystemExit: If password cannot be read or is empty
    """
    try:
        user_password = getpass.getpass("Enter password for OpenADP key recovery: ")
        if not user_password:
            print("Password cannot be empty.")
            sys.exit(1)
        return user_password
    except Exception as e:
        print(f"Could not read password: {e}")
        sys.exit(1)


def get_auth_token(issuer_url: str = DEFAULT_ISSUER_URL, 
                  client_id: str = DEFAULT_CLIENT_ID) -> Optional[Dict[str, Any]]:
    """
    Get authentication token using PKCE flow with DPoP.
    
    Args:
        issuer_url: OAuth issuer URL
        client_id: OAuth client ID
        
    Returns:
        Token information dictionary or None if authentication fails
    """
    print("🔐 Starting authentication flow...")
    
    try:
        from openadp.auth import run_pkce_flow, make_dpop_header, save_private_key, load_private_key
        from openadp.auth.pkce_flow import PKCEFlowError
        
        # Try to load existing private key
        private_key = None
        if os.path.exists(PRIVATE_KEY_PATH):
            try:
                private_key = load_private_key(PRIVATE_KEY_PATH)
                print("🔑 Loaded existing DPoP private key")
            except Exception as e:
                print(f"⚠️  Failed to load existing key: {e}")
                print("🔑 Will generate new key")
        
        # Run PKCE flow
        token_data = run_pkce_flow(
            issuer_url=issuer_url,
            client_id=client_id,
            private_key=private_key
        )
        
        # Save private key if it's new
        if private_key is None:
            save_private_key(token_data['private_key'], PRIVATE_KEY_PATH)
            print(f"🔐 Saved DPoP private key to {PRIVATE_KEY_PATH}")
        
        # Cache token data (excluding private key)
        cache_data = {
            'access_token': token_data['access_token'],
            'refresh_token': token_data.get('refresh_token'),
            'token_type': token_data['token_type'],
            'expires_in': token_data.get('expires_in'),
            'scope': token_data.get('scope'),
            'jwk_public': token_data['jwk_public']
        }
        
        # Ensure cache directory exists
        os.makedirs(TOKEN_CACHE_DIR, exist_ok=True)
        
        # Save token cache
        with open(TOKEN_CACHE_PATH, 'w') as f:
            json.dump(cache_data, f, indent=2)
        
        print("✅ Authentication successful!")
        return token_data
        
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        return None


def main() -> NoReturn:
    """
    Main function for the decryption utility.
    
    Parses command line arguments and performs file decryption using OpenADP.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Decrypt files using OpenADP distributed secret sharing",
        epilog="This utility decrypts files that were encrypted using OpenADP with OAuth authentication."
    )
    parser.add_argument(
        "filename", 
        help="Path to the encrypted file to decrypt"
    )
    
    parser.add_argument(
        '--password',
        help='Password for OpenADP key recovery (if not provided, will prompt securely)'
    )
    
    parser.add_argument(
        '--issuer',
        default=DEFAULT_ISSUER_URL,
        help=f'OAuth issuer URL (default: {DEFAULT_ISSUER_URL})'
    )
    
    parser.add_argument(
        '--client-id',
        default=DEFAULT_CLIENT_ID,
        help=f'OAuth client ID (default: {DEFAULT_CLIENT_ID})'
    )
    
    parser.add_argument(
        '--servers',
        nargs='+',
        help='Override server URLs for recovery (ignores metadata servers). Example: --servers http://localhost:8081'
    )
    
    # Check for minimum arguments before parsing
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    # Get password from command line or prompt securely
    if args.password:
        user_password = args.password
    else:
        user_password = get_password_securely()
    
    # Perform decryption
    decrypt_file(args.filename, user_password, 
                override_servers=args.servers, issuer_url=args.issuer, client_id=args.client_id)
    
    sys.exit(0)


if __name__ == '__main__':
    main()
