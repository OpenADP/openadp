#!/usr/bin/env python3
"""
OpenADP File Encryption Utility

This module provides file encryption functionality using ChaCha20-Poly1305 AEAD cipher
with OpenADP distributed secret sharing for key derivation instead of traditional 
password-based key derivation.

The encryption process:
1. Uses OpenADP servers to generate a strong encryption key
2. Encrypts the file with ChaCha20-Poly1305 
3. Stores encrypted file with format: [metadata_length][metadata][nonce][encrypted_data]

The key derivation is distributed across multiple servers for enhanced security
and recovery properties compared to traditional Scrypt-based approaches.

The metadata contains the list of servers used during encryption, which is 
cryptographically bound to the encrypted data as "additional data" in the AEAD cipher.

Usage:
    python3 encrypt.py <filename_to_encrypt>
    
Authentication is always enabled (Phase 4). The tool will guide you through
OAuth authentication using the Device Code flow.
"""

import os
import sys
import json
import getpass
import argparse
from typing import NoReturn, Optional, Dict, Any, List
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import keygen
from openadp.auth import run_pkce_flow, make_dpop_header, save_private_key, load_private_key
from openadp.auth.pkce_flow import PKCEFlowError

# --- Configuration ---
# Nonce (Number used once) is required for ChaCha20. It must be unique for each
# encryption operation with the same key. 12 bytes is the standard size.
NONCE_SIZE: int = 12

# Authentication configuration - Global IdP
DEFAULT_ISSUER_URL = "http://localhost:8081/realms/openadp"
DEFAULT_CLIENT_ID = "cli-test"
TOKEN_CACHE_DIR = os.path.expanduser("~/.openadp")
PRIVATE_KEY_PATH = os.path.join(TOKEN_CACHE_DIR, "dpop_key.pem")
TOKEN_CACHE_PATH = os.path.join(TOKEN_CACHE_DIR, "tokens.json")


def get_auth_token(issuer_url: str = DEFAULT_ISSUER_URL, 
                  client_id: str = DEFAULT_CLIENT_ID) -> Optional[Dict[str, Any]]:
    """
    Get authentication token using Device Code flow.
    
    Args:
        issuer_url: OAuth issuer URL
        client_id: OAuth client ID
        
    Returns:
        Token information dictionary or None if authentication fails
    """
    print("🔐 Starting authentication flow...")
    
    try:
        # Try to load existing private key
        private_key = None
        if os.path.exists(PRIVATE_KEY_PATH):
            try:
                private_key = load_private_key(PRIVATE_KEY_PATH)
                print("🔑 Loaded existing DPoP private key")
            except Exception as e:
                print(f"⚠️  Failed to load existing key: {e}")
                print("🔑 Will generate new key")
        
        # Run PKCE flow with DPoP support
        token_data = run_pkce_flow(
            issuer_url=issuer_url,
            client_id=client_id,
            private_key=private_key,
            redirect_port=8889  # Use a different port to avoid conflicts
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
        
    except PKCEFlowError as e:
        print(f"❌ Authentication failed: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected authentication error: {e}")
        return None


def make_authenticated_request(url: str, method: str = "POST", 
                             token_data: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """
    Create headers for authenticated requests with DPoP.
    
    Args:
        url: Request URL
        method: HTTP method
        token_data: Token information from authentication
        
    Returns:
        Dictionary of HTTP headers
    """
    if not token_data:
        return {}
    
    headers = {}
    
    # Add Authorization header
    access_token = token_data['access_token']
    token_type = token_data.get('token_type', 'Bearer')
    
    if token_type.lower() == 'dpop':
        headers['Authorization'] = f'DPoP {access_token}'
        
        # Generate DPoP header
        private_key = token_data['private_key']
        dpop_header = make_dpop_header(method, url, private_key, access_token)
        headers['DPoP'] = dpop_header
        
        print("🔒 Using DPoP authentication")
    else:
        headers['Authorization'] = f'Bearer {access_token}'
        print("🔒 Using Bearer token authentication")
    
    return headers


def encrypt_file(input_filename: str, password: str, 
                servers: Optional[List[str]] = None, servers_url: str = "https://servers.openadp.org",
                issuer_url: str = DEFAULT_ISSUER_URL, client_id: str = DEFAULT_CLIENT_ID) -> None:
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
        issuer_url: OAuth issuer URL for authentication
        client_id: OAuth client ID for authentication
        
    Raises:
        SystemExit: If file operations fail or key generation fails
    """
    # 1. Sanity checks and file setup
    if not os.path.exists(input_filename):
        print(f"Error: Input file '{input_filename}' not found.")
        sys.exit(1)
    
    output_filename = input_filename + ".enc"

    # 2. Handle authentication (always enabled in Phase 4)
    token_data = get_auth_token(issuer_url, client_id)
    if not token_data:
        print("❌ Authentication required but failed. Exiting.")
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

    # 3. Generate encryption key using OpenADP with user_id from JWT
    print("Generating encryption key from distributed OpenADP servers...")
    
    enc_key, error, actual_server_urls, threshold = keygen.generate_encryption_key(
        input_filename, password, user_id, 10, 0, auth_data, servers, servers_url
    )
    
    if error:
        print(f"❌ Failed to generate encryption key: {error}")
        print("Check that:")
        print("  • OpenADP servers are running and accessible")
        print("  • Password is correct")
        print("  • Authentication credentials are valid")
        sys.exit(1)
        
    # 4. Create metadata with server information
    metadata = {
        "version": 1,
        "servers": actual_server_urls,
        "threshold": threshold,
        "filename": os.path.basename(input_filename),
        "auth_enabled": True
    }
    metadata_json = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
    metadata_length = len(metadata_json)

    # 5. Generate random nonce for this encryption
    nonce = os.urandom(NONCE_SIZE)

    # 6. Read the plaintext file content
    try:
        with open(input_filename, 'rb') as f_in:
            plaintext = f_in.read()
    except IOError as e:
        print(f"Error reading from '{input_filename}': {e}")
        sys.exit(1)
        
    # 7. Encrypt the data with metadata as additional authenticated data
    # ChaCha20Poly1305 is an AEAD (Authenticated Encryption with Associated Data)
    # cipher, which provides both confidentiality and integrity/authenticity.
    # The metadata is bound cryptographically to the ciphertext.
    chacha = ChaCha20Poly1305(enc_key)
    ciphertext = chacha.encrypt(nonce, plaintext, metadata_json)  # metadata as additional data

    # 8. Write the metadata, nonce and ciphertext to the output file
    # Format: [metadata_length (4 bytes)][metadata][nonce][encrypted_data]
    try:
        with open(output_filename, 'wb') as f_out:
            # Write metadata length as a 4-byte little-endian integer
            f_out.write(metadata_length.to_bytes(4, 'little'))
            # Write metadata
            f_out.write(metadata_json)
            # Write nonce
            f_out.write(nonce)
            # Write encrypted data
            f_out.write(ciphertext)
        print(f"✅ Encryption successful. File saved to '{output_filename}'")
        print(f"   Original size: {len(plaintext)} bytes")
        print(f"   Metadata size: {metadata_length} bytes")
        print(f"   Total encrypted size: {4 + metadata_length + len(nonce) + len(ciphertext)} bytes")
        print(f"   Used servers: {len(actual_server_urls)} servers")
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
        user_password = getpass.getpass("Enter password for OpenADP key derivation: ")
        if not user_password:
            print("Password cannot be empty.")
            sys.exit(1)
        return user_password
    except Exception as e:
        print(f"Could not read password: {e}")
        sys.exit(1)


def main() -> NoReturn:
    """
    Main function for the encryption utility.
    
    Parses command line arguments and performs file encryption using OpenADP.
    """
    parser = argparse.ArgumentParser(
        description="OpenADP File Encryption Utility",
        epilog="This utility encrypts files using OpenADP distributed secret sharing "
               "with OAuth authentication for enhanced security and recovery properties."
    )
    
    parser.add_argument(
        'filename',
        help='File to encrypt'
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
        help='Custom server URLs to use (bypasses scraping). Example: --servers http://localhost:8081 http://localhost:8082'
    )
    
    parser.add_argument(
        '--servers-url',
        default="https://servers.openadp.org",
        help='URL to scrape for server list (default: https://servers.openadp.org)'
    )
    
    args = parser.parse_args()
    
    # Get password securely without echoing it to the terminal
    user_password = get_password_securely()
    
    # Perform encryption
    encrypt_file(args.filename, user_password, servers=args.servers, 
                 servers_url=args.servers_url, issuer_url=args.issuer, client_id=args.client_id)
    
    sys.exit(0)


if __name__ == '__main__':
    main()


