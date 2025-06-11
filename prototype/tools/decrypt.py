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
    python3 decrypt.py <filename_to_decrypt>
"""

import os
import sys
import json
import getpass
from typing import NoReturn, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import keygen

# --- Configuration ---
# These must match the values used during encryption
NONCE_SIZE: int = 12


def decrypt_file(input_filename: str, password: str) -> None:
    """
    Decrypt the specified file using ChaCha20-Poly1305 with OpenADP key recovery.

    Expected file format: [metadata_length][metadata][nonce][encrypted_data]
    The metadata contains server URLs and is used as additional authenticated data.
    The output file will have the same name but without the .enc extension.
    
    Args:
        input_filename: Path to the encrypted file to decrypt
        password: Password for OpenADP key recovery (must match encryption password)
        
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
        if not server_urls:
            print("Error: No server URLs found in metadata")
            sys.exit(1)
        print(f"Found metadata with {len(server_urls)} servers")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Error: Failed to parse metadata: {e}")
        sys.exit(1)

    # 4. Recover encryption key using OpenADP with specific servers from metadata
    # Derive original filename for BID (backup identifier)
    original_filename = output_filename
    print("Recovering encryption key from the original OpenADP servers...")
    enc_key, error = keygen.recover_encryption_key(original_filename, password, server_urls)
    
    if error:
        print(f"❌ Failed to recover encryption key: {error}")
        print("Check that:")
        print("  • The original OpenADP servers are running and accessible")
        print("  • The password matches the one used during encryption")
        print("  • The file was encrypted with the same user/device context")
        sys.exit(1)

    # 5. Decrypt the file using metadata as additional authenticated data
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

    # 6. Write the decrypted data to the output file
    try:
        with open(output_filename, 'wb') as f_out:
            f_out.write(plaintext)
        print(f"✅ Decryption successful. File saved to '{output_filename}'")
        print(f"   Encrypted size: {len(file_data)} bytes") 
        print(f"   Decrypted size: {len(plaintext)} bytes")
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


def main() -> NoReturn:
    """
    Main function for the decryption utility.
    
    Parses command line arguments and performs file decryption using OpenADP.
    """
    # Check for correct command-line arguments
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <filename_to_decrypt>")
        print("\nThis utility decrypts files that were encrypted using OpenADP")
        print("distributed secret sharing for enhanced security and recovery.")
        sys.exit(1)

    file_to_decrypt = sys.argv[1]
    
    # Get password securely without echoing it to the terminal
    user_password = get_password_securely()
    
    # Perform decryption
    decrypt_file(file_to_decrypt, user_password)
    
    sys.exit(0)


if __name__ == '__main__':
    main()
