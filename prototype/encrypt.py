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
"""

import os
import sys
import json
import getpass
from typing import NoReturn
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import openadp_keygen

# --- Configuration ---
# Nonce (Number used once) is required for ChaCha20. It must be unique for each
# encryption operation with the same key. 12 bytes is the standard size.
NONCE_SIZE: int = 12


def encrypt_file(input_filename: str, password: str) -> None:
    """
    Encrypt the specified file using ChaCha20-Poly1305 with OpenADP key derivation.

    The output file will have the format: [metadata_length][metadata][nonce][encrypted_data]
    The metadata contains the server URLs used during encryption and is bound 
    cryptographically as additional authenticated data.
    
    Args:
        input_filename: Path to the file to encrypt
        password: Password for OpenADP key derivation
        
    Raises:
        SystemExit: If file operations fail or key generation fails
    """
    # 1. Sanity checks and file setup
    if not os.path.exists(input_filename):
        print(f"Error: Input file '{input_filename}' not found.")
        sys.exit(1)
    
    output_filename = input_filename + ".enc"

    # 2. Generate encryption key using OpenADP
    print("Generating encryption key using OpenADP distributed servers...")
    enc_key, error, server_urls = openadp_keygen.generate_encryption_key(input_filename, password)
    
    if error:
        print(f"❌ Failed to generate encryption key: {error}")
        print("Make sure OpenADP servers are running and accessible.")
        sys.exit(1)
        
    # 3. Create metadata with server information
    metadata = {
        "version": 1,
        "servers": server_urls,
        "filename": os.path.basename(input_filename)
    }
    metadata_json = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
    metadata_length = len(metadata_json)

    # 4. Generate random nonce for this encryption
    nonce = os.urandom(NONCE_SIZE)

    # 5. Read the plaintext file content
    try:
        with open(input_filename, 'rb') as f_in:
            plaintext = f_in.read()
    except IOError as e:
        print(f"Error reading from '{input_filename}': {e}")
        sys.exit(1)
        
    # 6. Encrypt the data with metadata as additional authenticated data
    # ChaCha20Poly1305 is an AEAD (Authenticated Encryption with Associated Data)
    # cipher, which provides both confidentiality and integrity/authenticity.
    # The metadata is bound cryptographically to the ciphertext.
    chacha = ChaCha20Poly1305(enc_key)
    ciphertext = chacha.encrypt(nonce, plaintext, metadata_json)  # metadata as additional data

    # 7. Write the metadata, nonce and ciphertext to the output file
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
        print(f"   Used servers: {len(server_urls)} servers")
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
    # Check for correct command-line arguments
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <filename_to_encrypt>")
        print("\nThis utility encrypts files using OpenADP distributed secret sharing")
        print("for enhanced security and recovery properties.")
        sys.exit(1)

    file_to_encrypt = sys.argv[1]
    
    # Get password securely without echoing it to the terminal
    user_password = get_password_securely()
    
    # Perform encryption
    encrypt_file(file_to_encrypt, user_password)
    
    sys.exit(0)


if __name__ == '__main__':
    main()


