#!/usr/bin/env python3
"""
OpenADP File Encryption Utility

This module provides file encryption functionality using ChaCha20-Poly1305 AEAD cipher
with OpenADP distributed secret sharing for key derivation instead of traditional 
password-based key derivation.

The encryption process:
1. Uses OpenADP servers to generate a strong encryption key
2. Encrypts the file with ChaCha20-Poly1305
3. Stores encrypted file with format: [salt][nonce][encrypted_data]

The key derivation is distributed across multiple servers for enhanced security
and recovery properties compared to traditional Scrypt-based approaches.

Usage:
    python3 encrypt.py <filename_to_encrypt>
"""

import os
import sys
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

    The output file will have the format: [nonce][encrypted_data]
    Note: No salt needed since OpenADP handles key derivation differently.
    
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
    enc_key, error = openadp_keygen.generate_encryption_key(input_filename, password)
    
    if error:
        print(f"❌ Failed to generate encryption key: {error}")
        print("Make sure OpenADP servers are running and accessible.")
        sys.exit(1)

    # 3. Generate random nonce for this encryption
    nonce = os.urandom(NONCE_SIZE)

    # 4. Read the plaintext file content
    try:
        with open(input_filename, 'rb') as f_in:
            plaintext = f_in.read()
    except IOError as e:
        print(f"Error reading from '{input_filename}': {e}")
        sys.exit(1)
        
    # 5. Encrypt the data
    # ChaCha20Poly1305 is an AEAD (Authenticated Encryption with Associated Data)
    # cipher, which provides both confidentiality and integrity/authenticity.
    chacha = ChaCha20Poly1305(enc_key)
    ciphertext = chacha.encrypt(nonce, plaintext, None)  # 'None' for no associated data

    # 6. Write the nonce and ciphertext to the output file
    # Format: [nonce][encrypted_data] (no salt needed with OpenADP)
    try:
        with open(output_filename, 'wb') as f_out:
            f_out.write(nonce)
            f_out.write(ciphertext)
        print(f"✅ Encryption successful. File saved to '{output_filename}'")
        print(f"   Original size: {len(plaintext)} bytes")
        print(f"   Encrypted size: {len(nonce) + len(ciphertext)} bytes")
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


