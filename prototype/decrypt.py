#!/usr/bin/env python3
"""
OpenADP File Decryption Utility

This module provides file decryption functionality for files encrypted with
the OpenADP encrypt.py utility. It uses ChaCha20-Poly1305 AEAD cipher with
Scrypt-based key derivation.

The encrypted file format is: [salt][nonce][encrypted_data]
- salt: 16 bytes for Scrypt key derivation
- nonce: 12 bytes for ChaCha20
- encrypted_data: Variable length ciphertext + authentication tag

Usage:
    python3 decrypt.py <filename_to_decrypt.enc>
"""

import os
import sys
import getpass
from typing import NoReturn
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# --- Configuration ---
# These values must match the ones used in the encryption script.
SALT_SIZE: int = 16
NONCE_SIZE: int = 12
KEY_LENGTH: int = 32


def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive a 32-byte decryption key from password and salt using Scrypt.
    
    The parameters (n, r, p) must be identical to the ones used during
    encryption for the key derivation to produce the same result.
    
    Args:
        password: User password as bytes
        salt: Salt bytes extracted from encrypted file
        
    Returns:
        32-byte derived decryption key
    """
    kdf = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=2**14,  # CPU/memory cost factor (must match encrypt.py)
        r=8,      # Block size parameter
        p=1,      # Parallelization parameter
        backend=default_backend()
    )
    return kdf.derive(password)


def decrypt_file(input_filename: str, password: str) -> None:
    """
    Decrypt the specified file using ChaCha20-Poly1305 AEAD cipher.

    Assumes the input file has the format: [salt][nonce][encrypted_data]
    The decrypted file will be saved without the .enc extension.
    
    Args:
        input_filename: Path to the encrypted file (.enc extension expected)
        password: Password for decryption
        
    Raises:
        SystemExit: If file operations fail, authentication fails, or input validation fails
    """
    # 1. Sanity checks and file setup
    if not os.path.exists(input_filename):
        print(f"Error: Input file '{input_filename}' not found.")
        sys.exit(1)

    if not input_filename.endswith(".enc"):
        print(f"Error: Input file '{input_filename}' does not have a '.enc' extension.")
        sys.exit(1)
    
    # Use removesuffix for a clean way to get the original filename (Python 3.9+)
    if sys.version_info >= (3, 9):
        output_filename = input_filename.removesuffix(".enc")
    else:
        output_filename = input_filename[:-4]  # Remove last 4 characters (.enc)

    # 2. Read the encrypted file content
    try:
        with open(input_filename, 'rb') as f_in:
            encrypted_data = f_in.read()
    except IOError as e:
        print(f"Error reading from '{input_filename}': {e}")
        sys.exit(1)
    
    # 3. Validate file size and extract components
    min_file_size = SALT_SIZE + NONCE_SIZE + 16  # +16 for minimum auth tag size
    if len(encrypted_data) < min_file_size:
        print(f"Error: File too small to be a valid encrypted file (minimum {min_file_size} bytes)")
        sys.exit(1)
    
    # Extract the salt, nonce, and ciphertext from the file
    # This reverses the process from the encryption script
    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE :]

    # 4. Derive the key using the extracted salt
    key = derive_key(password.encode('utf-8'), salt)

    # 5. Decrypt the data
    chacha = ChaCha20Poly1305(key)
    try:
        # The decrypt method will automatically verify the authentication tag.
        # If the key is wrong or the ciphertext was tampered with, it will
        # raise an InvalidTag exception.
        plaintext = chacha.decrypt(nonce, ciphertext, None)  # 'None' for no associated data
    except InvalidTag:
        print("❌ Decryption failed. The password may be incorrect or the file is corrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        sys.exit(1)
        
    # 6. Write the decrypted plaintext to the output file
    try:
        with open(output_filename, 'wb') as f_out:
            f_out.write(plaintext)
        print(f"✅ Decryption successful. File saved to '{output_filename}'")
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
        user_password = getpass.getpass("Enter password for decryption: ")
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
    
    Parses command line arguments and performs file decryption.
    """
    # Check for correct command-line arguments
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <filename_to_decrypt.enc>")
        sys.exit(1)

    file_to_decrypt = sys.argv[1]
    
    # Get password securely
    user_password = get_password_securely()
    
    # Perform decryption
    decrypt_file(file_to_decrypt, user_password)
    
    sys.exit(0)


if __name__ == '__main__':
    main()
