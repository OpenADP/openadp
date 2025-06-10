#!/usr/bin/env python3

import os
import sys
import getpass
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
# Salt is a random value used to make dictionary attacks on the password harder.
# 16 bytes is a standard and secure size.
SALT_SIZE = 16
# Nonce (Number used once) is required for ChaCha20. It must be unique for each
# encryption operation with the same key. 12 bytes is the standard size.
NONCE_SIZE = 12
# The length of the encryption key to be derived from the password.
# ChaCha20 uses a 256-bit (32-byte) key.
KEY_LENGTH = 32

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derives a 32-byte key from the given password and salt using Scrypt.
    
    Scrypt is a password-based key derivation function that is designed to be
    computationally intensive to protect against brute-force attacks.
    """
    kdf = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=2**14,  # CPU/memory cost factor
        r=8,      # Block size parameter
        p=1,      # Parallelization parameter
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(input_filename: str, password: str):
    """
    Encrypts the specified file using ChaCha20-Poly1305.

    The output file will have the format: [salt][nonce][encrypted_data]
    """
    # 1. Sanity checks and file setup
    if not os.path.exists(input_filename):
        print(f"Error: Input file '{input_filename}' not found.")
        sys.exit(1)
    
    output_filename = input_filename + ".enc"

    # 2. Generate random salt and nonce
    # These must be random for each encryption and are safe to store publicly.
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # 3. Derive the encryption key from the user's password and the salt
    key = derive_key(password.encode('utf-8'), salt)

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
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, None) # 'None' for no associated data

    # 6. Write the salt, nonce, and ciphertext to the output file
    try:
        with open(output_filename, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(nonce)
            f_out.write(ciphertext)
        print(f"✅ Encryption successful. File saved to '{output_filename}'")
    except IOError as e:
        print(f"Error writing to '{output_filename}': {e}")
        sys.exit(1)

if __name__ == '__main__':
    # Check for correct command-line arguments
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <filename_to_encrypt>")
        sys.exit(1)

    file_to_encrypt = sys.argv[1]
    
    # Get password securely without echoing it to the terminal
    try:
        user_password = getpass.getpass("Enter password for encryption: ")
        if not user_password:
            print("Password cannot be empty.")
            sys.exit(1)
    except Exception as e:
        print(f"Could not read password: {e}")
        sys.exit(1)

    encrypt_file(file_to_encrypt, user_password)


