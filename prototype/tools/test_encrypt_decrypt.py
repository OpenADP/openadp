#!/usr/bin/env python3
"""
Test script for OpenADP encrypt/decrypt functionality.

This script tests the file encryption and decryption without requiring
interactive password input, making it suitable for automated testing.
"""

import os
import sys
import json
import tempfile
from typing import NoReturn
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Add the src directory to Python path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import keygen

# Configuration
NONCE_SIZE: int = 12


def encrypt_file_with_password(input_filename: str, password: str) -> tuple[bool, str]:
    """
    Encrypt file with given password (non-interactive version of encrypt.py)
    
    Returns:
        (success: bool, message: str)
    """
    try:
        # Check input file exists
        if not os.path.exists(input_filename):
            return False, f"Input file '{input_filename}' not found"
        
        output_filename = input_filename + ".enc"
        
        # Generate encryption key using OpenADP
        print(f"Generating encryption key for '{input_filename}'...")
        enc_key, error, server_urls = keygen.generate_encryption_key(input_filename, password)
        
        if error:
            return False, f"Failed to generate encryption key: {error}"
        
        # Create metadata
        metadata = {
            "version": 1,
            "servers": server_urls,
            "filename": os.path.basename(input_filename)
        }
        metadata_json = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
        metadata_length = len(metadata_json)
        
        # Generate nonce
        nonce = os.urandom(NONCE_SIZE)
        
        # Read plaintext
        with open(input_filename, 'rb') as f_in:
            plaintext = f_in.read()
        
        # Encrypt
        chacha = ChaCha20Poly1305(enc_key)
        ciphertext = chacha.encrypt(nonce, plaintext, metadata_json)
        
        # Write encrypted file
        with open(output_filename, 'wb') as f_out:
            f_out.write(metadata_length.to_bytes(4, 'little'))
            f_out.write(metadata_json)
            f_out.write(nonce)
            f_out.write(ciphertext)
        
        return True, f"Encrypted to '{output_filename}' ({len(ciphertext)} bytes)"
        
    except Exception as e:
        return False, f"Encryption failed: {e}"


def decrypt_file_with_password(input_filename: str, password: str) -> tuple[bool, str]:
    """
    Decrypt file with given password (non-interactive version of decrypt.py)
    
    Returns:
        (success: bool, message: str)
    """
    try:
        # Check input file exists
        if not os.path.exists(input_filename):
            return False, f"Input file '{input_filename}' not found"
        
        if not input_filename.endswith('.enc'):
            return False, f"Input file should have .enc extension"
        
        output_filename = input_filename[:-4]  # Remove .enc extension
        
        # Read encrypted file
        with open(input_filename, 'rb') as f_in:
            # Read metadata length
            metadata_length = int.from_bytes(f_in.read(4), 'little')
            
            # Read metadata
            metadata_json = f_in.read(metadata_length)
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            # Read nonce
            nonce = f_in.read(NONCE_SIZE)
            
            # Read ciphertext
            ciphertext = f_in.read()
        
        # Recover encryption key
        original_filename = metadata.get('filename', os.path.basename(output_filename))
        server_urls = metadata.get('servers')
        
        print(f"Recovering encryption key for '{original_filename}'...")
        enc_key, error = keygen.recover_encryption_key(original_filename, password, server_urls)
        
        if error:
            return False, f"Failed to recover encryption key: {error}"
        
        # Decrypt
        chacha = ChaCha20Poly1305(enc_key)
        plaintext = chacha.decrypt(nonce, ciphertext, metadata_json)
        
        # Write decrypted file
        with open(output_filename, 'wb') as f_out:
            f_out.write(plaintext)
        
        return True, f"Decrypted to '{output_filename}' ({len(plaintext)} bytes)"
        
    except Exception as e:
        return False, f"Decryption failed: {e}"


def test_encrypt_decrypt():
    """Test the complete encrypt/decrypt cycle"""
    print("🔐 OpenADP Encrypt/Decrypt Test")
    print("=" * 50)
    
    # Test data
    test_password = "test_password_123"
    test_content = b"This is test content for OpenADP encryption.\nIt has multiple lines.\nAnd some special chars: !@#$%^&*()"
    
    # Create temporary test file
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as tmp_file:
        tmp_file.write(test_content)
        test_filename = tmp_file.name
    
    try:
        print(f"Test file: {test_filename}")
        print(f"Test content: {len(test_content)} bytes")
        
        # Test encryption
        print("\n1. Testing encryption...")
        success, message = encrypt_file_with_password(test_filename, test_password)
        
        if not success:
            print(f"❌ Encryption failed: {message}")
            return False
        
        print(f"✅ Encryption successful: {message}")
        encrypted_filename = test_filename + ".enc"
        
        # Verify encrypted file exists
        if not os.path.exists(encrypted_filename):
            print(f"❌ Encrypted file not found: {encrypted_filename}")
            return False
        
        # Test decryption
        print("\n2. Testing decryption...")
        success, message = decrypt_file_with_password(encrypted_filename, test_password)
        
        if not success:
            print(f"❌ Decryption failed: {message}")
            return False
        
        print(f"✅ Decryption successful: {message}")
        
        # Verify decrypted content matches original
        decrypted_filename = test_filename  # Should overwrite original
        with open(decrypted_filename, 'rb') as f:
            decrypted_content = f.read()
        
        if decrypted_content == test_content:
            print("✅ Content verification: PASS - Decrypted content matches original")
            return True
        else:
            print("❌ Content verification: FAIL - Decrypted content differs")
            print(f"Original:  {test_content[:50]}...")
            print(f"Decrypted: {decrypted_content[:50]}...")
            return False
    
    finally:
        # Clean up temporary files
        for filename in [test_filename, test_filename + ".enc"]:
            if os.path.exists(filename):
                os.unlink(filename)
                print(f"Cleaned up: {filename}")


def main():
    """Main test function"""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("OpenADP Encrypt/Decrypt Test")
        print("Usage: python3 test_encrypt_decrypt.py")
        print("This script tests encrypt/decrypt functionality without requiring interactive input.")
        sys.exit(0)
    
    success = test_encrypt_decrypt()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 All encrypt/decrypt tests passed!")
        print("✅ OpenADP file encryption is working correctly.")
    else:
        print("❌ Some tests failed!")
        print("🔧 Check OpenADP server connectivity and keygen.py implementation.")
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main() 