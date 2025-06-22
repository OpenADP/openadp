#!/usr/bin/env python3

import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def test_aesgcm_decrypt():
    """Test AES-GCM decryption with exact parameters from the debug output"""
    
    # Exact parameters from debug output
    key = bytes.fromhex('746708fc3a2cbf23d7cde32803ac24bc7f5f09050fb1a5f9bb1b095cba2cbe49')
    nonce = bytes.fromhex('000000000000000000000000')
    associated_data = bytes.fromhex('1b42f7b5b5bcea1c55686484c55188d7f5e33972377ff1fc199cf0aaece03998')
    ciphertext = bytes.fromhex('c08ac722941440904eeae04a0157f8d1')
    
    print("🧪 Testing AES-GCM decryption with exact parameters:")
    print(f"   Key: {key.hex()}")
    print(f"   Nonce: {nonce.hex()}")
    print(f"   Associated Data: {associated_data.hex()}")
    print(f"   Ciphertext: {ciphertext.hex()}")
    
    try:
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
        print(f"✅ SUCCESS: Decrypted plaintext: {plaintext.hex()}")
        print(f"   Plaintext length: {len(plaintext)}")
        return True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False

def test_aesgcm_encrypt():
    """Test AES-GCM encryption with same parameters to see if we get same ciphertext"""
    
    # Same parameters
    key = bytes.fromhex('746708fc3a2cbf23d7cde32803ac24bc7f5f09050fb1a5f9bb1b095cba2cbe49')
    nonce = bytes.fromhex('000000000000000000000000')
    associated_data = bytes.fromhex('1b42f7b5b5bcea1c55686484c55188d7f5e33972377ff1fc199cf0aaece03998')
    plaintext = b''  # Empty plaintext
    
    print("\n🧪 Testing AES-GCM encryption with empty plaintext:")
    print(f"   Key: {key.hex()}")
    print(f"   Nonce: {nonce.hex()}")
    print(f"   Associated Data: {associated_data.hex()}")
    print(f"   Plaintext: {plaintext.hex()} (empty)")
    
    try:
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
        print(f"✅ SUCCESS: Encrypted ciphertext: {ciphertext.hex()}")
        print(f"   Expected from JS: c08ac722941440904eeae04a0157f8d1")
        print(f"   Match: {'✅ YES' if ciphertext.hex() == 'c08ac722941440904eeae04a0157f8d1' else '❌ NO'}")
        return ciphertext
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return None

if __name__ == "__main__":
    print("🔐 AES-GCM Compatibility Test")
    print("=" * 40)
    
    # Test encryption first
    python_ciphertext = test_aesgcm_encrypt()
    
    # Test decryption of JavaScript ciphertext
    decrypt_success = test_aesgcm_decrypt()
    
    if python_ciphertext and decrypt_success:
        print("\n🎉 Both encryption and decryption work!")
    elif python_ciphertext:
        print("\n⚠️  Encryption works but decryption of JS ciphertext fails")
    else:
        print("\n💥 Both encryption and decryption failed") 