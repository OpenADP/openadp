#!/usr/bin/env python3
"""Test OpenADP with a fresh BID to avoid old registration conflicts."""

import sys
import os

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import keygen

def test_fresh_openadp():
    """Test OpenADP key generation with a fresh backup ID."""
    print("Testing OpenADP with fresh backup ID...")
    
    test_filename = "fresh_test_file.txt"
    test_password = "my_secure_password123"
    
    # Test key generation
    print("\n1. Generating encryption key...")
    enc_key, error, server_urls = keygen.generate_encryption_key(test_filename, test_password)
    
    if error:
        print(f"❌ Key generation failed: {error}")
        return
    
    print(f"✅ Generated key: {enc_key.hex()[:32]}...")
    
    # Test key recovery
    print("\n2. Recovering encryption key...")
    recovered_key, error = keygen.recover_encryption_key(test_filename, test_password, server_urls)
    
    if error:
        print(f"❌ Key recovery failed: {error}")
        return
    
    print(f"✅ Recovered key: {recovered_key.hex()[:32]}...")
    
    # Verify keys match
    if enc_key == recovered_key:
        print("✅ Keys match! OpenADP key generation working correctly.")
        return True
    else:
        print("❌ Keys don't match - there's still a bug in the implementation.")
        print(f"   Generated:  {enc_key.hex()}")
        print(f"   Recovered:  {recovered_key.hex()}")
        return False

if __name__ == "__main__":
    test_fresh_openadp() 