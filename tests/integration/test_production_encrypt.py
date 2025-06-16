#!/usr/bin/env python3
"""
Test Production Encryption with Cached Tokens

This script uses the cached production tokens to test file encryption
without going through the OAuth flow again.

NOTE: This test connects to production servers and should not be run
in automated CI/CD environments.
"""

import sys
import json
import os
import pytest

# Add the prototype src to path
sys.path.insert(0, 'prototype/src')

from openadp.auth.keys import load_private_key
from cryptography.hazmat.primitives.asymmetric import ec

def load_cached_tokens():
    """Load cached tokens from the production authentication."""
    cache_path = os.path.expanduser("~/.openadp/token_cache.json")
    private_key_path = os.path.expanduser("~/.openadp/dpop_private_key.pem")
    
    if not os.path.exists(cache_path):
        print("❌ No cached tokens found. Run production_auth_test.py first.")
        return None
    
    if not os.path.exists(private_key_path):
        print("❌ No DPoP private key found. Run production_auth_test.py first.")
        return None
    
    try:
        # Load token cache
        with open(cache_path, 'r') as f:
            cache_data = json.load(f)
        
        # Load private key
        private_key = load_private_key(private_key_path)
        
        # Combine into complete token data
        token_data = {
            'access_token': cache_data['access_token'],
            'refresh_token': cache_data.get('refresh_token'),
            'token_type': cache_data['token_type'],
            'expires_in': cache_data.get('expires_in'),
            'scope': cache_data.get('scope'),
            'jwk_public': cache_data['jwk_public'],
            'private_key': private_key
        }
        
        print("✅ Loaded cached production tokens")
        return token_data
        
    except Exception as e:
        print(f"❌ Failed to load cached tokens: {e}")
        return None

@pytest.mark.manual
def test_encryption(filename, password):
    """Test encryption using cached production tokens.
    
    This test connects to production servers and requires manual setup.
    """
    
    print("🔐 Testing Production Encryption")
    print("=" * 50)
    
    # Load cached tokens
    token_data = load_cached_tokens()
    if not token_data:
        return False
    
    # Extract user_id from JWT token
    try:
        import jwt
        payload = jwt.decode(token_data['access_token'], options={"verify_signature": False})
        user_id = payload.get('sub')
        if not user_id:
            print("❌ JWT token missing 'sub' claim. Invalid token.")
            return False
        print(f"🔐 Authenticated as user: {user_id}")
    except Exception as e:
        print(f"❌ Failed to extract user ID from token: {e}")
        return False
    
    # Create auth_data for Phase 3.5 encrypted authentication
    auth_data = {
        "needs_signing": True,
        "access_token": token_data['access_token'],
        "private_key": token_data['private_key'],
        "public_key_jwk": token_data['jwk_public']
    }
    print("🔐 Using Phase 3.5 encrypted authentication")
    
    # Test key generation
    print("🔑 Testing OpenADP key generation...")
    
    try:
        import openadp.keygen as keygen
        
        enc_key, error, actual_server_urls, threshold = keygen.generate_encryption_key(
            filename, password, user_id, 10, 0, auth_data, 
            servers=None, servers_url="https://servers.openadp.org"
        )
        
        if error:
            print(f"❌ Failed to generate encryption key: {error}")
            print("Check that:")
            print("  • OpenADP servers are running and accessible")
            print("  • Password is correct")
            print("  • Authentication credentials are valid")
            return False
        
        print(f"✅ Successfully generated encryption key!")
        print(f"   Key length: {len(enc_key)} bytes")
        print(f"   Servers used: {len(actual_server_urls)}")
        print(f"   Threshold: {threshold}")
        print(f"   Server URLs: {actual_server_urls}")
        
        return True
        
    except Exception as e:
        print(f"❌ Encryption test failed: {e}")
        return False

def main():
    if len(sys.argv) != 3:
        print("Usage: python test_production_encrypt.py <filename> <password>")
        print("\nExample:")
        print("python test_production_encrypt.py test_file.txt mypassword123")
        sys.exit(1)
    
    filename = sys.argv[1]
    password = sys.argv[2]
    
    if not os.path.exists(filename):
        print(f"❌ File '{filename}' not found.")
        sys.exit(1)
    
    success = test_encryption(filename, password)
    
    if success:
        print("\n🎉 Production encryption test successful!")
        print("✅ Your production authentication is working correctly!")
        print("✅ OpenADP servers are accessible and responding!")
        print("\n💡 You can now use the full encrypt tool with:")
        print(f"   python prototype/tools/encrypt.py --issuer https://auth.openadp.org/realms/openadp {filename}")
    else:
        print("\n❌ Production encryption test failed")
        print("💡 Check server connectivity and authentication setup")

if __name__ == "__main__":
    main() 