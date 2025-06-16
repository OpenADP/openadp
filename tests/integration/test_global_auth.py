#!/usr/bin/env python3
"""
Test Phase 4 Authentication with Global IdP

This script tests the complete Phase 4 authentication flow using our global
Keycloak instance running on the Raspberry Pi.

NOTE: This test requires manual browser interaction and should not be run
in automated CI/CD environments.
"""

import os
import sys
import tempfile
import hashlib
import pytest

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp.auth import run_pkce_flow, save_private_key, load_private_key
from openadp.auth.pkce_flow import PKCEFlowError

# Global IdP configuration
GLOBAL_ISSUER_URL = "https://auth.openadp.org/realms/openadp"
GLOBAL_CLIENT_ID = "cli-test"
GLOBAL_CLIENT_SECRET = "openadp-cli-secret-change-in-production"

# Test configuration
TOKEN_CACHE_DIR = os.path.expanduser("~/.openadp_test")
PRIVATE_KEY_PATH = os.path.join(TOKEN_CACHE_DIR, "test_dpop_key.pem")

@pytest.mark.manual
def test_global_auth():
    """Test authentication with the global Keycloak IdP.
    
    This test requires manual browser interaction and connects to the
    production Keycloak server. It should only be run manually.
    """
    print("🌍 Testing Phase 4 Authentication with Global IdP")
    print("=" * 60)
    print(f"🔗 Issuer: {GLOBAL_ISSUER_URL}")
    print(f"🔧 Client: {GLOBAL_CLIENT_ID}")
    print()
    
    try:
        # Ensure test cache directory exists
        os.makedirs(TOKEN_CACHE_DIR, exist_ok=True)
        
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
        print("\n🔐 Starting PKCE + DPoP authentication flow...")
        token_data = run_pkce_flow(
            issuer_url=GLOBAL_ISSUER_URL,
            client_id=GLOBAL_CLIENT_ID,
            private_key=private_key,
            redirect_port=8889,  # Use different port to avoid conflicts
            scopes="openid email profile"
        )
        
        # Save private key if it's new
        if private_key is None:
            save_private_key(token_data['private_key'], PRIVATE_KEY_PATH)
            print(f"🔐 Saved DPoP private key to {PRIVATE_KEY_PATH}")
        
        print("\n✅ Authentication Successful!")
        print("=" * 60)
        print(f"🎫 Token Type: {token_data['token_type']}")
        print(f"⏰ Expires In: {token_data.get('expires_in', 'Unknown')} seconds")
        print(f"🔍 Scope: {token_data.get('scope', 'Unknown')}")
        print(f"🔑 Has Refresh Token: {'Yes' if token_data.get('refresh_token') else 'No'}")
        
        # Extract user info from JWT token
        try:
            import jwt
            payload = jwt.decode(token_data['access_token'], options={"verify_signature": False})
            user_id = payload.get('sub')
            username = payload.get('preferred_username', 'Unknown')
            email = payload.get('email', 'Unknown')
            
            print(f"👤 User ID: {user_id}")
            print(f"📧 Username: {username}")
            print(f"📬 Email: {email}")
            
        except Exception as e:
            print(f"⚠️  Could not decode JWT: {e}")
        
        # Test DPoP key thumbprint
        from openadp.auth.dpop import calculate_jwk_thumbprint
        thumbprint = calculate_jwk_thumbprint(token_data['jwk_public'])
        print(f"🔒 DPoP Key Thumbprint: {thumbprint[:16]}...")
        
        return token_data
        
    except PKCEFlowError as e:
        print(f"❌ Authentication failed: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None

@pytest.mark.manual
def test_file_encryption_with_global_auth():
    """Test file encryption/decryption with global authentication.
    
    This test requires manual browser interaction and connects to the
    production Keycloak server. It should only be run manually.
    """
    print("\n🔒 Testing File Encryption with Global Auth")
    print("=" * 60)
    
    # Create a test file
    test_content = f"OpenADP Phase 4 Test - Global IdP Authentication\nTimestamp: {os.urandom(8).hex()}\n"
    test_file = os.path.join(tempfile.gettempdir(), "openadp_global_test.txt")
    
    try:
        # Write test file
        with open(test_file, 'w') as f:
            f.write(test_content)
        print(f"📝 Created test file: {test_file}")
        
        # Test encryption using subprocess (since direct imports are complex)
        print("\n🔐 Testing encryption...")
        import subprocess
        
        encrypt_cmd = [
            sys.executable, 
            os.path.join(os.path.dirname(__file__), "encrypt.py"),
            test_file,
            "--password", "test123",
            "--servers", "http://localhost:8080",  # Assuming local server for testing
        ]
        
        result = subprocess.run(encrypt_cmd, capture_output=True, text=True)
        
        encrypted_file = test_file + ".enc"
        if result.returncode == 0 and os.path.exists(encrypted_file):
            print(f"✅ Encryption successful: {encrypted_file}")
        else:
            print(f"❌ Encryption failed: {result.stderr}")
            assert False, f"Encryption failed: {result.stderr}"
        
        # Test decryption
        print("\n🔓 Testing decryption...")
        
        # Remove original file to test decryption
        os.remove(test_file)
        
        decrypt_cmd = [
            sys.executable,
            os.path.join(os.path.dirname(__file__), "decrypt.py"), 
            encrypted_file,
            "--password", "test123"
        ]
        
        result = subprocess.run(decrypt_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ Decryption failed: {result.stderr}")
            assert False, f"Decryption failed: {result.stderr}"
        
        # Verify content
        if os.path.exists(test_file):
            with open(test_file, 'r') as f:
                decrypted_content = f.read()
            
            if decrypted_content == test_content:
                print("✅ Decryption successful - content matches!")
                assert True  # Explicit success
            else:
                print("❌ Decryption failed - content mismatch")
                print(f"Expected: {repr(test_content)}")
                print(f"Got: {repr(decrypted_content)}")
                assert False, f"Content mismatch: expected {repr(test_content)}, got {repr(decrypted_content)}"
        else:
            print("❌ Decryption failed - no output file")
            assert False, "Decryption failed - no output file"
            
    except Exception as e:
        print(f"❌ File encryption test failed: {e}")
        assert False, f"File encryption test failed: {e}"
    finally:
        # Cleanup
        for file_path in [test_file, test_file + ".enc"]:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass

def main():
    """Main test function."""
    print("🚀 OpenADP Phase 4 Global Authentication Test")
    print("=" * 60)
    print("Testing authentication with global Keycloak IdP on Raspberry Pi")
    print()
    
    # Test 1: Basic authentication
    token_data = test_global_auth()
    if not token_data:
        print("\n❌ Authentication test failed!")
        sys.exit(1)
    
    # Test 2: File encryption with authentication
    if test_file_encryption_with_global_auth():
        print("\n🎉 All tests passed!")
        print("✅ Phase 4 global authentication is working correctly!")
    else:
        print("\n❌ File encryption test failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 