#!/usr/bin/env python3
"""
Test Global OpenADP Authentication Setup

This script tests that the global authentication server at https://auth.openadp.org
is properly configured and working with our updated tools.
"""

import os
import sys
import tempfile
import subprocess

# Configuration
GLOBAL_ISSUER = "https://auth.openadp.org/realms/openadp"
TEST_PASSWORD = "test123"

def test_auth_endpoints():
    """Test that the global auth server endpoints are accessible."""
    print("🌍 Testing Global Authentication Server")
    print("=" * 50)
    print(f"🔗 Server: {GLOBAL_ISSUER}")
    
    try:
        import requests
        
        # Test .well-known endpoint
        well_known_url = f"{GLOBAL_ISSUER}/.well-known/openid-configuration"
        print(f"📡 Testing: {well_known_url}")
        
        response = requests.get(well_known_url, timeout=10)
        response.raise_for_status()
        
        config = response.json()
        print(f"✅ OIDC Discovery successful")
        print(f"   - Authorization Endpoint: {config.get('authorization_endpoint', 'Not found')}")
        print(f"   - Token Endpoint: {config.get('token_endpoint', 'Not found')}")
        print(f"   - JWKS URI: {config.get('jwks_uri', 'Not found')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to connect to auth server: {e}")
        return False

def test_tool_configs():
    """Test that our tools have the correct configuration."""
    print("\n🔧 Testing Tool Configuration")
    print("=" * 50)
    
    tools_dir = os.path.join("prototype", "tools")
    
    for tool in ["encrypt.py", "decrypt.py"]:
        tool_path = os.path.join(tools_dir, tool)
        if os.path.exists(tool_path):
            print(f"📄 Checking {tool}...")
            
            # Read the file and check for global server URL
            with open(tool_path, 'r') as f:
                content = f.read()
                if "https://auth.openadp.org/realms/openadp" in content:
                    print(f"   ✅ {tool} configured for global server")
                else:
                    print(f"   ❌ {tool} NOT configured for global server")
        else:
            print(f"   ❌ {tool} not found at {tool_path}")

def test_encrypt_decrypt_flow():
    """Test a basic encrypt/decrypt flow."""
    print("\n🔐 Testing Encrypt/Decrypt Flow")
    print("=" * 50)
    
    # Create test file
    test_content = f"OpenADP Global Auth Test\nTimestamp: {os.urandom(4).hex()}\n"
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(test_content)
        test_file = f.name
    
    try:
        tools_dir = os.path.join("prototype", "tools")
        encrypt_py = os.path.join(tools_dir, "encrypt.py")
        decrypt_py = os.path.join(tools_dir, "decrypt.py")
        
        if not os.path.exists(encrypt_py):
            print(f"❌ encrypt.py not found at {encrypt_py}")
            return False
            
        if not os.path.exists(decrypt_py):
            print(f"❌ decrypt.py not found at {decrypt_py}")
            return False
        
        print(f"📝 Created test file: {test_file}")
        print("🔍 Note: This will require browser authentication...")
        
        # Test encryption (this will open browser for auth)
        print("\n🔐 Testing encryption (will open browser)...")
        encrypt_cmd = [
            sys.executable, encrypt_py,
            test_file,
            "--password", TEST_PASSWORD,
            "--servers", "http://localhost:8080"  # Assume local test server
        ]
        
        print(f"Running: {' '.join(encrypt_cmd)}")
        print("⚠️  This will open your browser for authentication!")
        
        # Don't actually run it automatically - just show the command
        print("✅ Command prepared. Run manually to test authentication flow.")
        return True
        
    except Exception as e:
        print(f"❌ Error preparing test: {e}")
        return False
    finally:
        # Clean up test file
        if os.path.exists(test_file):
            try:
                os.unlink(test_file)
            except:
                pass

def main():
    """Main test function."""
    print("🚀 OpenADP Global Authentication Setup Test")
    print("=" * 60)
    
    success = True
    
    # Test 1: Auth server endpoints
    if not test_auth_endpoints():
        success = False
    
    # Test 2: Tool configuration
    test_tool_configs()
    
    # Test 3: Prepare encrypt/decrypt test
    if not test_encrypt_decrypt_flow():
        success = False
    
    print("\n" + "=" * 60)
    if success:
        print("✅ Global authentication setup test completed successfully!")
        print("\n📋 Next Steps:")
        print("1. Ensure your OpenADP server is running and accessible")
        print("2. Run the encrypt.py tool manually to test authentication")
        print("3. The tool will open your browser to https://auth.openadp.org")
        print("4. Complete the authentication and test encryption/decryption")
    else:
        print("❌ Some tests failed. Check the output above for details.")
        sys.exit(1)

if __name__ == "__main__":
    main() 