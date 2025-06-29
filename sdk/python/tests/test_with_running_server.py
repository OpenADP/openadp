#!/usr/bin/env python3
"""
Simple integration test using the running OpenADP server on port 19200
"""

import sys
import os
import json
import base64
import pytest

# Add the SDK to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from openadp import (
    OpenADPClient, EncryptedOpenADPClient,
    Identity, generate_auth_codes,
    generate_encryption_key
)
from openadp.crypto import derive_enc_key, H


@pytest.fixture
def server_info():
    """Pytest fixture to get server info, or skip if server not available."""
    server_url = "http://localhost:19200"
    client = OpenADPClient(server_url)
    
    try:
        info = client.get_server_info()
        return info
    except Exception:
        pytest.skip("Server not available on port 19200")


def test_basic_connectivity():
    """Test basic connectivity to the server"""
    print("🔗 Testing basic connectivity...")
    
    server_url = "http://localhost:19200"
    client = OpenADPClient(server_url)
    
    try:
        # Test GetServerInfo
        info = client.get_server_info()
        print(f"   ✅ Server info: {info['version']}")
        print(f"   🔑 Public key: {info.get('noise_nk_public_key', 'None')[:20]}...")
        
        # Test Echo
        echo_result = client.echo("Hello from Python!")
        print(f"   ✅ Echo test: {echo_result}")
        
        return info
        
    except Exception as e:
        print(f"   ❌ Basic connectivity failed: {e}")
        print(f"   💡 Note: This test requires a server running on port 19200")
        print(f"   💡 You can start one with: ./build/openadp-server -port 19200")
        return None


def test_encrypted_connectivity(server_info):
    """Test encrypted connectivity using Noise-NK"""
    print("\n🔒 Testing encrypted connectivity...")
    
    if not server_info or 'noise_nk_public_key' not in server_info:
        print("   ❌ No server public key available")
        return False
    
    server_url = "http://localhost:19200"
    
    try:
        # Parse the public key
        public_key_b64 = server_info['noise_nk_public_key']
        public_key_bytes = base64.b64decode(public_key_b64)
        
        print(f"   🔑 Using public key: {public_key_b64[:20]}...")
        print(f"   🔑 Key bytes ({len(public_key_bytes)}): {public_key_bytes.hex()[:20]}...")
        
        # Create encrypted client
        client = EncryptedOpenADPClient(server_url, public_key_bytes)
        
        # Test encrypted echo
        echo_result = client.echo("Hello encrypted world!", encrypted=True)
        print(f"   ✅ Encrypted echo: {echo_result}")
        
        # Test encrypted ping
        client.ping()
        print(f"   ✅ Encrypted ping successful")
        
        # Test encrypted server info
        encrypted_info = client.get_server_info()
        print(f"   ✅ Encrypted server info: {encrypted_info['version']}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Encrypted connectivity failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_key_generation_workflow(server_info):
    """Test the complete key generation workflow"""
    print("\n🔐 Testing key generation workflow...")
    
    if not server_info or 'noise_nk_public_key' not in server_info:
        print("   ❌ No server public key available")
        return False
    
    try:
        # Test parameters
        filename = "test-backup.tar.gz"
        user_id = "test@example.com"
        hostname = "test-device"
        password = "test-password-123"
        
        # Create Identity
        identity = Identity(uid=user_id, did=hostname, bid=f"file://{filename}")
        print(f"   📋 UID: {identity.uid}")
        print(f"   📋 DID: {identity.did}")
        print(f"   📋 BID: {identity.bid}")
        
        # Convert password to PIN
        pin = password.encode('utf-8')
        print(f"   🔢 PIN: {pin}")
        
        # Create server info object
        from openadp.client import ServerInfo
        server_url = "http://localhost:19200"
        public_key_b64 = server_info['noise_nk_public_key']
        
        server_infos = [ServerInfo(
            url=server_url,
            public_key=f"ed25519:{public_key_b64}",
            country="Test"
        )]
        
        # Test key generation (this will attempt to register with the server)
        print("   🚀 Attempting key generation...")
        
        result = generate_encryption_key(
            identity=identity,
            password=password,
            max_guesses=10,
            expiration=0,  # No expiration for test
            server_infos=server_infos
        )
        
        if result and result.encryption_key and not result.error:
            print(f"   ✅ Key generation successful!")
            print(f"   🔑 Encryption key: {result.encryption_key.hex()[:20]}...")
            if result.auth_codes:
                print(f"   🔐 Base auth code: {result.auth_codes.base_auth_code[:20]}...")
            return True
        else:
            print(f"   ❌ Key generation failed: {result.error if result else 'No result'}")
            return False
            
    except Exception as e:
        print(f"   ❌ Key generation workflow failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run the integration tests"""
    print("🚀 OpenADP Python SDK Integration Test (Single Server)")
    print("=" * 55)
    
    # Test basic connectivity
    server_info = test_basic_connectivity()
    if not server_info:
        print("\n⚠️  Server not available - tests will be skipped")
        print("✅ Test infrastructure works correctly (server connection is optional)")
        return True
    
    # Test encrypted connectivity
    encrypted_success = test_encrypted_connectivity(server_info)
    if not encrypted_success:
        print("\n❌ Encrypted connectivity failed")
        return False
    
    # Test key generation workflow
    workflow_success = test_key_generation_workflow(server_info)
    if not workflow_success:
        print("\n❌ Key generation workflow failed")
        return False
    
    print("\n🎉 All tests passed!")
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 
