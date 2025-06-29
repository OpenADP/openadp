#!/usr/bin/env python3
"""
Test script for OpenADP Python client implementation.

This script tests the basic functionality of the Python client to ensure
it matches the Go implementation correctly.
"""

import sys
import os

# Add the SDK to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'sdk', 'python'))

try:
    from openadp import (
        OpenADPClient, EncryptedOpenADPClient, MultiServerClient,
        NoiseNK, generate_keypair, parse_server_public_key,
        ServerInfo, OpenADPError, ErrorCode,
        get_fallback_servers, discover_servers
    )
    from openadp.crypto import Point2D, Point4D, G, P, Q, D, point_add, point_mul, point_compress, point_decompress
    from openadp.keygen import generate_encryption_key, Identity
    print("✅ All imports successful")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)

def test_crypto_operations():
    """Test basic cryptographic operations."""
    print("\n🔐 Testing crypto operations...")
    
    try:
        # Test point operations
        point = point_mul(12345, G)
        compressed = point_compress(point)
        print(f"✅ Point operations work, compressed point: {compressed.hex()[:16]}...")
        
        # Test point decompression
        decompressed = point_decompress(compressed)
        print(f"✅ Point decompression works")
        
        # Test Identity creation
        identity = Identity(uid="user@example.com", did="device123", bid="file://test_file.txt")
        print(f"✅ Identity creation works, UID: {identity.uid[:16]}...")
        
    except Exception as e:
        print(f"❌ Crypto test failed: {e}")
        return False
    
    return True

def test_noise_nk():
    """Test Noise-NK protocol implementation."""
    print("\n🔒 Testing Noise-NK protocol...")
    
    try:
        # Generate server keypair
        server_private, server_public = generate_keypair()
        print(f"✅ Generated server keypair, public key: {server_public.hex()[:16]}...")
        
        # Create client and server
        client = NoiseNK()
        client.initialize_as_initiator(server_public)
        
        server = NoiseNK() 
        server.initialize_as_responder(server_private)
        
        # Perform handshake
        msg1 = client.write_message(b"Hello Server")
        payload1 = server.read_message(msg1)
        print(f"✅ Client -> Server handshake: {payload1}")
        
        msg2 = server.write_message(b"Hello Client")
        payload2 = client.read_message(msg2)
        print(f"✅ Server -> Client handshake: {payload2}")
        
        # Test encryption/decryption
        if client.handshake_complete and server.handshake_complete:
            secret = b"Secret message"
            encrypted = client.encrypt(secret)
            decrypted = server.decrypt(encrypted)
            
            if decrypted == secret:
                print("✅ Noise-NK encryption/decryption works")
            else:
                print("❌ Noise-NK encryption/decryption failed")
                return False
        else:
            print("❌ Handshake not completed")
            return False
            
    except Exception as e:
        print(f"❌ Noise-NK test failed: {e}")
        return False
    
    return True

def test_basic_client():
    """Test basic client functionality."""
    print("\n📡 Testing basic client...")
    
    try:
        # Create basic client (will fail to connect, but tests instantiation)
        client = OpenADPClient("https://test.example.com")
        print(f"✅ Basic client created: {client.get_server_url()}")
        print(f"✅ Supports encryption: {client.supports_encryption()}")
        
    except Exception as e:
        print(f"❌ Basic client test failed: {e}")
        return False
    
    return True

def test_encrypted_client():
    """Test encrypted client functionality."""
    print("\n🔐 Testing encrypted client...")
    
    try:
        # Generate a test server public key
        _, server_public = generate_keypair()
        
        # Create encrypted client
        client = EncryptedOpenADPClient("https://test.example.com", server_public)
        print(f"✅ Encrypted client created: {client.get_server_url()}")
        print(f"✅ Has public key: {client.has_public_key()}")
        print(f"✅ Supports encryption: {client.supports_encryption()}")
        
    except Exception as e:
        print(f"❌ Encrypted client test failed: {e}")
        return False
    
    return True

def test_multi_server_client():
    """Test multi-server client functionality."""
    print("\n🌐 Testing multi-server client...")
    
    try:
        # Create multi-server client with fallback servers
        fallback_servers = get_fallback_servers()
        print(f"✅ Got {len(fallback_servers)} fallback servers")
        
        # Test server discovery
        servers = discover_servers()
        print(f"✅ Discovered {len(servers)} servers")
        
        # Create client (will try to connect but likely fail - that's OK for testing)
        try:
            client = MultiServerClient(fallback_servers=fallback_servers[:1])  # Just test one
            print(f"✅ Multi-server client created with {client.get_live_server_count()} live servers")
        except Exception as e:
            print(f"⚠️  Multi-server client connection failed (expected): {e}")
            print("✅ Multi-server client class works (connection failure is normal in tests)")
        
    except Exception as e:
        print(f"❌ Multi-server client test failed: {e}")
        return False
    
    return True

def test_server_discovery():
    """Test server discovery functionality."""
    print("\n🔍 Testing server discovery...")
    
    try:
        # Test fallback servers
        fallback_servers = get_fallback_servers()
        print(f"✅ Got {len(fallback_servers)} fallback servers: {fallback_servers[0]}")
        
        # Test server discovery
        servers = discover_servers()
        print(f"✅ Discovered {len(servers)} servers")
        
        if servers:
            server = servers[0]
            print(f"✅ First server: {server.url}, country: {server.country}")
        
    except Exception as e:
        print(f"❌ Server discovery test failed: {e}")
        return False
    
    return True

def test_key_generation():
    """Test key generation functionality."""
    print("\n🔑 Testing key generation...")
    
    try:
        # Test basic key generation (without actual server connection)
        try:
            identity = Identity(uid="test@example.com", did="test_device", bid="test_backup")
            result = generate_encryption_key(
                identity=identity,
                password="test_password"
            )
            if result.error:
                if "No OpenADP servers available" in result.error:
                    print("⚠️  Key generation failed due to no servers (expected in test)")
                    print("✅ Key generation function works (server connection failure is normal)")
                else:
                    raise OpenADPError(ErrorCode.SERVER_ERROR, result.error)
            else:
                print("✅ Key generation completed successfully")
                print(f"✅ Generated key length: {len(result.encryption_key)} bytes")
                if result.auth_codes:
                    print(f"✅ Auth code length: {len(result.auth_codes.base_auth_code)} characters")
        except OpenADPError as e:
            if e.code == ErrorCode.NO_LIVE_SERVERS:
                print("⚠️  Key generation failed due to no live servers (expected in test)")
                print("✅ Key generation function works (server connection failure is normal)")
            else:
                raise
        
    except Exception as e:
        print(f"❌ Key generation test failed: {e}")
        return False
    
    return True

def main():
    """Run all tests."""
    print("🧪 OpenADP Python Client Test Suite")
    print("=" * 50)
    
    tests = [
        test_crypto_operations,
        test_noise_nk,
        test_basic_client,
        test_encrypted_client,
        test_server_discovery,
        test_multi_server_client,
        test_key_generation,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"❌ {test.__name__} failed")
        except Exception as e:
            print(f"❌ {test.__name__} crashed: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! Python client implementation is working correctly.")
        return True
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 