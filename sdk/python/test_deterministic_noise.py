#!/usr/bin/env python3
"""
Deterministic Noise-NK test for cross-language compatibility verification.
Uses fixed keys to eliminate all randomness and allow direct comparison with Go.
"""

import os
import sys
import binascii

# Add the parent directory to the path so we can import openadp
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from noise.connection import NoiseConnection, Keypair


def test_deterministic_noise_nk():
    """Test Noise-NK with deterministic keys for cross-language compatibility."""
    
    print("🔐 Testing Deterministic Noise-NK Protocol")
    print("=" * 50)
    
    # Fixed keys for deterministic testing (32 bytes each)
    # These should match the Go implementation exactly
    server_static_private = bytes.fromhex("7bb864b489efa3b78c2c63e98cb1c0b4c4b0e8e1e1f3e4d4c1b0a9d8c7b6a5b4")
    server_static_public = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    
    # In NK pattern, both client and server have ephemeral keys
    client_ephemeral_private = bytes.fromhex("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678")
    server_ephemeral_private = bytes.fromhex("b1c2d3e4f5a67890123456789012345678901234567890123456789012345678")
    
    print(f"Server static private: {server_static_private.hex()}")
    print(f"Server static public:  {server_static_public.hex()}")
    print(f"Client ephemeral private: {client_ephemeral_private.hex()}")
    print(f"Server ephemeral private: {server_ephemeral_private.hex()}")
    print()
    
    # Test payload
    client_payload = b"Hello from client"
    server_payload = b"Hello from server"
    
    # Create client (initiator)
    print("🔧 Creating client (initiator)...")
    client_noise = NoiseConnection.from_name(b'Noise_NK_25519_ChaChaPoly_SHA256')
    client_noise.set_as_initiator()
    client_noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, server_static_public)
    # Set client ephemeral key BEFORE starting handshake
    client_noise.set_keypair_from_private_bytes(Keypair.EPHEMERAL, client_ephemeral_private)
    client_noise.start_handshake()
    
    # Create server (responder)
    print("🔧 Creating server (responder)...")
    server_noise = NoiseConnection.from_name(b'Noise_NK_25519_ChaChaPoly_SHA256')
    server_noise.set_as_responder()
    server_noise.set_keypair_from_private_bytes(Keypair.STATIC, server_static_private)
    server_noise.start_handshake()
    
    print("✅ Both sides initialized")
    print()
    
    # Step 1: Client creates handshake message
    print("📤 Step 1: Client creates handshake message...")
    handshake_msg1 = client_noise.write_message(client_payload)
    print(f"   Client handshake message ({len(handshake_msg1)} bytes): {handshake_msg1.hex()}")
    print(f"   Client payload: {client_payload}")
    print()
    
    # Step 2: Server processes handshake message
    print("📥 Step 2: Server processes handshake message...")
    received_payload1 = server_noise.read_message(handshake_msg1)
    print(f"   Server received payload: {received_payload1}")
    print(f"   Payload matches: {received_payload1 == client_payload}")
    print()
    
    # Step 3: Server creates response message
    print("📤 Step 3: Server creates response message...")
    # In NK pattern, server generates ephemeral key in second message
    # We need to set it before write_message to make it deterministic
    server_noise.set_keypair_from_private_bytes(Keypair.EPHEMERAL, server_ephemeral_private)
    handshake_msg2 = server_noise.write_message(server_payload)
    print(f"   Server handshake message ({len(handshake_msg2)} bytes): {handshake_msg2.hex()}")
    print(f"   Server payload: {server_payload}")
    print()
    
    # Step 4: Client processes response message
    print("📥 Step 4: Client processes response message...")
    received_payload2 = client_noise.read_message(handshake_msg2)
    print(f"   Client received payload: {received_payload2}")
    print(f"   Payload matches: {received_payload2 == server_payload}")
    print()
    
    # Verify handshake completion
    print("🔒 Handshake completion status:")
    print(f"   Client handshake complete: {client_noise.handshake_finished}")
    print(f"   Server handshake complete: {server_noise.handshake_finished}")
    print()
    
    if client_noise.handshake_finished and server_noise.handshake_finished:
        print("✅ Handshake completed successfully!")
        
        # Test transport messages
        print("\n📨 Testing transport messages...")
        transport_msg = b"Secret transport message"
        
        # Client encrypts
        encrypted = client_noise.encrypt(transport_msg)
        print(f"   Encrypted message ({len(encrypted)} bytes): {encrypted.hex()}")
        
        # Server decrypts
        decrypted = server_noise.decrypt(encrypted)
        print(f"   Decrypted message: {decrypted}")
        print(f"   Transport message matches: {decrypted == transport_msg}")
        
        if decrypted == transport_msg:
            print("✅ Transport encryption/decryption successful!")
        else:
            print("❌ Transport encryption/decryption failed!")
            return False
    else:
        print("❌ Handshake failed!")
        return False
    
    return True


if __name__ == "__main__":
    success = test_deterministic_noise_nk()
    if success:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n💥 Tests failed!")
        sys.exit(1) 