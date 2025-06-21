#!/usr/bin/env python3
"""
Simplified deterministic Noise-NK test that just shows handshake message bytes.
This allows direct comparison with Go implementation.
"""

import os
import sys

# Add the parent directory to the path so we can import openadp
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from noise.connection import NoiseConnection, Keypair


def test_deterministic_handshake_message():
    """Test deterministic Noise-NK handshake message creation."""
    
    print("🔐 Deterministic Noise-NK Handshake Message Test")
    print("=" * 55)
    
    # Fixed keys for deterministic testing (32 bytes each)
    # These should match the Go implementation exactly
    server_static_private = bytes.fromhex("7bb864b489efa3b78c2c63e98cb1c0b4c4b0e8e1e1f3e4d4c1b0a9d8c7b6a5b4")
    server_static_public = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    
    # In NK pattern, both client and server have ephemeral keys
    client_ephemeral_private = bytes.fromhex("a1b2c3d4e5f67890123456789012345678901234567890123456789012345678")
    
    print(f"Server static private: {server_static_private.hex()}")
    print(f"Server static public:  {server_static_public.hex()}")
    print(f"Client ephemeral private: {client_ephemeral_private.hex()}")
    print()
    
    # Test payload
    client_payload = b"Hello from client"
    
    # Create client (initiator)
    print("🔧 Creating client (initiator)...")
    client_noise = NoiseConnection.from_name(b'Noise_NK_25519_AESGCM_SHA256')
    client_noise.set_as_initiator()
    client_noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, server_static_public)
    # Set client ephemeral key BEFORE starting handshake
    client_noise.set_keypair_from_private_bytes(Keypair.EPHEMERAL, client_ephemeral_private)
    client_noise.start_handshake()
    
    print("✅ Client initialized")
    print()
    
    # Step 1: Client creates handshake message
    print("📤 Step 1: Client creates handshake message...")
    handshake_msg1 = client_noise.write_message(client_payload)
    print(f"   Client handshake message ({len(handshake_msg1)} bytes):")
    print(f"   {handshake_msg1.hex()}")
    print(f"   Client payload: {client_payload}")
    print()
    
    # Break down the message structure for analysis
    print("📋 Message Structure Analysis:")
    print("   NK pattern first message: -> e, es")
    print("   Expected: [ephemeral_key(32)] + [encrypted_payload(?)]")
    
    if len(handshake_msg1) >= 32:
        ephemeral_key = handshake_msg1[:32]
        encrypted_payload = handshake_msg1[32:]
        print(f"   Ephemeral key (32 bytes): {ephemeral_key.hex()}")
        print(f"   Encrypted payload ({len(encrypted_payload)} bytes): {encrypted_payload.hex()}")
    else:
        print(f"   ⚠️  Message too short: {len(handshake_msg1)} bytes")
    
    return True


if __name__ == "__main__":
    success = test_deterministic_handshake_message()
    if success:
        print("\n🎉 Test completed!")
        sys.exit(0)
    else:
        print("\n💥 Test failed!")
        sys.exit(1) 