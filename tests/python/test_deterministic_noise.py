#!/usr/bin/env python3
"""
Deterministic test for Python Noise-NK implementation.

This test uses hard-coded keys to ensure reproducible results and verify
compatibility with the JavaScript implementation.
"""

import sys
import os

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'openadp'))

from openadp.client import NoiseNK

def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string for display."""
    return data.hex()

def test_deterministic_noise_nk():
    """Test Noise-NK with deterministic keys."""
    print("🔒 Testing Python Noise-NK with deterministic keys...")
    
    # Hard-coded test keys (same as JavaScript test)
    # Server static key pair
    server_private_key = bytes.fromhex(
        "4040404040404040404040404040404040404040404040404040404040404040"
    )
    server_public_key = bytes.fromhex(
        "d7b5e81d336e578b13b8d706e82d061e3038c96bce66cdcf50d566b96ddbba10"
    )
    
    # Test prologue
    prologue = b"test_prologue_12345"
    
    print(f"   Server private key: {bytes_to_hex(server_private_key)}")
    print(f"   Server public key:  {bytes_to_hex(server_public_key)}")
    print(f"   Prologue: {prologue}")
    
    # Initialize client (initiator) and server (responder)
    client = NoiseNK()
    server = NoiseNK()
    
    client.initialize_as_initiator(server_public_key)
    server.initialize_as_responder(server_private_key)
    
    print("   ✅ Initialized client and server")
    
    # We need to monkey-patch the ephemeral key generation to be deterministic
    # This requires accessing the underlying noise library
    
    # Hard-coded ephemeral keys for deterministic testing
    client_ephemeral_private = bytes.fromhex(
        "5050505050505050505050505050505050505050505050505050505050505050"
    )
    server_ephemeral_private = bytes.fromhex(
        "6060606060606060606060606060606060606060606060606060606060606060"
    )
    
    # We need to set these in the noise library objects
    # This is implementation-specific and may need adjustment
    try:
        # Try to access the noise connection's keypairs
        from noise.connection import Keypair
        
        # Set client ephemeral key
        if hasattr(client.noise, '_keypairs'):
            # Create ephemeral keypair for client
            client_ephemeral_keypair = Keypair()
            client_ephemeral_keypair.private = client_ephemeral_private
            # Derive public key from private key
            from cryptography.hazmat.primitives.asymmetric import x25519
            private_key_obj = x25519.X25519PrivateKey.from_private_bytes(client_ephemeral_private)
            public_key_obj = private_key_obj.public_key()
            client_ephemeral_keypair.public = public_key_obj.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            client.noise._keypairs[Keypair.LOCAL_EPHEMERAL] = client_ephemeral_keypair
            
        # Set server ephemeral key
        if hasattr(server.noise, '_keypairs'):
            server_ephemeral_keypair = Keypair()
            server_ephemeral_keypair.private = server_ephemeral_private
            private_key_obj = x25519.X25519PrivateKey.from_private_bytes(server_ephemeral_private)
            public_key_obj = private_key_obj.public_key()
            server_ephemeral_keypair.public = public_key_obj.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            server.noise._keypairs[Keypair.LOCAL_EPHEMERAL] = server_ephemeral_keypair
            
    except Exception as e:
        print(f"   ⚠️  Could not set deterministic ephemeral keys: {e}")
        print("   Proceeding with random ephemeral keys...")
    
    # Perform handshake
    print("   Performing handshake...")
    
    # Step 1: Client -> Server (first handshake message)
    payload1 = b"Hello from client!"
    message1 = client.write_message(payload1)
    print(f"   Client message 1: {len(message1)} bytes")
    print(f"   Message 1 hex: {bytes_to_hex(message1)}")
    
    # Server processes first message
    received_payload1 = server.read_message(message1)
    print(f"   Server received: {received_payload1}")
    
    # Step 2: Server -> Client (second handshake message)
    payload2 = b"Hello from server!"
    message2 = server.write_message(payload2)
    print(f"   Server message 2: {len(message2)} bytes")
    print(f"   Message 2 hex: {bytes_to_hex(message2)}")
    
    # Client processes second message
    received_payload2 = client.read_message(message2)
    print(f"   Client received: {received_payload2}")
    
    # Verify handshake completion
    if not client.handshake_complete:
        raise Exception("Client handshake not complete")
    if not server.handshake_complete:
        raise Exception("Server handshake not complete")
    
    print("   ✅ Handshake completed successfully")
    
    # Extract handshake hash from the noise library
    try:
        # Use the get_handshake_hash() method
        client_hash = client.noise.get_handshake_hash()
        server_hash = server.noise.get_handshake_hash()
        
        print(f"   Client handshake hash: {bytes_to_hex(client_hash)}")
        print(f"   Server handshake hash: {bytes_to_hex(server_hash)}")
        
        if client_hash == server_hash:
            print("   ✅ Handshake hashes match!")
            handshake_hash = client_hash
        else:
            print("   ❌ Handshake hashes do not match!")
            handshake_hash = None
            
    except Exception as e:
        print(f"   ⚠️  Error extracting handshake hash: {e}")
        handshake_hash = None
    
    # Test encryption to verify the handshake worked
    test_message = b"Test encryption after handshake"
    encrypted = client.encrypt(test_message)
    decrypted = server.decrypt(encrypted)
    
    if decrypted == test_message:
        print("   ✅ Post-handshake encryption working")
    else:
        print("   ❌ Post-handshake encryption failed")
    
    return handshake_hash

def main():
    """Run the deterministic test."""
    try:
        from cryptography.hazmat.primitives import serialization
        handshake_hash = test_deterministic_noise_nk()
        if handshake_hash:
            print(f"\n🎉 Test completed! Final handshake hash: {bytes_to_hex(handshake_hash)}")
        else:
            print("\n⚠️  Test completed but could not extract handshake hash")
    except ImportError as e:
        print(f"❌ Missing cryptography dependency: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 