#!/usr/bin/env python3
"""
Test script for Python Noise-NK implementation

This script tests the Python Noise-NK implementation to ensure it works correctly
and matches the expected behavior.
"""

import sys
import os

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from openadp.client import NoiseNK, generate_keypair

def test_noise_nk_basic():
    """Test basic Noise-NK handshake and encryption."""
    print("🔒 Testing Python Noise-NK implementation...")
    
    # Generate server keypair
    server_private, server_public = generate_keypair()
    print(f"   Server public key: {server_public.hex()[:32]}...")
    
    # Create client (initiator) and server (responder)
    client = NoiseNK("initiator", None, server_public, b"")
    server = NoiseNK("responder", server_private, None, b"")
    
    print("   Created client and server instances")
    
    # Perform handshake
    print("   Performing handshake...")
    
    # Step 1: Client sends handshake message
    client_msg = client.write_handshake_message(b"Hello Server")
    print(f"   Client handshake message: {len(client_msg)} bytes")
    
    # Step 2: Server reads client message
    server_payload = server.read_handshake_message(client_msg)
    print(f"   Server received payload: {server_payload}")
    
    # Step 3: Server sends response
    server_msg = server.write_handshake_message(b"Hello Client")
    print(f"   Server handshake message: {len(server_msg)} bytes")
    
    # Step 4: Client reads server response
    client_payload = client.read_handshake_message(server_msg)
    print(f"   Client received payload: {client_payload}")
    
    # Verify handshake completion
    if not client.is_handshake_complete():
        raise Exception("Client handshake not complete")
    if not server.is_handshake_complete():
        raise Exception("Server handshake not complete")
    
    print("   ✅ Handshake completed successfully")
    
    # Test encryption/decryption
    print("   Testing post-handshake encryption...")
    
    plaintext = b"Secret message from client to server"
    encrypted = client.encrypt(plaintext)
    decrypted = server.decrypt(encrypted)
    
    if decrypted != plaintext:
        raise Exception(f"Decryption failed: {decrypted} != {plaintext}")
    
    print(f"   ✅ Client->Server encryption: {len(plaintext)} -> {len(encrypted)} -> {len(decrypted)} bytes")
    
    # Test reverse direction
    plaintext2 = b"Secret response from server to client"
    encrypted2 = server.encrypt(plaintext2)
    decrypted2 = client.decrypt(encrypted2)
    
    if decrypted2 != plaintext2:
        raise Exception(f"Reverse decryption failed: {decrypted2} != {plaintext2}")
    
    print(f"   ✅ Server->Client encryption: {len(plaintext2)} -> {len(encrypted2)} -> {len(decrypted2)} bytes")
    
    # Test handshake hash
    client_hash = client.get_handshake_hash()
    server_hash = server.get_handshake_hash()
    
    if client_hash != server_hash:
        raise Exception("Handshake hashes don't match")
    
    print(f"   ✅ Handshake hash: {client_hash.hex()[:32]}...")
    
    print("🎉 All Noise-NK tests passed!")

def test_noise_nk_empty_payloads():
    """Test Noise-NK with empty payloads."""
    print("🔒 Testing Noise-NK with empty payloads...")
    
    # Generate server keypair
    server_private, server_public = generate_keypair()
    
    # Create client and server
    client = NoiseNK("initiator", None, server_public, b"")
    server = NoiseNK("responder", server_private, None, b"")
    
    # Handshake with empty payloads
    client_msg = client.write_handshake_message(b"")
    server_payload = server.read_handshake_message(client_msg)
    server_msg = server.write_handshake_message(b"")
    client_payload = client.read_handshake_message(server_msg)
    
    if server_payload != b"" or client_payload != b"":
        raise Exception("Empty payloads not preserved")
    
    print("   ✅ Empty payloads handled correctly")

def main():
    """Run all tests."""
    try:
        test_noise_nk_basic()
        test_noise_nk_empty_payloads()
        print("\n🎉 All tests passed! Python Noise-NK implementation is working correctly.")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 