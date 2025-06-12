#!/usr/bin/env python3
"""
Simple Noise-NK Demo

This demonstrates how easy it is to use the NoiseNK class for secure communication.
"""

from noise_nk import NoiseNK, generate_keypair

def main():
    print("🔐 Simple Noise-NK Demo\n")
    
    # Step 1: Generate keypair for responder only (NK pattern)
    print("1. Generating keypair...")
    bob_key = generate_keypair()
    
    print(f"   Bob's public key:   {bob_key.public.data.hex()[:32]}...")
    
    # Step 2: Initialize secure endpoints (only initiator knows responder's public key)
    print("\n2. Setting up secure communication channels...")
    alice = NoiseNK(role='initiator', remote_static_key=bob_key.public)
    bob = NoiseNK(role='responder', local_static_key=bob_key)
    
    # Step 3: Perform handshake
    print("\n3. Performing secure handshake...")
    
    # Alice initiates
    msg1 = alice.write_handshake_message(b"Hi Bob!")
    payload1 = bob.read_handshake_message(msg1)
    print(f"   Alice -> Bob: '{payload1.decode()}'")
    
    # Bob responds
    msg2 = bob.write_handshake_message(b"Hi Alice!")
    payload2 = alice.read_handshake_message(msg2)
    print(f"   Bob -> Alice: '{payload2.decode()}'")
    
    print("   ✅ Handshake complete! Secure channel established.")
    
    # Step 4: Exchange encrypted messages
    print("\n4. Secure messaging...")
    
    # Alice sends a secret
    secret = b"The treasure is buried under the old oak tree."
    encrypted = alice.encrypt(secret)
    decrypted = bob.decrypt(encrypted)
    print(f"   Alice -> Bob: '{decrypted.decode()}'")
    
    # Bob replies
    reply = b"Got it! I'll meet you there at midnight."
    encrypted_reply = bob.encrypt(reply)
    decrypted_reply = alice.decrypt(encrypted_reply)
    print(f"   Bob -> Alice: '{decrypted_reply.decode()}'")
    
    print("\n🎉 Secure communication successful!")
    print(f"📋 Session info:")
    print(f"   • Handshake hash: {alice.get_handshake_hash().hex()[:32]}...")
    print(f"   • Crypto: X25519 + AESGCM + SHA256")
    print(f"   • Security: Server authentication + Forward secrecy")

if __name__ == "__main__":
    main() 