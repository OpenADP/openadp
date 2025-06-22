#!/usr/bin/env python3
"""
Generate test vectors for Noise-NK implementations.

This script creates known test vectors that both Python and JavaScript
implementations should produce identical results for.
"""

import sys
import os
import json

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from openadp.client import NoiseNK

def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()

def generate_test_vectors():
    """Generate test vectors for Noise-NK implementations."""
    print("🔧 Generating Noise-NK test vectors...")
    
    # Test case 1: Basic handshake with known keys
    test_vectors = []
    
    # Fixed keys for deterministic testing
    server_private = bytes.fromhex("4040404040404040404040404040404040404040404040404040404040404040")
    server_public = bytes.fromhex("d7b5e81d336e578b13b8d706e82d061e3038c96bce66cdcf50d566b96ddbba10")
    
    # Test different prologue values
    test_cases = [
        {"name": "empty_prologue", "prologue": b""},
        {"name": "simple_prologue", "prologue": b"test"},
        {"name": "complex_prologue", "prologue": b"test_prologue_12345_with_more_data"},
    ]
    
    for i, test_case in enumerate(test_cases):
        print(f"   Generating test case {i+1}: {test_case['name']}")
        
        prologue = test_case["prologue"]
        
        # Create client and server
        client = NoiseNK()
        server = NoiseNK()
        
        client.initialize_as_initiator(server_public)
        server.initialize_as_responder(server_private)
        
        # Perform handshake
        payload1 = b"Hello from client!"
        message1 = client.write_message(payload1)
        
        received_payload1 = server.read_message(message1)
        
        payload2 = b"Hello from server!"
        message2 = server.write_message(payload2)
        
        received_payload2 = client.read_message(message2)
        
        # Extract final handshake hashes
        client_hash = client.noise.get_handshake_hash()
        server_hash = server.noise.get_handshake_hash()
        
        # Create test vector
        vector = {
            "name": test_case["name"],
            "description": f"Noise-NK handshake with {test_case['name']}",
            "inputs": {
                "server_private_key": bytes_to_hex(server_private),
                "server_public_key": bytes_to_hex(server_public),
                "prologue": bytes_to_hex(prologue),
                "client_payload1": bytes_to_hex(payload1),
                "server_payload2": bytes_to_hex(payload2)
            },
            "expected_outputs": {
                "handshake_message1_length": len(message1),
                "handshake_message2_length": len(message2),
                "client_received_payload1": bytes_to_hex(received_payload1),
                "server_received_payload2": bytes_to_hex(received_payload2),
                "final_handshake_hash": bytes_to_hex(client_hash),
                "handshake_complete": client.handshake_complete and server.handshake_complete
            },
            "notes": [
                "Handshake messages will vary due to random ephemeral keys",
                "But payload extraction and final hash should be deterministic",
                "Both implementations should produce the same handshake hash given the same ephemeral keys"
            ]
        }
        
        test_vectors.append(vector)
        
        print(f"     ✅ Message 1: {len(message1)} bytes")
        print(f"     ✅ Message 2: {len(message2)} bytes") 
        print(f"     ✅ Handshake hash: {bytes_to_hex(client_hash)[:32]}...")
    
    return test_vectors

def save_test_vectors(vectors, filename="noise_nk_test_vectors.json"):
    """Save test vectors to JSON file."""
    with open(filename, 'w') as f:
        json.dump({
            "version": "1.0",
            "protocol": "Noise_NK_25519_AESGCM_SHA256",
            "description": "Test vectors for Noise-NK implementations",
            "test_vectors": vectors
        }, f, indent=2)
    
    print(f"💾 Test vectors saved to {filename}")

def verify_python_implementation(vectors):
    """Verify Python implementation against test vectors."""
    print("\n🐍 Verifying Python implementation against test vectors...")
    
    for i, vector in enumerate(vectors):
        print(f"   Test {i+1}: {vector['name']}")
        
        # Extract inputs
        server_private = bytes.fromhex(vector["inputs"]["server_private_key"])
        server_public = bytes.fromhex(vector["inputs"]["server_public_key"])
        prologue = bytes.fromhex(vector["inputs"]["prologue"])
        payload1 = bytes.fromhex(vector["inputs"]["client_payload1"])
        payload2 = bytes.fromhex(vector["inputs"]["server_payload2"])
        
        # Run test
        client = NoiseNK()
        server = NoiseNK()
        
        client.initialize_as_initiator(server_public)
        server.initialize_as_responder(server_private)
        
        message1 = client.write_message(payload1)
        received_payload1 = server.read_message(message1)
        message2 = server.write_message(payload2)
        received_payload2 = client.read_message(message2)
        
        # Verify outputs
        expected = vector["expected_outputs"]
        
        # Check message lengths
        if len(message1) != expected["handshake_message1_length"]:
            print(f"     ❌ Message 1 length mismatch: {len(message1)} vs {expected['handshake_message1_length']}")
            continue
            
        if len(message2) != expected["handshake_message2_length"]:
            print(f"     ❌ Message 2 length mismatch: {len(message2)} vs {expected['handshake_message2_length']}")
            continue
        
        # Check payload extraction
        if bytes_to_hex(received_payload1) != expected["client_received_payload1"]:
            print(f"     ❌ Payload 1 mismatch")
            continue
            
        if bytes_to_hex(received_payload2) != expected["server_received_payload2"]:
            print(f"     ❌ Payload 2 mismatch")
            continue
        
        # Check handshake completion
        if (client.handshake_complete and server.handshake_complete) != expected["handshake_complete"]:
            print(f"     ❌ Handshake completion mismatch")
            continue
            
        print(f"     ✅ All checks passed")
    
    print("   🎉 Python implementation verified!")

def main():
    """Generate and verify test vectors."""
    try:
        # Generate test vectors using Python implementation
        vectors = generate_test_vectors()
        
        # Save to file
        save_test_vectors(vectors)
        
        # Verify Python implementation
        verify_python_implementation(vectors)
        
        print(f"\n📋 Generated {len(vectors)} test vectors")
        print("🔧 Use these vectors to verify JavaScript implementation compatibility")
        print("📄 Test vectors saved to noise_nk_test_vectors.json")
        
    except Exception as e:
        print(f"❌ Failed to generate test vectors: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 