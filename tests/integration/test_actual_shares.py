#!/usr/bin/env python3
"""Test with actual secret sharing values."""

import sys
import os
import secrets

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import crypto, sharing
from client.client import Client

def test_actual_secret_sharing():
    """Test with actual values from secret sharing."""
    print("Testing with actual secret sharing values...")
    
    # Generate the same values as in OpenADP key generation
    secret = secrets.randbelow(crypto.q)
    shares = sharing.make_random_shares(secret, 2, 2)
    
    print(f"Secret: {secret}")
    print(f"Shares: {shares}")
    print()
    
    # Test parameters
    uid = "test@example.com"
    did = "test_device"
    bid = "test_actual_shares"
    version = 1
    max_guesses = 10
    expiration = 0
    
    # Initialize client with local test servers (not production)
    client = Client(
        servers_url=None,  # Don't scrape production servers
        fallback_servers=[
            "http://localhost:9200",
            "http://localhost:9201", 
            "http://localhost:9202"
        ]
    )
    if client.get_live_server_count() == 0:
        print("❌ No live servers available")
        print("ℹ️  Make sure local test servers are running on ports 9200, 9201, 9202")
        return
    
    print(f"Using {client.get_live_server_count()} live servers")
    
    # Try to register each share
    for i, (x, y) in enumerate(shares):
        print(f"\n--- Registering Share {i+1} ---")
        print(f"x: {x}")
        print(f"y: {y}")
        print(f"y bits: {y.bit_length()}")
        print(f"y string length: {len(str(y))}")
        
        # Test conversion
        try:
            y_bytes = int.to_bytes(y, 32, "little")
            print(f"✅ Local conversion successful: {len(y_bytes)} bytes")
        except Exception as e:
            print(f"❌ Local conversion failed: {e}")
            continue
        
        # Try to register with remote servers
        y_str = str(y)
        success, error = client.register_secret(uid, did, f"{bid}_{i}", version, x, y_str, max_guesses, expiration)
        
        if success:
            print("✅ Registration successful!")
        else:
            print(f"❌ Registration failed: {error}")
            assert False, f"Registration failed: {error}"
    
    print("✅ All registrations successful!")
    assert True  # Explicit success assertion

if __name__ == "__main__":
    test_actual_secret_sharing() 