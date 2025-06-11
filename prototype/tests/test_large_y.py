#!/usr/bin/env python3
"""Test different y value sizes to understand remote server limits."""

import base64
from client import Client

def test_y_size(y_int, description):
    """Test registering with a specific y value."""
    print(f"\n--- Testing {description} ---")
    
    # Test parameters
    uid = "test@example.com"
    did = "test_device"
    bid = f"test_backup_{description.replace(' ', '_')}"
    version = 1
    x = 42
    max_guesses = 10
    expiration = 0
    
    y_str = str(y_int)
    print(f"Y integer: {y_int}")
    print(f"Y string length: {len(y_str)}")
    print(f"Y bits: {y_int.bit_length()}")
    print(f"Y bytes needed: {(y_int.bit_length() + 7) // 8}")
    
    # Initialize client
    client = Client()
    if client.get_live_server_count() == 0:
        print("❌ No live servers available")
        return False
    
    # Try to register
    success, error = client.register_secret(uid, did, bid, version, x, y_str, max_guesses, expiration)
    
    if success:
        print("✅ Registration successful!")
        return True
    else:
        print(f"❌ Registration failed: {error}")
        return False

if __name__ == "__main__":
    # Test various sizes
    test_cases = [
        (123456789, "small integer"),
        (2**32 - 1, "32-bit max"),
        (2**64 - 1, "64-bit max"),
        (2**128 - 1, "128-bit max"),
        (2**200 - 1, "200-bit max"),
        (2**252 - 1, "252-bit max (close to crypto.q)"),
    ]
    
    for y_int, description in test_cases:
        try:
            success = test_y_size(y_int, description)
            if not success:
                break
        except Exception as e:
            print(f"❌ Exception during {description}: {e}")
            break 