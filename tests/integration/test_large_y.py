#!/usr/bin/env python3
"""Test different y value sizes to understand remote server limits."""

import sys
import os
import base64
import pytest

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from client.client import Client

# Test cases as parameters
test_cases = [
    (123456789, "small integer"),
    (2**32 - 1, "32-bit max"),
    (2**64 - 1, "64-bit max"),
    (2**128 - 1, "128-bit max"),
    (2**200 - 1, "200-bit max"),
    (2**252 - 1, "252-bit max (close to crypto.q)"),
]

@pytest.mark.parametrize("y_int,description", test_cases)
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
        assert True  # Explicit success
    else:
        print(f"❌ Registration failed: {error}")
        assert False, f"Registration failed for {description}: {error}"

if __name__ == "__main__":
    # Run tests manually if called directly
    for y_int, description in test_cases:
        try:
            test_y_size(y_int, description)
            print(f"✅ {description} test passed")
        except Exception as e:
            print(f"❌ Exception during {description}: {e}")
            break 