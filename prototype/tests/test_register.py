#!/usr/bin/env python3
"""
Test script to debug the register_secret issue.
"""

import sys
import os
import base64

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from client.client import Client

def test_register():
    """Test registering a secret with known values."""
    
    # Test parameters
    uid = "test@example.com"
    did = "test_device"
    bid = "test_backup"
    version = 1
    x = 42
    max_guesses = 10
    expiration = 0
    
    # Create a test integer for y (within valid range)
    y_int = 123456789012345678901234567890
    y_str = str(y_int)
    
    print(f"x as integer: {x}")
    print(f"y as integer: {y_int}")
    print(f"y as string length: {len(y_str)}")
    print(f"y string: {y_str[:50]}..." if len(y_str) > 50 else f"y string: {y_str}")
    
    # Initialize client
    client = Client()
    if client.get_live_server_count() == 0:
        print("❌ No live servers available")
        return
    
    print(f"Using {client.get_live_server_count()} live servers")
    
    # Try to register
    success, error = client.register_secret(uid, did, bid, version, x, y_str, max_guesses, expiration)
    
    if success:
        print("✅ Registration successful!")
    else:
        print(f"❌ Registration failed: {error}")

if __name__ == "__main__":
    test_register() 