#!/usr/bin/env python3
"""Debug the registration process to understand the x value issue."""

import crypto
import sharing
import secrets
from client import Client

def debug_registration():
    """Debug the registration process step by step."""
    
    # Generate shares like in the real code
    secret = secrets.randbelow(crypto.q)
    shares = sharing.make_random_shares(secret, 2, 2)
    
    print(f"Generated shares: {shares}")
    
    # Test parameters
    uid = "test_debug@example.com"
    did = "test_device"
    bid = "test_registration_debug"
    version = 1
    max_guesses = 10
    expiration = 0
    
    # Initialize client
    client = Client()
    if client.get_live_server_count() == 0:
        print("❌ No live servers available")
        return
    
    print(f"Using {client.get_live_server_count()} live servers")
    print(f"Server URLs: {[s.server_url for s in client.live_servers]}")
    
    # Register shares with servers - debug version
    for i, (x, y) in enumerate(shares):
        if i >= len(client.live_servers):
            print(f"Skipping share {x} - more shares than servers")
            break
            
        server_url = client.live_servers[i].server_url
        y_str = str(y)
        
        print(f"\nRegistering share {i+1}:")
        print(f"  Server: {server_url}")
        print(f"  X value: {x}")
        print(f"  Y length: {len(y_str)}")
        
        success, error = client.register_secret(uid, did, f"{bid}_{i}", version, x, y_str, max_guesses, expiration)
        
        if success:
            print(f"  ✅ Registration successful")
        else:
            print(f"  ❌ Registration failed: {error}")
    
    print("\nChecking what was actually stored...")
    
    # Check what each server has
    for i, server_client in enumerate(client.live_servers):
        print(f"\n--- Server {i+1}: {server_client.server_url} ---")
        
        backups, error = server_client.list_backups(uid)
        if error:
            print(f"❌ List backups failed: {error}")
            continue
            
        print(f"Backups on this server:")
        for backup in backups:
            print(f"  {backup}")

if __name__ == "__main__":
    debug_registration() 