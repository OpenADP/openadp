#!/usr/bin/env python3
"""Test registration with unique BIDs for each server to debug share distribution."""

import crypto
import sharing
import secrets
from client import Client

def test_unique_bids():
    """Test registering shares with unique BIDs to each server."""
    
    # Generate shares
    secret = secrets.randbelow(crypto.q)
    shares = sharing.make_random_shares(secret, 2, 2)
    
    print(f"Generated shares: {shares}")
    
    # Test parameters
    uid = "test_unique@example.com"
    did = "test_device"
    version = 1
    max_guesses = 10
    expiration = 0
    
    # Initialize client
    client = Client()
    if client.get_live_server_count() == 0:
        print("❌ No live servers available")
        return
    
    print(f"Using {client.get_live_server_count()} live servers")
    
    # Register each share to a specific server with unique BID
    for i, (x, y) in enumerate(shares):
        if i >= len(client.live_servers):
            break
            
        server_client = client.live_servers[i]
        bid = f"unique_test_bid_server_{i+1}"  # Unique BID for each server
        y_str = str(y)
        
        print(f"\nRegistering to server {i+1}: {server_client.server_url}")
        print(f"  BID: {bid}")
        print(f"  X value: {x}")
        
        try:
            result, error = server_client.register_secret(uid, did, bid, version, x, y_str, max_guesses, expiration)
            
            if error:
                print(f"  ❌ Registration failed: {error}")
            elif not result:
                print(f"  ❌ Registration returned false")
            else:
                print(f"  ✅ Registration successful")
                
        except Exception as e:
            print(f"  ❌ Exception: {str(e)}")
    
    # Now check what each server has
    print("\nChecking what each server stored...")
    
    for i, server_client in enumerate(client.live_servers):
        print(f"\n--- Server {i+1}: {server_client.server_url} ---")
        
        backups, error = server_client.list_backups(uid)
        if error:
            print(f"❌ List backups failed: {error}")
            continue
            
        print(f"Backups:")
        for backup in backups:
            print(f"  {backup}")
        
        # Try to recover from this server's unique BID
        bid = f"unique_test_bid_server_{i+1}"
        
        # Create B point for recovery
        pin = b'\x12\x34'
        U = crypto.H(uid.encode(), did.encode(), bid.encode(), pin)
        p = crypto.q
        r = secrets.randbelow(p - 1) + 1
        B = crypto.point_mul(r, U)
        
        try:
            result, error = server_client.recover_secret(uid, did, bid, crypto.unexpand(B), 0)
            
            if error:
                print(f"  ❌ Recovery failed: {error}")
            else:
                version, x, si_b, num_guesses, max_guesses, expiration = result
                print(f"  ✅ Recovery successful - X value: {x}")
                
        except Exception as e:
            print(f"  ❌ Recovery exception: {e}")

if __name__ == "__main__":
    test_unique_bids() 