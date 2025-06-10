#!/usr/bin/env python3
"""Debug what shares are actually stored on each server."""

import crypto
import secrets
from client import Client
from jsonrpc_client import OpenADPClient

def debug_individual_servers():
    """Check what each individual server has stored."""
    
    servers = ["https://sky.openadp.org", "https://xyzzybill.openadp.org"]
    uid = "waywardgeek@beast"
    did = "beast"
    bid = "file://test_document.txt"
    
    print("Checking individual servers...")
    
    for i, server_url in enumerate(servers):
        print(f"\n--- Server {i+1}: {server_url} ---")
        
        client = OpenADPClient(server_url)
        
        # Check backups
        backups, error = client.list_backups(uid)
        if error:
            print(f"❌ List backups failed: {error}")
            continue
            
        print(f"Backups on this server:")
        for backup in backups:
            print(f"  {backup}")
        
        # Try recovery to see what x value we get
        pin = b'\x12\x34'  # Test PIN  
        U = crypto.H(uid.encode(), did.encode(), bid.encode(), pin)
        p = crypto.q
        r = secrets.randbelow(p - 1) + 1
        B = crypto.point_mul(r, U)
        
        result, error = client.recover_secret(uid, did, bid, crypto.unexpand(B), 0)
        
        if error:
            print(f"❌ Recovery failed: {error}")
        else:
            version, x, si_b, num_guesses, max_guesses, expiration = result
            print(f"✅ Recovery successful - X value: {x}")

if __name__ == "__main__":
    debug_individual_servers() 