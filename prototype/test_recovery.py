#!/usr/bin/env python3
"""Test just the recovery logic to debug the issue."""

import crypto
import secrets
from client import Client

def test_recovery():
    """Test the recovery process."""
    
    # Test parameters
    uid = "waywardgeek@beast"
    did = "beast"
    bid = "file://test_document.txt"
    
    print(f"Testing recovery for UID={uid}, DID={did}, BID={bid}")
    
    # Initialize client
    client = Client()
    if client.get_live_server_count() == 0:
        print("❌ No live servers available")
        return
    
    print(f"Using {client.get_live_server_count()} live servers")
    
    # Check backups
    print("\n--- Listing backups ---")
    backups, error = client.list_backups(uid)
    if error:
        print(f"❌ List backups failed: {error}")
        return
    
    print(f"Found {len(backups)} backups:")
    for i, backup in enumerate(backups):
        print(f"  Backup {i}: {backup}")
        if len(backup) >= 4:
            backup_bid = backup[1]
            num_guesses = backup[3]
            print(f"    BID: {backup_bid}, num_guesses: {num_guesses}")
    
    # Find our backup
    guess_num = 0
    found_backup = False
    for backup in backups:
        if len(backup) > 1:
            backup_bid = backup[1]
            if backup_bid == bid:
                guess_num = backup[3] if len(backup) > 3 else 0
                found_backup = True
                print(f"✅ Found matching backup: {backup}")
                print(f"    Current guess_num: {guess_num}")
                break
    
    if not found_backup:
        print(f"❌ No backup found for BID: {bid}")
        return
    
    # Test recovery from one server
    print("\n--- Testing recovery from first server ---")
    
    # Create B point for recovery
    pin = b'\x12\x34'  # Test PIN
    U = crypto.H(uid.encode(), did.encode(), bid.encode(), pin)
    p = crypto.q
    r = secrets.randbelow(p - 1) + 1
    B = crypto.point_mul(r, U)
    
    try:
        result, error = client.recover_secret(uid, did, bid, crypto.unexpand(B), guess_num)
        
        if error:
            print(f"❌ Recovery failed: {error}")
        else:
            print(f"✅ Recovery successful: {result}")
            
    except Exception as e:
        print(f"❌ Exception during recovery: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_recovery() 