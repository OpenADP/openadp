#!/usr/bin/env python3
"""
OpenADP Server Business Logic

This module contains the core business logic for the OpenADP (Open Asynchronous 
Distributed Password) system. It provides functions for:
- Registering secret shares
- Recovering secret shares 
- Listing user backups
- Input validation and security checks

This is a prototype implementation designed to clarify the system design
and work with both prototype and production clients.
"""

import time
from typing import Union, Tuple, List, Any

import sys
import os
import secrets

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from openadp import crypto
from openadp import database
from openadp import sharing


def check_register_inputs(uid: str, did: str, bid: str, x: int, y: bytes, 
                         max_guesses: int, expiration: int) -> Union[bool, Exception]:
    """
    Validate inputs for secret registration.
    
    Args:
        uid: User identifier
        did: Device identifier 
        bid: Backup identifier
        x: X coordinate for secret sharing
        y: Y coordinate (encrypted share) 
        max_guesses: Maximum number of recovery attempts allowed
        expiration: Expiration timestamp (0 for no expiration)
        
    Returns:
        True if inputs are valid, Exception with error message otherwise
    """
    MAX_LEN = 512
    
    if len(uid) > MAX_LEN:
        return Exception("UID too long")
    if len(did) > MAX_LEN:
        return Exception("DID too long")
    if len(bid) > MAX_LEN:
        return Exception("BID too long")
    if x > 1000:
        return Exception("Too many shares")
    if len(y) > 32:
        return Exception("Y share too large")
    if max_guesses > 1000:
        return Exception("Max guesses too high")
    
    seconds_since_epoch = int(time.time())
    # Allow 0 to represent no expiration
    print(f"DEBUG: expiration={expiration} (type={type(expiration)}), seconds_since_epoch={seconds_since_epoch} (type={type(seconds_since_epoch)})")
    if expiration < seconds_since_epoch and expiration != 0:
        return Exception("Expiration is in the past")
    
    return True


def register_secret(db: database.Database, uid: str, did: str, bid: str, 
                   version: int, x: int, y: bytes, max_guesses: int, 
                   expiration: int, owner_sub: str) -> Union[bool, Exception]:
    """
    Register a secret share with the server.
    
    Args:
        db: Database connection
        uid: User identifier
        did: Device identifier
        bid: Backup identifier
        version: Version number for this backup
        x: X coordinate for secret sharing
        y: Y coordinate (encrypted share)
        max_guesses: Maximum number of recovery attempts allowed
        expiration: Expiration timestamp (0 for no expiration)
        owner_sub: OAuth sub claim of the user registering this backup
        
    Returns:
        True if successful, Exception with error message otherwise
    """
    validation_result = check_register_inputs(uid, did, bid, x, y, max_guesses, expiration)
    if validation_result is not True:
        return validation_result
    
    # Convert string parameters to bytes for database storage
    uid_bytes = uid.encode('utf-8') if isinstance(uid, str) else uid
    did_bytes = did.encode('utf-8') if isinstance(did, str) else did
    bid_bytes = bid.encode('utf-8') if isinstance(bid, str) else bid
    
    # Check ownership before allowing registration/update
    if not db.check_ownership(uid_bytes, did_bytes, bid_bytes, owner_sub):
        return Exception(f"Access denied: User {owner_sub} does not own backup {uid}/{did}/{bid}")
    
    db.insert(uid_bytes, did_bytes, bid_bytes, version, x, y, 0, max_guesses, expiration, owner_sub)
    return True


def check_recover_inputs(uid: str, did: str, bid: str, b: Any) -> Union[bool, Exception]:
    """
    Validate inputs for secret recovery.
    
    Args:
        uid: User identifier
        did: Device identifier
        bid: Backup identifier
        b: Point B for cryptographic recovery
        
    Returns:
        True if inputs are valid, Exception with error message otherwise
    """
    MAX_LEN = 512
    
    if len(uid) > MAX_LEN:
        return Exception("UID too long")
    if len(did) > MAX_LEN:
        return Exception("DID too long")
    if len(bid) > MAX_LEN:
        return Exception("BID too long")
    if not crypto.point_valid(b):
        return Exception("Invalid point")
    
    return True


def recover_secret(db: database.Database, uid: str, did: str, bid: str, 
                  b: Any, guess_num: int, owner_sub: str) -> Union[Tuple[int, int, Any, int, int, int], Exception]:
    """
    Recover a secret share from the server.
    
    The guess_num parameter prevents accidental replay attacks by ensuring
    the counter only increments once per recovery attempt, making this RPC idempotent.
    
    Args:
        db: Database connection
        uid: User identifier
        did: Device identifier
        bid: Backup identifier
        b: Point B for cryptographic recovery
        guess_num: Expected current guess number (for idempotency)
        owner_sub: OAuth sub claim of the user requesting recovery
        
    Returns:
        Tuple of (version, x, siB, num_guesses, max_guesses, expiration) if successful,
        Exception with error message otherwise
    """
    try:
        validation_result = check_recover_inputs(uid, did, bid, b)
        if validation_result is not True:
            return validation_result
        
        # Convert string parameters to bytes for database lookup
        uid_bytes = uid.encode('utf-8') if isinstance(uid, str) else uid
        did_bytes = did.encode('utf-8') if isinstance(did, str) else did
        bid_bytes = bid.encode('utf-8') if isinstance(bid, str) else bid
        
        # Look up the stored share
        result = db.lookup(uid_bytes, did_bytes, bid_bytes)
        if result is None:
            return Exception("Share not found")
        
        # Debug: check result format
        print(f"DEBUG: Database lookup result: {result}, type: {type(result)}, length: {len(result)}")
        
        # Safely unpack the result (now with owner_sub at index 6)
        if len(result) != 7:
            return Exception(f"Invalid database result format: expected 7 fields, got {len(result)}")
        
        version, x, y, num_guesses, max_guesses, expiration, backup_owner = result
        
        # Check ownership - user must own this backup to recover it
        if backup_owner != owner_sub:
            return Exception(f"Access denied: User {owner_sub} does not own backup {uid}/{did}/{bid} (owned by {backup_owner})")
        
        # Debug: check field types
        print(f"DEBUG: version={version}, x={x}, y type={type(y)}, num_guesses={num_guesses}")
        
        # Verify expected guess number (for idempotency)
        if guess_num != num_guesses:
            return Exception(f"Expecting guess_num = {num_guesses}")
        
        # Check if too many guesses have been made
        if num_guesses >= max_guesses:
            return Exception("Too many guesses")
        
        # Increment guess counter (preserve ownership)
        num_guesses += 1
        db.insert(uid_bytes, did_bytes, bid_bytes, version, x, y, num_guesses, max_guesses, expiration, owner_sub)
        
        # Perform cryptographic recovery calculation
        y_int = int.from_bytes(y, "little")
        si_b = crypto.unexpand(crypto.point_mul(y_int, b))
        
        return (version, x, si_b, num_guesses, max_guesses, expiration)
        
    except Exception as e:
        print(f"DEBUG: Exception in recover_secret: {e}")
        import traceback
        traceback.print_exc()
        return Exception(f"Recovery failed: {str(e)}")


def list_backups(db: database.Database, uid: str, owner_sub: str) -> List[Tuple]:
    """
    List all backups for a user that they own.
    
    Args:
        db: Database connection
        uid: User identifier
        owner_sub: OAuth sub claim to filter by ownership
        
    Returns:
        List of tuples containing backup information:
        (did, bid, version, num_guesses, max_guesses, expiration, owner_sub)
    """
    # Convert string to bytes if needed for database query
    uid_bytes = uid.encode('utf-8') if isinstance(uid, str) else uid
    return db.list_backups(uid_bytes, owner_sub)


def main():
    """
    Test/demo function for the server functionality.
    
    This creates test data and demonstrates the complete flow of:
    1. Creating shares using secret sharing
    2. Registering shares with multiple servers
    3. Recovering shares from servers
    4. Reconstructing the original secret
    """
    # Test parameters
    uid = b"waywardgeek@gmail.com"
    did = b"Ubuntu beast Alienware laptop"
    bid = b"file://archive.tgz"
    
    # Generate random PIN
    pin_val = secrets.randbelow(10000)
    print("pin =", pin_val)
    pin = int.to_bytes(pin_val, 2, "little")
    
    # Cryptographic setup
    u = crypto.H(uid, did, bid, pin)
    print("U =", crypto.unexpand(u))
    
    p = crypto.q
    r = secrets.randbelow(p - 1) + 1
    r_inv = pow(r, -1, p)
    b = crypto.point_mul(r, u)
    s = secrets.randbelow(p)
    s_point = crypto.point_mul(s, u)
    print("S =", crypto.unexpand(s_point))
    
    enc_key = crypto.deriveEncKey(s_point)
    print("enc_key =", enc_key)
    
    # Create secret shares
    threshold = 2
    num_shares = 3
    shares = sharing.make_random_shares(s, threshold, num_shares)
    print("s =", s)
    print("shares =", shares)
    
    # Register shares with multiple servers
    for (x, y) in shares:
        y_enc = int.to_bytes(y, 32, "little")
        db_name = f"openadp_test{x}.db"
        db = database.Database(db_name)
        register_secret(db, uid.decode(), did.decode(), bid.decode(), 1, x, y_enc, 10, 10000000000, "owner_sub")
        
        # Simulate some random failed recovery attempts
        for guess_num in range(secrets.randbelow(10)):
            result = recover_secret(db, uid.decode(), did.decode(), bid.decode(), b, guess_num, "owner_sub")
    
    # Verify cryptographic relationship
    assert crypto.point_equal(u, crypto.point_mul(r_inv, b))
    print("B =", crypto.unexpand(b))
    
    # Recover shares from servers
    recovered_shares = []
    for x, _ in shares:
        db_name = f"openadp_test{x}.db"
        db = database.Database(db_name)
        guess_num = db.find_guess_number(uid, did, bid)
        result = recover_secret(db, uid.decode(), did.decode(), bid.decode(), b, guess_num, "owner_sub")
        
        assert not isinstance(result, Exception), f"Recovery failed: {result}"
        
        version, x, si_b, num_guesses, max_guesses, expiration = result
        print("siB =", si_b)
        recovered_shares.append((x, si_b))
    
    print("recovered_shares =", recovered_shares)
    
    # Reconstruct original secret using threshold of shares
    rec_sb = sharing.recover_sb([recovered_shares[0], recovered_shares[2]])
    rec_s = crypto.point_mul(r_inv, crypto.expand(rec_sb))
    print("recovered S =", crypto.unexpand(rec_s))
    
    # Verify reconstruction was successful
    assert crypto.point_equal(rec_s, s_point)
    rec_enc_key = crypto.deriveEncKey(rec_s)
    assert enc_key == rec_enc_key
    
    print("✅ All tests passed!")


if __name__ == '__main__':
    main()
