#!/usr/bin/env python3
"""
OpenADP Key Generation Module

This module provides high-level functions for generating encryption keys using
the OpenADP distributed secret sharing system. It handles the complete workflow:

1. Generate random secrets and split into shares
2. Register shares with distributed servers  
3. Recover secrets from servers during decryption
4. Derive encryption keys using cryptographic functions

This replaces traditional password-based key derivation (like Scrypt) with
a distributed approach that provides better security and recovery properties.
"""

import os
import time
import hashlib
import secrets
import base64
from typing import Tuple, Optional, List

import crypto
import sharing
from client import Client


def derive_identifiers(filename: str, username: Optional[str] = None, 
                      hostname: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Derive UID, DID, and BID from file and system context.
    
    Args:
        filename: Name of file being encrypted/decrypted
        username: Override username (auto-detected if None)
        hostname: Override hostname (auto-detected if None)
        
    Returns:
        Tuple of (uid, did, bid) identifiers
    """
    # Auto-detect username if not provided
    if username is None:
        username = os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
    
    # Auto-detect hostname if not provided  
    if hostname is None:
        import socket
        hostname = socket.gethostname()
    
    # Create identifiers
    uid = f"{username}@{hostname}"  # User@device identifier
    did = hostname  # Device identifier
    bid = f"file://{os.path.basename(filename)}"  # Backup identifier for this file
    
    return uid, did, bid


def password_to_pin(password: str) -> bytes:
    """
    Convert user password to PIN bytes for cryptographic operations.
    
    Args:
        password: User-provided password string
        
    Returns:
        PIN as bytes suitable for crypto.H()
    """
    # Hash password to get consistent bytes, then take first 2 bytes as PIN
    hash_bytes = hashlib.sha256(password.encode('utf-8')).digest()
    return hash_bytes[:2]  # Use first 2 bytes as PIN


def generate_encryption_key(filename: str, password: str, max_guesses: int = 10,
                           expiration: int = 0) -> Tuple[bytes, Optional[str]]:
    """
    Generate an encryption key using OpenADP distributed secret sharing.
    
    This function:
    1. Derives UID/DID/BID from file and system context
    2. Converts password to PIN for cryptographic operations
    3. Generates random secret and splits into shares
    4. Registers shares with live OpenADP servers
    5. Derives encryption key from the secret
    
    Args:
        filename: File being encrypted (used for BID)
        password: User password 
        max_guesses: Maximum recovery attempts allowed
        expiration: Expiration timestamp (0 for no expiration)
        
    Returns:
        Tuple of (encryption_key, error_message). If successful, error_message is None.
    """
    # Step 1: Derive identifiers
    uid, did, bid = derive_identifiers(filename)
    print(f"OpenADP: UID={uid}, DID={did}, BID={bid}")
    
    # Step 2: Convert password to PIN
    pin = password_to_pin(password)
    
    # Step 3: Initialize OpenADP client
    client = Client()
    if client.get_live_server_count() == 0:
        return None, "No live OpenADP servers available"
    
    print(f"OpenADP: Using {client.get_live_server_count()} live servers")
    
    # Step 4: Generate random secret and create point
    secret = secrets.randbelow(crypto.q)
    U = crypto.H(uid.encode(), did.encode(), bid.encode(), pin)
    S = crypto.point_mul(secret, U)
    
    # Step 5: Create shares using secret sharing
    threshold = min(2, client.get_live_server_count())  # Need at least 2 servers for threshold
    num_shares = client.get_live_server_count()
    
    if num_shares < threshold:
        return None, f"Need at least {threshold} servers, only {num_shares} available"
    
    shares = sharing.make_random_shares(secret, threshold, num_shares)
    print(f"OpenADP: Created {len(shares)} shares with threshold {threshold}")
    
    # Step 6: Register shares with servers
    version = 1
    registration_errors = []
    
    for i, (x, y) in enumerate(shares):
        if i >= len(client.live_servers):
            break  # More shares than servers
            
        # Register this specific share to this specific server only
        # Each server has its own database, so same UID/DID/BID is fine
        server_client = client.live_servers[i]
        y_str = str(y)
        
        try:
            result, error = server_client.register_secret(uid, did, bid, version, x, y_str, max_guesses, expiration)
            
            if error:
                registration_errors.append(f"Server {i+1}: {error}")
            elif not result:
                registration_errors.append(f"Server {i+1}: Registration returned false")
            else:
                print(f"OpenADP: Registered share {x} with server {i+1}")
                
        except Exception as e:
            registration_errors.append(f"Server {i+1}: Exception: {str(e)}")
    
    if len(registration_errors) == len(shares):
        return None, f"Failed to register any shares: {'; '.join(registration_errors)}"
    
    # Step 7: Derive encryption key
    enc_key = crypto.deriveEncKey(S)
    print("OpenADP: Successfully generated encryption key")
    
    return enc_key, None


def recover_encryption_key(filename: str, password: str) -> Tuple[bytes, Optional[str]]:
    """
    Recover an encryption key from OpenADP servers for decryption.
    
    This function:
    1. Derives same UID/DID/BID from file and system context
    2. Converts password to same PIN 
    3. Recovers secret shares from OpenADP servers
    4. Reconstructs original secret using threshold cryptography
    5. Derives same encryption key
    
    Args:
        filename: File being decrypted (used for BID)
        password: User password (must match encryption password)
        
    Returns:
        Tuple of (encryption_key, error_message). If successful, error_message is None.
    """
    # Step 1: Derive same identifiers as during encryption
    uid, did, bid = derive_identifiers(filename)
    print(f"OpenADP: Recovering for UID={uid}, DID={did}, BID={bid}")
    
    # Step 2: Convert password to same PIN
    pin = password_to_pin(password)
    
    # Step 3: Initialize OpenADP client
    client = Client()
    if client.get_live_server_count() == 0:
        return None, "No live OpenADP servers available"
    
    print(f"OpenADP: Using {client.get_live_server_count()} live servers")
    
    # Step 4: Create cryptographic context (same as encryption)
    U = crypto.H(uid.encode(), did.encode(), bid.encode(), pin)
    
    # Generate random r and compute B for recovery protocol
    p = crypto.q
    r = secrets.randbelow(p - 1) + 1
    r_inv = pow(r, -1, p)
    B = crypto.point_mul(r, U)
    
    # Step 5: Recover shares from servers
    print("OpenADP: Recovering shares from servers...")
    recovered_shares = []
    
    for i, server_client in enumerate(client.live_servers):
        try:
            # Get current guess number for this backup from this specific server
            backups, error = server_client.list_backups(uid)
            if error:
                print(f"Warning: Could not list backups from server {i+1}: {error}")
                guess_num = 0  # Start with 0 if we can't determine current state
            else:
                # Find our backup in the list from this server
                guess_num = 0
                for backup in backups:
                    backup_bid = backup[1] if len(backup) > 1 else ""
                    if backup_bid == bid:
                        guess_num = backup[3] if len(backup) > 3 else 0  # num_guesses field
                        break
            
            # Attempt recovery from this specific server
            result, error = server_client.recover_secret(uid, did, bid, crypto.unexpand(B), guess_num)
            
            if error:
                print(f"Server {i+1} recovery failed: {error}")
                continue
                
            version, x, si_b_unexpanded, num_guesses, max_guesses, expiration = result
            recovered_shares.append((x, si_b_unexpanded))
            print(f"OpenADP: Recovered share {x} from server {i+1}")
            
        except Exception as e:
            print(f"Exception recovering from server {i+1}: {e}")
            continue
    
    if len(recovered_shares) < 2:  # Need at least threshold shares
        return None, f"Could not recover enough shares (got {len(recovered_shares)}, need at least 2)"
    
    # Step 6: Reconstruct secret using recovered shares
    print(f"OpenADP: Reconstructing secret from {len(recovered_shares)} shares...")
    rec_sb = sharing.recover_sb(recovered_shares)
    rec_s_point = crypto.point_mul(r_inv, crypto.expand(rec_sb))
    
    # Step 7: Derive same encryption key
    enc_key = crypto.deriveEncKey(rec_s_point)
    print("OpenADP: Successfully recovered encryption key")
    
    return enc_key, None


def main():
    """Test/demo function for OpenADP key generation."""
    print("Testing OpenADP Key Generation...")
    
    test_filename = "test_document.txt"
    test_password = "my_secure_password123"
    
    # Test key generation
    print("\n1. Generating encryption key...")
    enc_key, error = generate_encryption_key(test_filename, test_password)
    
    if error:
        print(f"❌ Key generation failed: {error}")
        return
    
    print(f"✅ Generated key: {enc_key.hex()[:32]}...")
    
    # Test key recovery
    print("\n2. Recovering encryption key...")
    recovered_key, error = recover_encryption_key(test_filename, test_password)
    
    if error:
        print(f"❌ Key recovery failed: {error}")
        return
    
    print(f"✅ Recovered key: {recovered_key.hex()[:32]}...")
    
    # Verify keys match
    if enc_key == recovered_key:
        print("✅ Keys match! OpenADP key generation working correctly.")
    else:
        print("❌ Keys don't match - there's a bug in the implementation.")


if __name__ == "__main__":
    main() 