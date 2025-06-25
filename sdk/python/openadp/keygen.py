"""
Key generation and recovery for OpenADP.

This module provides high-level functions for generating encryption keys using
the OpenADP distributed secret sharing system, matching the Go implementation exactly.

This module handles the complete workflow:
1. Generate random secrets and split into shares
2. Register shares with distributed servers  
3. Recover secrets from servers during decryption
4. Derive encryption keys using cryptographic functions
"""

import os
import hashlib
import secrets
import base64
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass

from .crypto import (
    H, derive_enc_key, point_mul, point_compress, point_decompress,
    ShamirSecretSharing, recover_point_secret, PointShare, Point2D, Point4D,
    expand, unexpand, Q, mod_inverse
)
from .client import EncryptedOpenADPClient, ServerInfo


@dataclass
class Identity:
    """Identity represents the primary key tuple for secret shares stored on servers"""
    uid: str  # User ID - uniquely identifies the user
    did: str  # Device ID - identifies the device/application  
    bid: str  # Backup ID - identifies the specific backup
    
    def __str__(self) -> str:
        return f"UID={self.uid}, DID={self.did}, BID={self.bid}"


@dataclass
class AuthCodes:
    """Authentication codes for OpenADP servers."""
    base_auth_code: str
    server_auth_codes: Dict[str, str]
    user_id: str


@dataclass
class GenerateEncryptionKeyResult:
    """Result of encryption key generation."""
    encryption_key: Optional[bytes] = None
    error: Optional[str] = None
    server_infos: Optional[List[ServerInfo]] = None
    threshold: Optional[int] = None
    auth_codes: Optional[Dict[str, Any]] = None


@dataclass
class RecoverEncryptionKeyResult:
    """Result of encryption key recovery."""
    encryption_key: Optional[bytes] = None
    error: Optional[str] = None


def password_to_pin(password: str) -> bytes:
    """
    Convert user password to PIN bytes for cryptographic operations (matches Go PasswordToPin).
    
    Args:
        password: User-provided password string
        
    Returns:
        PIN as bytes suitable for crypto.H()
    """
    # Hash password to get consistent bytes, then take first 2 bytes as PIN
    hash_bytes = hashlib.sha256(password.encode('utf-8')).digest()
    return hash_bytes[:2]  # Use first 2 bytes as PIN


def generate_auth_codes(server_urls: List[str]) -> AuthCodes:
    """
    Generate authentication codes for OpenADP servers.
    
    Creates a base authentication code and derives server-specific codes.
    Each server gets a unique code derived from the base code and server URL.
    
    Args:
        server_urls: List of server URLs to generate codes for
        
    Returns:
        AuthCodes object containing base code and server-specific codes
    """
    # Generate base authentication code (32 random bytes as hex)
    base_auth_code = secrets.token_hex(32)

    
    # Generate server-specific authentication codes
    server_auth_codes = {}
    for server_url in server_urls:
        # Derive server-specific code using SHA256 (same as Go implementation)
        combined = f"{base_auth_code}:{server_url}"
        hash_bytes = hashlib.sha256(combined.encode('utf-8')).digest()
        server_code = hash_bytes.hex()
        server_auth_codes[server_url] = server_code
    
    # Return with a placeholder user_id (will be set by caller)
    return AuthCodes(
        base_auth_code=base_auth_code,
        server_auth_codes=server_auth_codes,
        user_id=""  # Will be set by the caller
    )


def generate_encryption_key(
    identity: Identity,
    password: str, 
    max_guesses: int = 10,
    expiration: int = 0,
    server_infos: List[ServerInfo] = None
) -> GenerateEncryptionKeyResult:
    """
    Generate an encryption key using OpenADP distributed secret sharing.
    
    FULL DISTRIBUTED IMPLEMENTATION: This implements the complete OpenADP protocol:
    1. Uses the provided Identity (UID, DID, BID) as the primary key
    2. Converts password to cryptographic PIN
    3. Distributes secret shares to OpenADP servers via JSON-RPC
    4. Uses authentication codes for secure server communication
    5. Uses threshold cryptography for recovery
    
    Args:
        identity: Identity containing (UID, DID, BID) primary key tuple
        password: User password to convert to PIN
        max_guesses: Maximum password attempts allowed
        expiration: Expiration time for shares (0 = no expiration)
        server_infos: List of OpenADP servers
        
    Returns:
        GenerateEncryptionKeyResult with encryption key or error
    """
    # Input validation
    if identity is None:
        return GenerateEncryptionKeyResult(error="Identity cannot be None")
    
    if not identity.uid:
        return GenerateEncryptionKeyResult(error="UID cannot be empty")
    
    if not identity.did:
        return GenerateEncryptionKeyResult(error="DID cannot be empty")
    
    if not identity.bid:
        return GenerateEncryptionKeyResult(error="BID cannot be empty")
    
    if max_guesses < 0:
        return GenerateEncryptionKeyResult(error="Max guesses cannot be negative")
    
    print(f"OpenADP: Identity={identity}")
    
    try:
        # Step 1: Convert password to PIN
        pin = password_to_pin(password)
        
        # Step 2: Check if we have servers
        if not server_infos:
            return GenerateEncryptionKeyResult(error="No OpenADP servers available")
        
        # Step 3: Initialize encrypted clients for each server using public keys from servers.json
        clients = []
        live_server_urls = []
        
        for server_info in server_infos:
            public_key = None
            
            # Parse public key if available
            if server_info.public_key:
                try:
                    # Handle different key formats
                    if server_info.public_key.startswith("ed25519:"):
                        # Remove ed25519: prefix and decode
                        key_b64 = server_info.public_key[8:]
                        public_key = base64.b64decode(key_b64)
                    else:
                        # Assume it's already base64
                        public_key = base64.b64decode(server_info.public_key)
                except Exception as e:
                    print(f"Warning: Invalid public key for server {server_info.url}: {e}")
                    public_key = None
            
            # Create encrypted client with public key from servers.json (secure)
            client = EncryptedOpenADPClient(server_info.url, public_key)
            try:
                client.ping()
                clients.append(client)
                live_server_urls.append(server_info.url)
                if public_key:
                    print(f"OpenADP: Server {server_info.url} - Using Noise-NK encryption (key from servers.json)")
                else:
                    print(f"OpenADP: Server {server_info.url} - No encryption (no public key)")
            except Exception as e:
                print(f"Warning: Server {server_info.url} is not accessible: {e}")
        
        if not clients:
            return GenerateEncryptionKeyResult(error="No live servers available")
        
        print(f"OpenADP: Using {len(clients)} live servers")
        
        # Step 4: Generate authentication codes for the live servers
        auth_codes = generate_auth_codes(live_server_urls)
        auth_codes.user_id = identity.uid
        
        # Step 5: Generate RANDOM secret and create point
        # SECURITY FIX: Use random secret for Shamir secret sharing, not deterministic
        secret = secrets.randbelow(Q)
        # Note: secret can be 0 - this is valid for Shamir secret sharing
        
        U = H(identity.uid.encode(), identity.did.encode(), identity.bid.encode(), pin)
        S = point_mul(secret, U)
        
        # Step 6: Create shares using secret sharing
        num_shares = len(clients)
        threshold = len(clients) // 2 + 1  # Standard majority threshold: floor(N/2) + 1
        
        if num_shares < threshold:
            return GenerateEncryptionKeyResult(
                error=f"Need at least {threshold} servers, only {num_shares} available"
            )
        
        shares = ShamirSecretSharing.split_secret(secret, threshold, num_shares)
        print(f"OpenADP: Created {len(shares)} shares with threshold {threshold}")
        
        # Step 7: Register shares with servers using authentication codes and encryption
        # Only use encrypted registration for sensitive operations
        version = 1
        registration_errors = []
        successful_registrations = 0
        
        for i, (x, y) in enumerate(shares):
            if i >= len(clients):
                break  # More shares than servers
            
            client = clients[i]
            server_url = live_server_urls[i]
            auth_code = auth_codes.server_auth_codes[server_url]
            
            # Convert share Y to string (Shamir secret sharing polynomial Y coordinate)
            # Y is the Y coordinate of a point on the polynomial, not an elliptic curve point
            # The Go implementation sends this as a decimal string: share.Y.String()
            # We'll match that for compatibility, even though base64 would be better
            y_str = str(y)
            
            # Use encrypted registration if server has public key, otherwise unencrypted for compatibility
            encrypted = client.has_public_key()
            
            try:
                success = client.register_secret(
                    auth_code, identity.uid, identity.did, identity.bid, version, x, y_str, max_guesses, expiration, encrypted, None
                )
                
                if not success:
                    registration_errors.append(f"Server {i+1} ({server_url}): Registration returned false")
                else:
                    enc_status = "encrypted" if encrypted else "unencrypted"
                    print(f"OpenADP: Registered share {x} with server {i+1} ({server_url}) [{enc_status}]")
                    successful_registrations += 1
                    
            except Exception as e:
                registration_errors.append(f"Server {i+1} ({server_url}): {e}")
        
        if successful_registrations == 0:
            return GenerateEncryptionKeyResult(
                error=f"Failed to register any shares: {registration_errors}"
            )
        
        # Step 8: Derive encryption key
        enc_key = derive_enc_key(S)
        print("OpenADP: Successfully generated encryption key")
        
        return GenerateEncryptionKeyResult(
            encryption_key=enc_key,
            server_infos=server_infos,
            threshold=threshold,
            auth_codes=auth_codes
        )
        
    except Exception as e:
        return GenerateEncryptionKeyResult(error=f"Unexpected error: {e}")


def recover_encryption_key(
    identity: Identity,
    password: str,
    server_infos: List[ServerInfo],
    threshold: int,
    auth_codes: Dict[str, Any]
) -> RecoverEncryptionKeyResult:
    """
    Recover an encryption key using OpenADP distributed secret sharing.
    
    FULL DISTRIBUTED IMPLEMENTATION: This implements the complete OpenADP protocol:
    1. Uses the provided Identity (UID, DID, BID) as the primary key
    2. Converts password to the same PIN
    3. Recovers shares from OpenADP servers via JSON-RPC with encryption
    4. Reconstructs the original secret using threshold cryptography
    5. Derives the same encryption key
    
    Args:
        identity: Identity containing (UID, DID, BID) primary key tuple
        password: User password to convert to PIN
        server_infos: List of OpenADP servers
        threshold: Minimum shares needed for recovery
        auth_codes: Authentication codes for servers
        
    Returns:
        RecoverEncryptionKeyResult with encryption key or error
    """
    # Input validation
    if identity is None:
        return RecoverEncryptionKeyResult(error="Identity cannot be None")
    
    if not identity.uid:
        return RecoverEncryptionKeyResult(error="UID cannot be empty")
    
    if not identity.did:
        return RecoverEncryptionKeyResult(error="DID cannot be empty")
    
    if not identity.bid:
        return RecoverEncryptionKeyResult(error="BID cannot be empty")
    
    if threshold <= 0:
        return RecoverEncryptionKeyResult(error="Threshold must be positive")
    
    print(f"OpenADP: Identity={identity}")
    
    try:
        # Step 1: Convert password to same PIN
        pin = password_to_pin(password)
        
        # Step 2: Initialize clients for the specific servers, using encryption when public keys are available
        clients = []
        live_server_urls = []
        
        for server_info in server_infos:
            public_key = None
            if server_info.public_key:
                try:
                    # Parse public key (handles "ed25519:" prefix)
                    key_str = server_info.public_key
                    if key_str.startswith("ed25519:"):
                        key_str = key_str[8:]
                    
                    public_key = base64.b64decode(key_str)
                    print(f"OpenADP: Using Noise-NK encryption for server {server_info.url}")
                except Exception as e:
                    print(f"Warning: Invalid public key for server {server_info.url}: {e}")
                    public_key = None
            
            client = EncryptedOpenADPClient(server_info.url, public_key)
            try:
                client.ping()
                clients.append(client)
                live_server_urls.append(server_info.url)
            except Exception as e:
                print(f"Warning: Server {server_info.url} is not accessible: {e}")
        
        if not clients:
            return RecoverEncryptionKeyResult(error="No servers are accessible")
        
        print(f"OpenADP: Using {len(clients)} live servers")
        
        # Step 3: Create cryptographic context (same as encryption)
        U = H(identity.uid.encode(), identity.did.encode(), identity.bid.encode(), pin)
        
        # Debug: Show the U point that we're using for recovery
        u_point_affine = unexpand(U)
        
        # Generate random r for blinding (0 < r < Q)  
        r = secrets.randbelow(Q)
        if r == 0:
            r = 1  # Ensure r is not zero
        
        # Compute r^-1 mod Q
        r_inv = mod_inverse(r, Q)
        
        # Compute B = r * U
        b_point = point_mul(r, U)
        b_point_affine = unexpand(b_point)
        b_compressed = point_compress(b_point)
        b_base64_format = base64.b64encode(b_compressed).decode('ascii')
        
        # Step 5: Recover shares from servers
        print("OpenADP: Recovering shares from servers...")
        valid_shares = []
        
        for i in range(min(len(clients), threshold + 2)):  # Get a few extra shares for redundancy
            client = clients[i]
            server_url = live_server_urls[i]
            auth_code = auth_codes.server_auth_codes[server_url]
            
            if not auth_code:
                print(f"Warning: No auth code for server {server_url}")
                continue
            
            try:
                # Get current guess number for this backup from the server
                guess_num = 0  # Default to 0 for first guess (0-based indexing)
                try:
                    backups = client.list_backups(identity.uid, False, None)
                    # Find our backup in the list using the complete primary key (UID, DID, BID)
                    for backup in backups:
                        if (backup['uid'] == identity.uid and 
                            backup['did'] == identity.did and 
                            backup['bid'] == identity.bid):
                            guess_num = int(backup.get('num_guesses', 0))
                            break
                except Exception as e:
                    print(f"Warning: Could not list backups from server {i+1}: {e}")
                
                # Try recovery with current guess number, retry once if guess number is wrong
                try:
                    result = client.recover_secret(
                        auth_code, identity.uid, identity.did, identity.bid, b_base64_format, guess_num, True
                    )
                    result_map = result if isinstance(result, dict) else result.__dict__
                    
                    print(f"OpenADP: ✓ Recovered share from server {i+1} ({server_url})")
                    
                    # Convert si_b back to point and then to share
                    try:
                        si_b_base64 = result_map.get('si_b')
                        x_coord = result_map.get('x')
                        
                        if not si_b_base64 or x_coord is None:
                            print(f"Warning: Server {i+1} returned incomplete data")
                            continue
                        
                        si_b_bytes = base64.b64decode(si_b_base64)
                        si_b = point_decompress(si_b_bytes)
                        
                        valid_shares.append(PointShare(x_coord, si_b))
                        
                    except Exception as share_error:
                        print(f"Warning: Failed to process share from server {i+1}: {share_error}")
                        
                except Exception as error:
                    # If we get a guess number error, try to parse the expected number and retry
                    if "expecting guess_num =" in str(error):
                        try:
                            error_str = str(error)
                            idx = error_str.find("expecting guess_num = ")
                            if idx != -1:
                                expected_str = error_str[idx + len("expecting guess_num = "):]
                                space_idx = expected_str.find(" ")
                                expected_guess = int(expected_str[:space_idx] if space_idx != -1 else expected_str)
                                print(f"Server {i+1} ({server_url}): Retrying with expected guess_num = {expected_guess}")
                                
                                retry_result = client.recover_secret(
                                    auth_code, identity.uid, identity.did, identity.bid, b_base64_format, expected_guess, True
                                )
                                retry_result_map = retry_result if isinstance(retry_result, dict) else retry_result.__dict__
                                
                                print(f"OpenADP: ✓ Recovered share from server {i+1} ({server_url}) on retry")
                                
                                # Convert si_b back to point and then to share
                                try:
                                    si_b_base64 = retry_result_map.get('si_b')
                                    x_coord = retry_result_map.get('x')
                                    
                                    if not si_b_base64 or x_coord is None:
                                        print(f"Warning: Server {i+1} returned incomplete data on retry")
                                        continue
                                    
                                    si_b_bytes = base64.b64decode(si_b_base64)
                                    si_b = point_decompress(si_b_bytes)
                                    
                                    valid_shares.append(PointShare(x_coord, si_b))
                                    
                                except Exception as retry_share_error:
                                    print(f"Warning: Failed to process retry share from server {i+1}: {retry_share_error}")
                            else:
                                print(f"Warning: Server {i+1} ({server_url}) recovery failed: {error}")
                        except Exception as retry_error:
                            print(f"Warning: Server {i+1} ({server_url}) recovery retry failed: {retry_error}")
                    else:
                        print(f"Warning: Server {i+1} ({server_url}) recovery failed: {error}")
                    
            except Exception as e:
                print(f"Warning: Failed to recover from server {i+1} ({server_url}): {e}")
        
        if len(valid_shares) < threshold:
            return RecoverEncryptionKeyResult(
                error=f"Not enough valid shares recovered. Got {len(valid_shares)}, need {threshold}"
            )
        
        print(f"OpenADP: Recovered {len(valid_shares)} valid shares")
        
        # Step 6: Reconstruct secret using point-based recovery (like Go recover_sb)
        print(f"OpenADP: Reconstructing secret from {len(valid_shares)} point shares...")
        
        # Use point-based Lagrange interpolation to recover s*B (like Go RecoverPointSecret)
        # Use ALL available shares, not just threshold (matches Go implementation)
        recovered_sb = recover_point_secret(valid_shares)
        
        # Apply r^-1 to get the original secret point: s*U = r^-1 * (s*B)
        # This matches Go: rec_s_point = crypto.point_mul(r_inv, crypto.expand(rec_sb))
        recovered_sb_4d = expand(recovered_sb)
        original_su = point_mul(r_inv, recovered_sb_4d)
        
        # Step 7: Derive same encryption key
        encryption_key = derive_enc_key(original_su)
        print("OpenADP: Successfully recovered encryption key")
        
        return RecoverEncryptionKeyResult(encryption_key=encryption_key)
        
    except Exception as e:
        return RecoverEncryptionKeyResult(error=f"Unexpected error: {e}") 
