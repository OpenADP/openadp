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
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from .crypto import (
    H, derive_secret, derive_enc_key, point_mul, point_compress, point_decompress,
    ShamirSecretSharing, recover_point_secret, PointShare, Point2D, Point4D,
    expand, unexpand, Q, mod_inverse
)
from .client import EncryptedOpenADPClient, ServerInfo


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
    server_urls: Optional[List[str]] = None
    threshold: Optional[int] = None
    auth_codes: Optional[AuthCodes] = None


@dataclass
class RecoverEncryptionKeyResult:
    """Result of encryption key recovery."""
    encryption_key: Optional[bytes] = None
    error: Optional[str] = None


def derive_identifiers(filename: str, user_id: str, hostname: str = "") -> Tuple[str, str, str]:
    """
    Derive UID, DID, and BID for OpenADP operations (matches Go DeriveIdentifiers).
    
    Args:
        filename: Name of file being encrypted/decrypted  
        user_id: Authenticated user ID (authentication code system - UUID)
        hostname: Override hostname (auto-detected if empty)
        
    Returns:
        Tuple of (uid, did, bid) identifiers
    """
    # Auto-detect hostname if not provided
    if not hostname:
        try:
            hostname = os.uname().nodename
        except:
            hostname = "unknown"
    
    # Phase 4: Use authenticated user ID (UUID) as UID directly
    uid = user_id  # This is now the authenticated user ID (UUID)
    did = hostname  # Device identifier
    bid = f"file://{os.path.basename(filename)}"  # Backup identifier for this file
    
    return uid, did, bid


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
    Generate authentication codes for OpenADP servers (matches Go GenerateAuthCodes).
    
    This creates a base authentication code (256-bit SHA256 hash) and derives 
    server-specific codes for each server URL, matching the expected 64-character hex format.
    """
    # Generate random base authentication code (32 bytes = 256 bits)
    base_auth_bytes = secrets.token_bytes(32)
    base_auth_code = base_auth_bytes.hex()
    
    # Derive server-specific auth codes
    server_auth_codes = {}
    for server_url in server_urls:
        # Combine base auth code with server URL and hash (matches Go format with colon separator)
        combined = f"{base_auth_code}:{server_url}"
        server_hash = hashlib.sha256(combined.encode('utf-8')).digest()
        server_auth_codes[server_url] = server_hash.hex()
    
    return AuthCodes(
        base_auth_code=base_auth_code,
        server_auth_codes=server_auth_codes,
        user_id=""  # Will be set by caller
    )


def generate_encryption_key(
    filename: str,
    password: str, 
    user_id: str,
    max_guesses: int = 10,
    expiration: int = 0,
    server_infos: List[ServerInfo] = None
) -> GenerateEncryptionKeyResult:
    """
    Generate an encryption key using OpenADP distributed secret sharing (matches Go GenerateEncryptionKey).
    
    FULL DISTRIBUTED IMPLEMENTATION: This implements the complete OpenADP protocol:
    1. Derives unique UID/DID/BID from filename and user identity
    2. Converts password to cryptographic PIN
    3. Distributes secret shares to OpenADP servers via JSON-RPC
    4. Uses authentication codes for secure server communication
    5. Uses threshold cryptography for recovery
    """
    # Input validation
    if not filename:
        return GenerateEncryptionKeyResult(error="Filename cannot be empty")
    
    if not user_id:
        return GenerateEncryptionKeyResult(error="User ID cannot be empty")
    
    if max_guesses < 0:
        return GenerateEncryptionKeyResult(error="Max guesses cannot be negative")
    
    try:
        # Step 1: Derive identifiers using authenticated user_id
        uid, did, bid = derive_identifiers(filename, user_id, "")
        print(f"OpenADP: UID={uid}, DID={did}, BID={bid}")
        
        # Step 2: Convert password to PIN
        pin = password_to_pin(password)
        
        # Step 3: Check if we have servers
        if not server_infos:
            return GenerateEncryptionKeyResult(error="No OpenADP servers available")
        
        # Step 4: Initialize encrypted clients for each server using public keys from servers.json
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
        
        # Step 5: Generate authentication codes for the live servers
        auth_codes = generate_auth_codes(live_server_urls)
        auth_codes.user_id = user_id
        
        # Step 6: Generate deterministic secret and create point
        # Use deterministic secret derivation for consistent key generation
        secret = derive_secret(uid.encode(), did.encode(), bid.encode(), pin)
        
        U = H(uid.encode(), did.encode(), bid.encode(), pin)
        S = point_mul(secret, U)
        
        # Step 7: Create shares using secret sharing
        threshold = max(1, min(2, len(clients)))  # At least 1, prefer 2 if available
        num_shares = len(clients)
        
        if num_shares < threshold:
            return GenerateEncryptionKeyResult(
                error=f"Need at least {threshold} servers, only {num_shares} available"
            )
        
        shares = ShamirSecretSharing.split_secret(secret, threshold, num_shares)
        print(f"OpenADP: Created {len(shares)} shares with threshold {threshold}")
        
        # Step 8: Register shares with servers using authentication codes and encryption
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
                    auth_code, uid, did, bid, version, x, y_str, max_guesses, expiration, encrypted, None
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
        
        # Step 9: Derive encryption key
        enc_key = derive_enc_key(S)
        print("OpenADP: Successfully generated encryption key")
        
        return GenerateEncryptionKeyResult(
            encryption_key=enc_key,
            server_urls=live_server_urls,
            threshold=threshold,
            auth_codes=auth_codes
        )
        
    except Exception as e:
        return GenerateEncryptionKeyResult(error=f"Unexpected error: {e}")


def recover_encryption_key(
    filename: str,
    password: str,
    user_id: str,
    server_infos: List[ServerInfo],
    threshold: int,
    auth_codes: AuthCodes
) -> RecoverEncryptionKeyResult:
    """
    Recover an encryption key using OpenADP distributed secret sharing (matches Go RecoverEncryptionKeyWithServerInfo).
    
    FULL DISTRIBUTED IMPLEMENTATION: This implements the complete OpenADP protocol:
    1. Derives the same UID/DID/BID as during encryption
    2. Converts password to the same PIN
    3. Recovers shares from OpenADP servers via JSON-RPC with Noise-NK encryption
    4. Reconstructs the original secret using threshold cryptography
    5. Derives the same encryption key
    """
    # Input validation
    if not filename:
        return RecoverEncryptionKeyResult(error="Filename cannot be empty")
    
    if not user_id:
        return RecoverEncryptionKeyResult(error="User ID cannot be empty")
    
    if threshold <= 0:
        return RecoverEncryptionKeyResult(error="Threshold must be positive")
    
    if not server_infos:
        return RecoverEncryptionKeyResult(error="No OpenADP servers available")
    
    if not auth_codes:
        return RecoverEncryptionKeyResult(error="No authentication codes provided")
    
    try:
        # Step 1: Derive same identifiers as during encryption
        uid, did, bid = derive_identifiers(filename, user_id, "")
        print(f"OpenADP: UID={uid}, DID={did}, BID={bid}")
        
        # Step 2: Convert password to same PIN
        pin = password_to_pin(password)
        
        # Step 3: Initialize clients for the specific servers, using encryption when public keys are available
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
        
        # Step 4: Create cryptographic context (same as encryption)
        U = H(uid.encode(), did.encode(), bid.encode(), pin)
        
        # Generate random r and compute B for recovery protocol
        r = secrets.randbelow(Q)
        while r == 0:  # Ensure r is not zero
            r = secrets.randbelow(Q)
        
        # Compute r^-1 mod q
        r_inv = mod_inverse(r, Q)
        
        B = point_mul(r, U)
        
        # Convert B to compressed point format (base64 string) - standard format for all servers
        b_compressed = point_compress(B)
        b_base64_format = base64.b64encode(b_compressed).decode('ascii')
        
        # Step 5: Recover shares from servers using authentication codes
        print("OpenADP: Recovering shares from servers...")
        recovered_point_shares = []
        
        for i, client in enumerate(clients):
            server_url = live_server_urls[i]
            auth_code = auth_codes.server_auth_codes[server_url]
            
            # Get current guess number for this backup from the server
            guess_num = 0  # Default to 0 for first guess (0-based indexing)
            try:
                backups = client.list_backups(uid, False, None)
                # Find our backup in the list using the complete primary key (UID, DID, BID)
                for backup in backups:
                    if (backup.get("uid") == uid and 
                        backup.get("did") == did and 
                        backup.get("bid") == bid):
                        guess_num = int(backup.get("num_guesses", 0))
                        break
            except Exception as e:
                print(f"Warning: Could not list backups from server {i+1}: {e}")
            
            # Try recovery with current guess number, retry once if guess number is wrong
            try:
                result_map = client.recover_secret(auth_code, uid, did, bid, b_base64_format, guess_num, True, None)
            except Exception as e:
                # If we get a guess number error, try to parse the expected number and retry
                if "expecting guess_num =" in str(e):
                    try:
                        error_str = str(e)
                        idx = error_str.find("expecting guess_num = ")
                        if idx != -1:
                            expected_str = error_str[idx + len("expecting guess_num = "):]
                            space_idx = expected_str.find(" ")
                            if space_idx != -1:
                                expected_str = expected_str[:space_idx]
                            expected_guess = int(expected_str)
                            print(f"Server {i+1} ({server_url}): Retrying with expected guess_num = {expected_guess}")
                            result_map = client.recover_secret(auth_code, uid, did, bid, b_base64_format, expected_guess, True, None)
                        else:
                            raise
                    except:
                        print(f"Server {i+1} ({server_url}) recovery failed: {e}")
                        continue
                else:
                    print(f"Server {i+1} ({server_url}) recovery failed: {e}")
                    continue
            
            try:
                x = int(result_map["x"])
                si_b_base64 = result_map["si_b"]
                
                # Decode si_b from base64
                si_b_bytes = base64.b64decode(si_b_base64)
                
                # Decompress si_b from the result
                si_b_4d = point_decompress(si_b_bytes)
                si_b = unexpand(si_b_4d)
                
                # Create point share from recovered data (si * B point)
                # This matches Go's recover_sb which expects (x, Point2D) pairs
                point_share = PointShare(x=x, point=si_b)
                
                recovered_point_shares.append(point_share)
                print(f"OpenADP: Recovered share {x} from server {i+1} ({server_url})")
                
            except Exception as e:
                print(f"Server {i+1} ({server_url}): Failed to process recovery result: {e}")
                continue
        
        if len(recovered_point_shares) < threshold:
            return RecoverEncryptionKeyResult(
                error=f"Could not recover enough shares (got {len(recovered_point_shares)}, need at least {threshold})"
            )
        
        # Step 6: Reconstruct secret using point-based recovery (like Go recover_sb)
        print(f"OpenADP: Reconstructing secret from {len(recovered_point_shares)} point shares...")
        
        # Use point-based Lagrange interpolation to recover s*B (like Go RecoverPointSecret)
        recovered_sb = recover_point_secret(recovered_point_shares)
        
        # Apply r^-1 to get the original secret point: s*U = r^-1 * (s*B)
        # This matches Go: rec_s_point = crypto.point_mul(r_inv, crypto.expand(rec_sb))
        recovered_sb_4d = expand(recovered_sb)
        original_su = point_mul(r_inv, recovered_sb_4d)
        
        # Step 7: Derive same encryption key
        enc_key = derive_enc_key(original_su)
        print("OpenADP: Successfully recovered encryption key")
        
        return RecoverEncryptionKeyResult(encryption_key=enc_key)
        
    except Exception as e:
        return RecoverEncryptionKeyResult(error=f"Unexpected error: {e}") 