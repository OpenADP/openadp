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
import time
import concurrent.futures
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass

from .crypto import (
    H, derive_enc_key, point_mul, point_compress, point_decompress,
    ShamirSecretSharing, recover_point_secret, PointShare, Point2D, Point4D,
    expand, unexpand, Q, mod_inverse
)
from .client import EncryptedOpenADPClient, ServerInfo
from .debug import debug_log, secure_random_scalar, is_debug_mode_enabled, get_deterministic_main_secret


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
    threshold: Optional[int] = None
    auth_codes: Optional[Dict[str, Any]] = None
    server_infos: Optional[List['ServerInfo']] = None


@dataclass
class RecoverEncryptionKeyResult:
    """Result of encryption key recovery."""
    encryption_key: Optional[bytes] = None
    error: Optional[str] = None
    num_guesses: int = 0  # Actual number of guesses used (from server responses)
    max_guesses: int = 0  # Maximum guesses allowed (from server responses)

def generate_auth_codes(server_urls: List[str]) -> AuthCodes:
    """
    Generate authentication codes for servers.
    
    Args:
        server_urls: List of server URLs
        
    Returns:
        AuthCodes object with base and server-specific codes
    """
    debug_log(f"Generating auth codes for {len(server_urls)} servers")
    
    # Generate base authentication code (32 random bytes as hex)
    if is_debug_mode_enabled():
        # Use deterministic value in debug mode
        base_auth_code = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        debug_log(f"Using deterministic base auth code: {base_auth_code}")
    else:
        base_auth_code = secrets.token_hex(32)
    
    # Generate server-specific codes using SHA256 (same as Go implementation)
    server_auth_codes = {}
    for server_url in server_urls:
        combined = f"{base_auth_code}:{server_url}"
        hash_obj = hashlib.sha256(combined.encode('utf-8'))
        server_auth_codes[server_url] = hash_obj.hexdigest()
        debug_log(f"Generated auth code for server: {server_url}")
    
    return AuthCodes(
        base_auth_code=base_auth_code,
        server_auth_codes=server_auth_codes,
        user_id=""  # Will be set by caller
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
        pin = password.encode('utf-8')
        
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
        if is_debug_mode_enabled():
            # Use deterministic secret in debug mode
            secret_hex = get_deterministic_main_secret()
            secret = int(secret_hex, 16) % Q
            debug_log(f"Using deterministic secret: 0x{secret_hex}")
        else:
            secret = secrets.randbelow(Q)
            # Note: secret can be 0 - this is valid for Shamir secret sharing
        
        debug_log(f"Generated main secret: {secret}")
        
        U = H(identity.uid.encode(), identity.did.encode(), identity.bid.encode(), pin)
        S = point_mul(secret, U)
        
        debug_log(f"Computed U point for identity: {identity}")
        debug_log(f"Computed S = secret * U")
        
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
        # Use concurrent registration for better reliability and speed
        version = 1
        registration_errors = []
        successful_registrations = 0
        successful_server_infos = []
        import threading
        registration_lock = threading.Lock()  # Thread-safe access to shared variables
        
        def register_share_with_server(share_index, x, y, client, server_url):
            """Register a single share with a server (thread-safe)"""
            nonlocal registration_errors, successful_registrations, successful_server_infos
            

            
            auth_code = auth_codes.server_auth_codes[server_url]
            
            # Find the corresponding server_info for this server
            server_info = None
            for si in server_infos:
                if si.url == server_url:
                    server_info = si
                    break
            
            try:
                # Convert share Y to base64-encoded 32-byte little-endian format (per API spec)
                # Y is the Y coordinate from Shamir secret sharing polynomial
                y_bytes = y.to_bytes(32, byteorder='little')
                y_str = base64.b64encode(y_bytes).decode('ascii')
                
                # Use encrypted registration if server has public key, otherwise unencrypted for compatibility
                encrypted = client.has_public_key()
                
                success = client.register_secret(
                    auth_code, identity.uid, identity.did, identity.bid, version, x, y_str, max_guesses, expiration, encrypted, None
                )
                
                # Thread-safe updates to shared state
                with registration_lock:
                    if not success:
                        registration_errors.append(f"Server {share_index+1} ({server_url}): Registration returned false")
                    else:
                        enc_status = "encrypted" if encrypted else "unencrypted"
                        print(f"OpenADP: Registered share {x} with server {share_index+1} ({server_url}) [{enc_status}]")
                        successful_registrations += 1
                        if server_info:
                            successful_server_infos.append(server_info)
                        
            except Exception as e:
                with registration_lock:
                    registration_errors.append(f"Server {share_index+1} ({server_url}): {e}")
        
        # Execute all registrations concurrently with better error handling
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(clients)) as executor:
            futures = []
            for i, (x, y) in enumerate(shares):
                if i >= len(clients):
                    break  # More shares than servers
                
                client = clients[i]
                server_url = live_server_urls[i]
                
                # Submit registration task
                future = executor.submit(register_share_with_server, i, x, y, client, server_url)
                futures.append(future)
            
            # Wait for all registrations to complete and check for exceptions
            try:
                completed_futures = concurrent.futures.wait(futures, timeout=90)
                
                # Check if any futures completed with exceptions
                for future in completed_futures.done:
                    try:
                        future.result()  # This will raise any exception that occurred
                    except Exception as e:
                        print(f"Warning: Registration future failed with exception: {e}")
                
                # Check for timeouts
                if completed_futures.not_done:
                    print(f"Warning: {len(completed_futures.not_done)} registrations timed out")
                    for future in completed_futures.not_done:
                        future.cancel()
                        
            except Exception as e:
                print(f"Warning: Error during concurrent registration: {e}")
        
        print(f"OpenADP: Registration completed - {successful_registrations} successful, {len(registration_errors)} errors")
        if registration_errors:
            for error in registration_errors:
                print(f"  - {error}")
        
        if successful_registrations == 0:
            return GenerateEncryptionKeyResult(
                error=f"Failed to register any shares: {registration_errors}"
            )
        
        # CRITICAL FIX: Recalculate threshold based on actual successful registrations
        # Original threshold was based on planned servers, but some may have failed
        actual_threshold = successful_registrations // 2 + 1  # Majority of successful servers
        if actual_threshold > successful_registrations:
            actual_threshold = successful_registrations  # Can't need more shares than we have
        
        print(f"✅ Generated encryption key with {successful_registrations} servers")
        print(f"🎯 Threshold: {actual_threshold}-of-{successful_registrations} recovery")
        
        # Step 8: Derive encryption key
        enc_key = derive_enc_key(S)
        print("OpenADP: Successfully generated encryption key")
        
        return GenerateEncryptionKeyResult(
            encryption_key=enc_key,
            threshold=actual_threshold,  # Use recalculated threshold
            auth_codes=auth_codes,
            server_infos=successful_server_infos
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
        return RecoverEncryptionKeyResult(error="Identity cannot be None", num_guesses=0, max_guesses=0)
    
    if not identity.uid:
        return RecoverEncryptionKeyResult(error="UID cannot be empty", num_guesses=0, max_guesses=0)
    
    if not identity.did:
        return RecoverEncryptionKeyResult(error="DID cannot be empty", num_guesses=0, max_guesses=0)
    
    if not identity.bid:
        return RecoverEncryptionKeyResult(error="BID cannot be empty", num_guesses=0, max_guesses=0)
    
    if threshold <= 0:
        return RecoverEncryptionKeyResult(error="Threshold must be positive", num_guesses=0, max_guesses=0)
    
    print(f"OpenADP: Identity={identity}")
    
    try:
        # Step 1: Convert password to same PIN
        pin = password.encode('utf-8')
        
        # Step 2: Fetch remaining guesses for all servers and select the best ones
        print("OpenADP: Fetching remaining guesses from servers...")
        server_infos_with_guesses = fetch_remaining_guesses_for_servers(identity, server_infos)
        
        # Calculate threshold for server selection
        threshold = len(server_infos_with_guesses) // 2 + 1  # Standard majority threshold: floor(N/2) + 1
        
        # Select servers intelligently based on remaining guesses
        selected_server_infos = select_servers_by_remaining_guesses(server_infos_with_guesses, threshold)
        
        # Initialize clients for the selected servers
        clients = []
        live_server_urls = []
        live_server_infos = []
        
        for server_info in selected_server_infos:
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
                live_server_infos.append(server_info)
            except Exception as e:
                print(f"Warning: Server {server_info.url} is not accessible: {e}")
        
        if not clients:
            return RecoverEncryptionKeyResult(error="No servers are accessible", num_guesses=0, max_guesses=0)
        
        print(f"OpenADP: Using {len(clients)} live servers")
        
        # Step 3: Create cryptographic context (same as encryption)
        U = H(identity.uid.encode(), identity.did.encode(), identity.bid.encode(), pin)
        
        # Debug: Show the U point that we're using for recovery
        u_point_affine = unexpand(U)
        debug_log(f"🔍 DEBUG: U point: x={u_point_affine.x}, y={u_point_affine.y}")
        
        # Generate random r for blinding (0 < r < Q)  
        if is_debug_mode_enabled():
            # Use deterministic value in debug mode
            secret_hex = get_deterministic_main_secret()
            r = int(secret_hex, 16) % Q
            if r == 0:
                r = 1  # Ensure r is not zero
            debug_log(f"Using deterministic blinding factor r: {r}")
        else:
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
        
        debug_log(f"r scalar: {r}")
        debug_log(f"r^-1 scalar: {r_inv}")
        debug_log(f"B point (r * U): x={b_point_affine.x}, y={b_point_affine.y}")
        debug_log(f"B compressed: {b_compressed.hex()}")
        debug_log(f"B base64: {b_base64_format}")
        
        # Step 5: Recover shares from servers (use all available servers, already intelligently selected)
        print("OpenADP: Recovering shares from servers...")
        valid_shares = []
        actual_num_guesses = 0
        actual_max_guesses = 0
        
        for i in range(len(clients)):  # Use all available servers (already filtered by remaining guesses)
            client = clients[i]
            server_url = live_server_urls[i]
            server_info = live_server_infos[i]
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
                    
                    # Capture guess information from server response (first successful server)
                    if actual_num_guesses == 0 and actual_max_guesses == 0:
                        if 'num_guesses' in result_map:
                            actual_num_guesses = int(result_map['num_guesses'])
                        if 'max_guesses' in result_map:
                            actual_max_guesses = int(result_map['max_guesses'])
                    
                    debug_log(f"🔍 DEBUG: Server {i+1} response - x: {result_map.get('x')}, si_b: {result_map.get('si_b')}")
                    debug_log(f"🔍 DEBUG: si_b length: {len(result_map.get('si_b', ''))}")
                    
                    guesses_str = "unknown" if server_info.remaining_guesses == -1 else f"{server_info.remaining_guesses}"
                    print(f"OpenADP: ✓ Recovered share from server {i+1} ({server_url}, {guesses_str} remaining guesses)")
                    
                    # Convert si_b back to point and then to share
                    try:
                        si_b_base64 = result_map.get('si_b')
                        x_coord = result_map.get('x')
                        
                        if not si_b_base64 or x_coord is None:
                            print(f"Warning: Server {i+1} returned incomplete data")
                            continue
                        
                        si_b_bytes = base64.b64decode(si_b_base64)
                        debug_log(f"🔍 DEBUG: Decoded si_b bytes length: {len(si_b_bytes)}")
                        debug_log(f"🔍 DEBUG: Decoded si_b bytes: {si_b_bytes.hex()}")
                        
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
                                
                                # Capture guess information from retry response (first successful server)
                                if actual_num_guesses == 0 and actual_max_guesses == 0:
                                    if 'num_guesses' in retry_result_map:
                                        actual_num_guesses = int(retry_result_map['num_guesses'])
                                    if 'max_guesses' in retry_result_map:
                                        actual_max_guesses = int(retry_result_map['max_guesses'])
                                
                                guesses_str = "unknown" if server_info.remaining_guesses == -1 else f"{server_info.remaining_guesses}"
                                print(f"OpenADP: ✓ Recovered share from server {i+1} ({server_url}, {guesses_str} remaining guesses) on retry")
                                
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
                error=f"Not enough valid shares recovered. Got {len(valid_shares)}, need {threshold}",
                num_guesses=actual_num_guesses,
                max_guesses=actual_max_guesses
            )
        
        print(f"OpenADP: Recovered {len(valid_shares)} valid shares")
        
        # Step 6: Reconstruct secret using point-based recovery (like Go recover_sb)
        print(f"OpenADP: Reconstructing secret from {len(valid_shares)} point shares...")
        
        # Use point-based Lagrange interpolation to recover s*B (like Go RecoverPointSecret)
        # Use ALL available shares, not just threshold (matches Go implementation)
        recovered_sb = recover_point_secret(valid_shares)
        
        debug_log(f"🔍 DEBUG: Recovered s*B point: x={recovered_sb.x}, y={recovered_sb.y}")
        
        # Apply r^-1 to get the original secret point: s*U = r^-1 * (s*B)
        # This matches Go: rec_s_point = crypto.point_mul(r_inv, crypto.expand(rec_sb))
        recovered_sb_4d = expand(recovered_sb)
        original_su = point_mul(r_inv, recovered_sb_4d)
        original_su_2d = unexpand(original_su)
        
        debug_log(f"🔍 DEBUG: Original s*U point (after r^-1): x={original_su_2d.x}, y={original_su_2d.y}")
        
        # Step 7: Derive same encryption key
        encryption_key = derive_enc_key(original_su)
        
        debug_log(f"🔍 DEBUG: Final encryption key: {encryption_key.hex()}")
        print("OpenADP: Successfully recovered encryption key")
        
        return RecoverEncryptionKeyResult(encryption_key=encryption_key, num_guesses=actual_num_guesses, max_guesses=actual_max_guesses)
        
    except Exception as e:
        return RecoverEncryptionKeyResult(error=f"Unexpected error: {e}", num_guesses=0, max_guesses=0)


def fetch_remaining_guesses_for_servers(identity: Identity, server_infos: List[ServerInfo]) -> List[ServerInfo]:
    """
    Fetch remaining guesses for each server and update ServerInfo objects.
    
    Args:
        identity: The identity to check remaining guesses for
        server_infos: List of ServerInfo objects to update
        
    Returns:
        Updated list of ServerInfo objects with remaining_guesses populated
    """
    updated_server_infos = []
    
    for server_info in server_infos:
        # Create a copy to avoid modifying the original
        updated_server_info = ServerInfo(
            url=server_info.url,
            public_key=server_info.public_key,
            country=server_info.country,
            remaining_guesses=server_info.remaining_guesses
        )
        
        try:
            # Parse public key if available
            public_key = None
            if server_info.public_key:
                try:
                    key_str = server_info.public_key
                    if key_str.startswith("ed25519:"):
                        key_str = key_str[8:]
                    public_key = base64.b64decode(key_str)
                except Exception as e:
                    print(f"Warning: Invalid public key for server {server_info.url}: {e}")
            
            # Create client and try to fetch backup info
            client = EncryptedOpenADPClient(server_info.url, public_key)
            client.ping()  # Test connectivity
            
            # List backups to get remaining guesses
            backups = client.list_backups(identity.uid, False, None)
            
            # Find our specific backup
            remaining_guesses = -1  # Default to unknown
            for backup in backups:
                if (backup.get('uid') == identity.uid and 
                    backup.get('did') == identity.did and 
                    backup.get('bid') == identity.bid):
                    num_guesses = int(backup.get('num_guesses', 0))
                    max_guesses = int(backup.get('max_guesses', 10))
                    remaining_guesses = max(0, max_guesses - num_guesses)
                    break
            
            updated_server_info.remaining_guesses = remaining_guesses
            print(f"OpenADP: Server {server_info.url} has {remaining_guesses} remaining guesses")
            
        except Exception as e:
            print(f"Warning: Could not fetch remaining guesses from server {server_info.url}: {e}")
            # Keep the original remaining_guesses value (likely -1 for unknown)
        
        updated_server_infos.append(updated_server_info)
    
    return updated_server_infos


def select_servers_by_remaining_guesses(server_infos: List[ServerInfo], threshold: int) -> List[ServerInfo]:
    """
    Select servers intelligently based on remaining guesses.
    
    Strategy:
    1. Filter out servers with 0 remaining guesses (exhausted)
    2. Sort by remaining guesses (descending) to use servers with most guesses first
    3. Servers with unknown remaining guesses (-1) are treated as having infinite guesses
    4. Select threshold + 2 servers for redundancy
    
    Args:
        server_infos: List of ServerInfo objects with remaining_guesses populated
        threshold: Minimum number of servers needed
        
    Returns:
        Selected servers sorted by remaining guesses (descending)
    """
    # Filter out servers with 0 remaining guesses (exhausted)
    available_servers = [s for s in server_infos if s.remaining_guesses != 0]
    
    if len(available_servers) == 0:
        print("Warning: All servers have exhausted their guesses!")
        return server_infos  # Return original list as fallback
    
    # Sort by remaining guesses (descending)
    # Servers with unknown remaining guesses (-1) are treated as having the highest priority
    def sort_key(server_info):
        if server_info.remaining_guesses == -1:
            return float('inf')  # Unknown guesses = highest priority
        return server_info.remaining_guesses
    
    sorted_servers = sorted(available_servers, key=sort_key, reverse=True)
    
    # Select threshold + 2 servers for redundancy, but don't exceed available servers
    num_to_select = min(len(sorted_servers), threshold + 2)
    selected_servers = sorted_servers[:num_to_select]
    
    print(f"OpenADP: Selected {len(selected_servers)} servers based on remaining guesses:")
    for i, server in enumerate(selected_servers):
        guesses_str = "unknown" if server.remaining_guesses == -1 else str(server.remaining_guesses)
        print(f"  {i+1}. {server.url} ({guesses_str} remaining guesses)")
    
    return selected_servers 
