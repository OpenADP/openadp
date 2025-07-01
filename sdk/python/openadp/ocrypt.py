#!/usr/bin/env python3
"""
Ocrypt - Drop-in replacement for traditional password hashing functions

Ocrypt provides a simple 2-function API that replaces bcrypt, scrypt, Argon2, and PBKDF2
with OpenADP's distributed threshold cryptography for nation-state-resistant password protection.

The name "Ocrypt" reflects the underlying Oblivious Pseudo Random Function (OPRF) cryptography
that enables secure, distributed key protection without revealing secrets to individual servers.

Core API:
- ocrypt.register(user_id, app_id, long_term_secret, pin, max_guesses=10) -> metadata
- ocrypt.recover(metadata, pin) -> (long_term_secret, remaining_guesses)
- ocrypt.recover_and_reregister(metadata, pin) -> (long_term_secret, new_metadata)

Both functions throw exceptions on errors.
"""

import json
import base64
import secrets
import hashlib
import random
import time
import os
import sys
from typing import Tuple, Optional, NamedTuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Import OpenADP functions
from .keygen import generate_encryption_key, recover_encryption_key, AuthCodes, Identity
from .client import get_servers, get_fallback_server_info, ServerInfo
from .debug import debug_log, is_debug_mode_enabled, get_deterministic_random_bytes


def _register_with_bid(user_id: str, app_id: str, long_term_secret: bytes, pin: str, max_guesses: int = 10, backup_id: str = "even", servers_url: str = "") -> bytes:
    """
    Internal function to register a long-term secret with a specific backup ID.
    
    This function wraps the existing OpenADP encryption key generation with user secret wrapping.
    It allows specifying the backup ID for proper BID alternation during recovery.
    
    Args:
        user_id: Unique identifier for the user (e.g., email, username)
        app_id: Application identifier to namespace secrets per app
        long_term_secret: User-provided secret to protect (any byte sequence)
        pin: Password/PIN that will unlock the secret
        max_guesses: Maximum wrong attempts before lockout (default: 10)
        backup_id: Backup identifier ("even" or "odd") for crash safety
        servers_url: Optional custom URL for server registry (empty string uses default)
    
    Returns:
        metadata: Opaque blob containing all recovery information (JSON bytes)
    
    Raises:
        Exception: If registration fails (network, validation, server errors, etc.)
    """
    # Input validation
    if not user_id or not isinstance(user_id, str):
        raise Exception("user_id must be a non-empty string")
    
    if not app_id or not isinstance(app_id, str):
        raise Exception("app_id must be a non-empty string")
    
    if not long_term_secret or not isinstance(long_term_secret, bytes):
        raise Exception("long_term_secret must be non-empty bytes")
    
    if not pin or not isinstance(pin, str):
        raise Exception("pin must be a non-empty string")
    
    if max_guesses < 1:
        raise Exception("max_guesses must be at least 1")
    
    try:
        # Step 1: Server Discovery & Liveness Testing
        print("🌐 Discovering OpenADP servers...")
        try:
            server_infos = get_servers(servers_url)
            if not server_infos:
                raise Exception("No servers returned from registry")
            print(f"   ✅ Successfully fetched {len(server_infos)} servers from registry")
        except Exception as e:
            print(f"   ⚠️  Failed to fetch from registry: {e}")
            print("   🔄 Falling back to hardcoded servers...")
            server_infos = get_fallback_server_info()
            print(f"   Fallback servers: {len(server_infos)}")
        
        if not server_infos:
            raise Exception("No OpenADP servers available")
        
        # Random server selection for load balancing (max 15 servers for performance)
        if len(server_infos) > 15:
            server_infos = random.sample(server_infos, 15)
            print(f"   📋 Randomly selected 15 servers for load balancing")
        
        # Step 2: Use specified backup ID
        print(f"🔄 Using backup ID: {backup_id}")
        
        # Step 3: OpenADP Key Generation
        # Create Identity object with UID, DID, BID
        identity = Identity(uid=user_id, did=app_id, bid=backup_id)
        
        print("🔑 Generating encryption key using OpenADP servers...")
        result = generate_encryption_key(
            identity=identity,
            password=pin,
            max_guesses=max_guesses,
            expiration=0,  # No expiration by default
            server_infos=server_infos
        )
        
        if result.error:
            raise Exception(f"OpenADP registration failed: {result.error}")
        
        enc_key = result.encryption_key
        auth_codes = result.auth_codes
        
        print(f"✅ Generated encryption key with {len(result.server_infos)} servers")
        
        # Step 4: Long-Term Secret Wrapping
        print("🔐 Wrapping long-term secret...")
        
        # Generate AES-GCM parameters
        if is_debug_mode_enabled():
            # Use deterministic nonce for reproducible testing
            nonce = bytes.fromhex("0102030405060708090a0b0c")
            debug_log("Generated deterministic bytes (12 bytes)")
            debug_log(f"Using deterministic nonce: {nonce.hex()}")
        else:
            nonce = get_random_bytes(12)  # AES-GCM nonce (96 bits)
        
        debug_log(f"🔐 PYTHON AES-GCM WRAPPING DEBUG:")
        debug_log(f"   - long-term secret length: {len(long_term_secret)} bytes")
        debug_log(f"   - long-term secret hex: {long_term_secret.hex()}")
        debug_log(f"   - encryption key length: {len(enc_key)} bytes") 
        debug_log(f"   - encryption key hex: {enc_key.hex()}")
        debug_log(f"   - nonce length: {len(nonce)} bytes")
        debug_log(f"   - nonce hex: {nonce.hex()}")
        debug_log(f"   - AAD: empty (no additional authenticated data)")
        
        debug_log(f"Encrypting long-term secret ({len(long_term_secret)} bytes)")
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
        wrapped_secret, tag = cipher.encrypt_and_digest(long_term_secret)
        debug_log(f"Wrapped secret: {len(wrapped_secret)} bytes ciphertext, {len(tag)} bytes tag")
        
        debug_log(f"🔐 PYTHON AES-GCM WRAPPING RESULT:")
        debug_log(f"   - ciphertext length: {len(wrapped_secret)} bytes")
        debug_log(f"   - ciphertext hex: {wrapped_secret.hex()}")
        debug_log(f"   - tag length: {len(tag)} bytes")
        debug_log(f"   - tag hex: {tag.hex()}")
        
        # Step 5: Metadata Creation
        server_urls = [server_info.url for server_info in result.server_infos]
        metadata = {
            # Standard openadp-encrypt metadata
            "servers": server_urls,
            "threshold": result.threshold,
            "version": "1.0",
            "auth_code": auth_codes.base_auth_code,
            "user_id": user_id,
            
            # Ocrypt-specific additions
            "wrapped_long_term_secret": {
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(wrapped_secret).decode(), 
                "tag": base64.b64encode(tag).decode()
            },
            "backup_id": backup_id,
            "app_id": app_id,
            "max_guesses": max_guesses,
            "ocrypt_version": "1.0"
        }
        
        metadata_bytes = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
        
        print(f"📦 Created metadata ({len(metadata_bytes)} bytes)")
        print(f"🎯 Threshold: {result.threshold}-of-{len(result.server_infos)} recovery")
        
        return metadata_bytes
        
    except Exception as e:
        # Re-raise with more context
        raise Exception(f"Ocrypt registration failed: {e}")


def register(user_id: str, app_id: str, long_term_secret: bytes, pin: str, max_guesses: int = 10, servers_url: str = "") -> bytes:
    """
    Register a long-term secret protected by a PIN using OpenADP distributed cryptography.
    
    This function provides a simple interface that replaces traditional password hashing functions
    like bcrypt, scrypt, Argon2, and PBKDF2 with distributed threshold cryptography.
    
    For initial registration, use this function. For backup refresh, use the automatic 
    prepare/commit behavior in recover() which safely refreshes backups without risk of lockout.
    
    Args:
        user_id: Unique identifier for the user (e.g., email, username)
        app_id: Application identifier to namespace secrets per app
        long_term_secret: User-provided secret to protect (any byte sequence)
        pin: Password/PIN that will unlock the secret
        max_guesses: Maximum wrong attempts before lockout (default: 10)
        servers_url: Optional custom URL for server registry (empty string uses default)
    
    Returns:
        metadata: Opaque blob containing all recovery information (JSON bytes)
    
    Raises:
        Exception: If registration fails (network, validation, server errors, etc.)
    
    Example:
        # Initial registration
        metadata = ocrypt.register(
            user_id="alice@example.com",
            app_id="document_signing", 
            long_term_secret=private_key_bytes,
            pin="1234"
        )
        # Store metadata with user account
        
        # Later recoveries will automatically refresh backup using prepare/commit
        secret, remaining, updated_metadata = ocrypt.recover(metadata, pin)
        # updated_metadata contains refreshed backup (e.g., even → odd)
    """
    return _register_with_bid(user_id, app_id, long_term_secret, pin, max_guesses, "even", servers_url)


def recover(metadata: bytes, pin: str, servers_url: str = "") -> Tuple[bytes, int, bytes]:
    """
    Recover a long-term secret using the PIN and automatically refresh backup using two-phase commit.
    
    This function:
    1. Recovers the secret using existing backup
    2. Automatically refreshes backup using two-phase commit for crash safety
    3. Returns recovered secret plus new metadata (if refresh succeeded)
    
    Args:
        metadata: Metadata blob from previous registration
        pin: Password/PIN to unlock secret
        servers_url: Optional custom URL for server registry (empty string uses default)
        
    Returns:
        Tuple of (recovered_secret, remaining_guesses, updated_metadata)
        - recovered_secret: The original protected secret
        - remaining_guesses: 0 on success (PIN was correct)
        - updated_metadata: New metadata with refreshed backup (use this for future recoveries)
        
    Note:
        If backup refresh fails, original metadata is returned and recovery still succeeds
    
    Example:
        # Register a secret
        metadata = ocrypt.register(user_id, app_id, secret, pin, "v1")
        
        # Later: recover the secret (with automatic backup refresh)
        try:
            secret, remaining, updated_metadata = ocrypt.recover(metadata, "1234")
            # PIN was correct, backup was refreshed (v1 → v2)
            # Store updated_metadata for future use
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret)
        except Exception as e:
            # PIN was wrong or system error
            print(f"Recovery failed: {e}")
    """
    # First, recover with existing backup
    print("📋 Step 1: Recovering with existing backup...")
    secret, remaining = _recover_without_refresh(metadata, pin, servers_url)
    
    # Parse metadata to get current backup info
    try:
        metadata_dict = json.loads(metadata.decode('utf-8'))
        current_backup_id = metadata_dict["backup_id"]
        user_id = metadata_dict["user_id"]
        app_id = metadata_dict["app_id"]
        max_guesses = metadata_dict.get("max_guesses", 10)
        
        print(f"📋 Step 2: Attempting backup refresh for BID: {current_backup_id}")
        
        # Attempt to refresh backup with two-phase commit
        new_metadata, new_backup_id = _register_with_commit_internal(
            user_id, app_id, secret, pin, current_backup_id, max_guesses, servers_url
        )
        
        print(f"✅ Backup refresh successful: {current_backup_id} → {new_backup_id}")
        return secret, remaining, new_metadata
        
    except Exception as e:
        print(f"⚠️  Backup refresh failed (recovery still succeeded): {e}")
        print("🔄 Continuing with original backup")
        return secret, remaining, metadata


def _recover_without_refresh(metadata: bytes, pin: str, servers_url: str = "") -> Tuple[bytes, int]:
    """
    Internal function to recover secret without automatic backup refresh.
    This is the original recover logic, now used as a building block.
    """
    # Input validation
    if not metadata or not isinstance(metadata, bytes):
        raise Exception("metadata must be non-empty bytes")
    
    if not pin or not isinstance(pin, str):
        raise Exception("pin must be a non-empty string")
    
    try:
        # Step 1: Metadata Parsing
        try:
            metadata_dict = json.loads(metadata.decode('utf-8'))
        except Exception as e:
            raise Exception(f"Invalid metadata format: {e}")
        
        # Validate required fields
        required_fields = ['servers', 'threshold', 'auth_code', 'user_id', 'wrapped_long_term_secret', 'backup_id', 'app_id']
        for field in required_fields:
            if field not in metadata_dict:
                raise Exception(f"Missing required field in metadata: {field}")
        
        # Extract OpenADP recovery parameters
        servers = metadata_dict["servers"]
        threshold = metadata_dict["threshold"]
        base_auth_code = metadata_dict["auth_code"]
        user_id = metadata_dict["user_id"]
        
        # Extract Ocrypt-specific data
        wrapped_data = metadata_dict["wrapped_long_term_secret"]
        backup_id = metadata_dict["backup_id"]
        app_id = metadata_dict["app_id"]
        max_guesses = metadata_dict.get("max_guesses", 10)
        
        print(f"🔍 Recovering secret for user: {user_id}, app: {app_id}, bid: {backup_id}")
        
        # Step 2: OpenADP Key Recovery
        print("🌐 Getting server information from registry...")
        
        # Get server info from registry (same as decrypt tool)
        try:
            # Use provided servers_url or default
            registry_url = servers_url if servers_url else "https://servers.openadp.org/api/servers.json"
            registry_server_infos = get_servers(registry_url)
            if not registry_server_infos:
                raise Exception("No servers returned from registry")
        except Exception as e:
            print(f"   ⚠️  Failed to fetch from registry: {e}")
            print("   🔄 Falling back to hardcoded servers...")
            registry_server_infos = get_fallback_server_info()
        
        # Match metadata servers with registry servers for public keys
        matched_servers = []
        for metadata_url in servers:
            # Find matching server in registry
            matched_server = None
            for registry_server in registry_server_infos:
                if registry_server.url == metadata_url:
                    matched_server = registry_server
                    break
            
            if matched_server:
                matched_servers.append(matched_server)
                print(f"   ✅ {metadata_url} - matched in registry")
            else:
                # Server not found in registry, add without public key as fallback
                print(f"   ⚠️  {metadata_url} - not found in registry, adding without public key")
                matched_servers.append(ServerInfo(
                    url=metadata_url,
                    public_key="",
                    country="Unknown"
                ))
        
        # Reconstruct auth codes from base auth code (same as decrypt tool)
        server_auth_codes = {}
        for server_info in matched_servers:
            combined = f"{base_auth_code}:{server_info.url}"
            server_auth_codes[server_info.url] = hashlib.sha256(combined.encode()).hexdigest()
        
        auth_codes = AuthCodes(
            base_auth_code=base_auth_code,
            server_auth_codes=server_auth_codes,
            user_id=user_id
        )
        
        # Create Identity object for recovery
        identity = Identity(uid=user_id, did=app_id, bid=backup_id)
        
        print("🔑 Recovering encryption key from OpenADP servers...")
        result = recover_encryption_key(
            identity=identity,
            password=pin,
            server_infos=matched_servers,
            threshold=threshold,
            auth_codes=auth_codes
        )
        
        if result.error:
            raise Exception(f"OpenADP key recovery failed: {result.error}")
        
        enc_key = result.encryption_key
        print("✅ Successfully recovered encryption key")
        
        # Step 3: PIN Validation via Unwrapping
        print("🔐 Validating PIN by unwrapping secret...")
        
        # Extract AES-GCM parameters from metadata
        nonce = base64.b64decode(wrapped_data["nonce"])
        ciphertext = base64.b64decode(wrapped_data["ciphertext"])
        tag = base64.b64decode(wrapped_data["tag"])
        
        debug_log(f"🔓 PYTHON AES-GCM UNWRAPPING DEBUG:")
        debug_log(f"   - encryption key length: {len(enc_key)} bytes")
        debug_log(f"   - encryption key hex: {enc_key.hex()}")
        debug_log(f"   - nonce length: {len(nonce)} bytes")
        debug_log(f"   - nonce hex: {nonce.hex()}")
        debug_log(f"   - ciphertext length: {len(ciphertext)} bytes")
        debug_log(f"   - ciphertext hex: {ciphertext.hex()}")
        debug_log(f"   - tag length: {len(tag)} bytes")
        debug_log(f"   - tag hex: {tag.hex()}")
        debug_log(f"   - AAD: empty (no additional authenticated data)")
        
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
        try:
            long_term_secret = cipher.decrypt_and_verify(ciphertext, tag)
            
            debug_log(f"🔓 PYTHON AES-GCM UNWRAPPING RESULT:")
            debug_log(f"   - decrypted secret length: {len(long_term_secret)} bytes")
            debug_log(f"   - decrypted secret hex: {long_term_secret.hex()}")
            
            print("✅ PIN validation successful - secret unwrapped")
            
        except Exception as e:
            # Decryption failed = wrong PIN (or corrupted data)
            # Note: Server guess counters were already incremented during key recovery
            
            # Show helpful message with actual remaining guesses
            if result.max_guesses > 0 and result.num_guesses > 0:
                remaining = result.max_guesses - result.num_guesses
                if remaining > 0:
                    print(f"❌ Invalid PIN! You have {remaining} guesses remaining.", file=sys.stderr)
                else:
                    print("❌ Invalid PIN! No more guesses remaining - account may be locked.", file=sys.stderr)
            else:
                print("❌ Invalid PIN! Check your password and try again.", file=sys.stderr)
            
            raise Exception(f"Invalid PIN or corrupted data: {e}")
        
        # Return the recovered secret
        return long_term_secret, 0  # 0 remaining guesses = success
        
    except Exception as e:
        # Re-raise with more context if not already an Ocrypt error
        if "Ocrypt" in str(e) or "OpenADP" in str(e):
            raise e
        else:
            raise Exception(f"Ocrypt recovery failed: {e}")


def _generate_next_backup_id(current_backup_id: str) -> str:
    """
    Generate next backup ID for two-phase commit pattern.
    
    Args:
        current_backup_id: Current backup identifier
        
    Returns:
        Next backup identifier using simple alternation or versioning
    """
    # Simple alternation strategy
    if current_backup_id == "even":
        return "odd"
    elif current_backup_id == "odd":
        return "even"
    
    # Version-based strategy
    if current_backup_id.startswith("v"):
        try:
            version_num = int(current_backup_id[1:])
            return f"v{version_num + 1}"
        except ValueError:
            pass
    
    # Fallback: append timestamp
    timestamp = int(time.time())
    return f"{current_backup_id}_v{timestamp}"


def _register_with_commit_internal(user_id: str, app_id: str, long_term_secret: bytes, pin: str, 
                                  current_backup_id: str, max_guesses: int = 10, servers_url: str = "") -> Tuple[bytes, str]:
    """
    Two-phase commit registration for reliable backup refresh.
    
    This function implements a prepare/commit pattern:
    1. PREPARE: Register new backup with different backup_id
    2. COMMIT: Verify new backup works by recovering from it
    3. If verification fails, old backup remains intact
    
    Args:
        user_id: Unique identifier for the user
        app_id: Application identifier
        long_term_secret: Secret to protect
        pin: Password/PIN for protection
        current_backup_id: Current backup identifier (for generating next one)
        max_guesses: Maximum wrong attempts before lockout
        servers_url: Optional custom URL for server registry (empty string uses default)
        
    Returns:
        Tuple of (new_metadata, new_backup_id)
        
    Raises:
        Exception: If backup refresh fails (old backup still valid)
    """
    # Phase 1: PREPARE - Generate new backup ID and register
    new_backup_id = _generate_next_backup_id(current_backup_id)
    
    print(f"🔄 Two-phase commit: {current_backup_id} → {new_backup_id}")
    print("📋 Phase 1: PREPARE - Registering new backup...")
    
    try:
        # Register new backup (old one still exists on servers)
        new_metadata = _register_with_bid(user_id, app_id, long_term_secret, pin, max_guesses, new_backup_id, servers_url)
        
        print("✅ Phase 1 complete: New backup registered")
        
        # Phase 2: COMMIT - Verify new backup works
        print("📋 Phase 2: COMMIT - Verifying new backup...")
        recovered_secret, remaining = _recover_without_refresh(new_metadata, pin, servers_url)
        
        if recovered_secret == long_term_secret:
            print("✅ Phase 2 complete: New backup verified and committed")
            return new_metadata, new_backup_id
        else:
            raise Exception("New backup verification failed - recovered secret doesn't match")
            
    except Exception as e:
        # ROLLBACK - New backup failed, but old one should still work
        print(f"❌ Two-phase commit failed: {e}")
        print("🔄 ROLLBACK: Old backup remains intact")
        raise Exception(f"Backup refresh failed, old backup still valid: {e}")


class RecoverAndReregisterResult(NamedTuple):
    """Result of recover_and_reregister operation"""
    secret: bytes  # The recovered long-term secret
    new_metadata: bytes  # Fresh metadata from re-registration


def recover_and_reregister(old_metadata: bytes, pin: str, servers_url: str = "") -> RecoverAndReregisterResult:
    """
    Recover a long-term secret and re-register with fresh cryptographic material.
    
    This function:
    1. Recovers the secret using the old metadata
    2. Performs a completely fresh registration with new cryptographic material
    3. Returns both the recovered secret and new metadata
    
    This is the recommended approach for recovery as it provides:
    - Fresh cryptographic material (new nonces, keys, etc.)
    - Clean separation between recovery and registration
    - Consistent behavior across language SDKs
    
    Args:
        old_metadata: Metadata blob from previous registration
        pin: Password/PIN to unlock secret
        servers_url: Optional custom URL for server registry (empty string uses default)
        
    Returns:
        RecoverAndReregisterResult with:
        - secret: The recovered long-term secret
        - new_metadata: Fresh metadata for future recoveries
        
    Raises:
        Exception: If recovery or re-registration fails
        
    Example:
        # Recover and get fresh metadata
        result = ocrypt.recover_and_reregister(old_metadata, "1234")
        secret = result.secret
        new_metadata = result.new_metadata
        
        # Use the secret
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret)
        
        # Store new_metadata for future recoveries
        save_metadata_to_user_account(new_metadata)
    """
    print("🔄 Step 1: Recovering secret from old metadata...")
    
    # Step 1: Recover the secret using existing metadata
    secret, remaining = _recover_without_refresh(old_metadata, pin, servers_url)
    
    print("✅ Secret recovered successfully")
    
    # Step 2: Parse old metadata to get user info for re-registration
    try:
        old_metadata_dict = json.loads(old_metadata.decode('utf-8'))
        user_id = old_metadata_dict["user_id"]
        app_id = old_metadata_dict["app_id"]
        max_guesses = old_metadata_dict.get("max_guesses", 10)
    except Exception as e:
        raise Exception(f"Failed to parse old metadata: {e}")
    
    print(f"🔄 Step 2: Re-registering with fresh cryptographic material...")
    print(f"   User: {user_id}, App: {app_id}")
    
    # Step 3: Fresh registration with the recovered secret
    # Generate next backup ID to ensure alternation (critical for prepare/commit safety)
    old_backup_id = old_metadata_dict.get("backup_id", "even")
    backup_id = _generate_next_backup_id(old_backup_id)
    print(f"🔄 Backup ID alternation: {old_backup_id} → {backup_id}")
    debug_log(f"Backup ID alternation: {old_backup_id} → {backup_id}")
    
    new_metadata = _register_with_bid(
        user_id=user_id,
        app_id=app_id,
        long_term_secret=secret,
        pin=pin,
        max_guesses=max_guesses,
        backup_id=backup_id,
        servers_url=servers_url
    )
    
    print("✅ Re-registration completed with fresh cryptographic material")
    
    return RecoverAndReregisterResult(
        secret=secret,
        new_metadata=new_metadata
    )


# Module metadata
__version__ = "0.1.3"
__author__ = "OpenADP Team"
__description__ = "Drop-in replacement for password hashing functions using distributed cryptography"

# Export public API
__all__ = [
    'register',
    'recover',
    'recover_and_reregister'
] 