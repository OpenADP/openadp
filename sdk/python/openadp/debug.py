"""
Debug module for OpenADP Python SDK

This module provides deterministic operations for testing and debugging,
allowing for reproducible results across different runs and languages.
It implements the same debug mode functionality as the Go and C++ versions.
"""

import logging
import threading
from typing import Optional

# Global debug state
_debug_mode = False
_debug_lock = threading.RLock()
_deterministic_counter = 0

# Configure debug logger
debug_logger = logging.getLogger('openadp.debug')
debug_logger.setLevel(logging.DEBUG)

# Create console handler if it doesn't exist
if not debug_logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[DEBUG] %(message)s')
    handler.setFormatter(formatter)
    debug_logger.addHandler(handler)

def set_debug_mode(enabled: bool) -> None:
    """Enable or disable debug mode for deterministic operations."""
    global _debug_mode, _deterministic_counter
    
    with _debug_lock:
        _debug_mode = enabled
        _deterministic_counter = 0  # Reset counter when enabling/disabling
        
        if enabled:
            debug_log("Debug mode enabled - all operations are now deterministic")
        else:
            debug_log("Debug mode disabled - randomness restored")

def is_debug_mode_enabled() -> bool:
    """Return whether debug mode is currently enabled."""
    with _debug_lock:
        return _debug_mode

def debug_log(message: str) -> None:
    """Print a debug message if debug mode is enabled."""
    with _debug_lock:
        if _debug_mode:
            debug_logger.debug(message)

def get_deterministic_main_secret() -> str:
    """
    Return a large deterministic scalar for the main secret r.
    This is a fixed large value that properly exercises the cryptographic operations.
    
    Returns the same value as Go and C++ implementations:
    0x023456789abcdef0fedcba9876543220ffd555c99f7c5421aa6ca577e195e5e23
    """
    if not _debug_mode:
        raise RuntimeError("get_deterministic_main_secret called outside debug mode")
    
    # Use the same large deterministic constant as Go and C++ implementations
    # This is the hex pattern reduced modulo Ed25519 group order q
    # 64 characters (even length) for consistent hex parsing across all SDKs
    deterministic_secret = "023456789abcdef0fedcba987654320ffd555c99f7c5421aa6ca577e195e5e23"
    
    debug_log(f"Using deterministic main secret r = 0x{deterministic_secret}")
    return deterministic_secret

    with _debug_lock:
        _deterministic_counter += 1
        debug_log(f"Using deterministic polynomial coefficient: {_deterministic_counter}")
        return _deterministic_counter

def get_deterministic_random_hex(length: int) -> str:
    """
    Return deterministic hex string for testing.
    
    Args:
        length: Number of hex characters to generate
        
    Returns:
        Deterministic hex string of specified length
    """
    global _deterministic_counter
    
    if not _debug_mode:
        raise RuntimeError("get_deterministic_random_hex called outside debug mode")
    
    with _debug_lock:
        _deterministic_counter += 1
        
        # Generate deterministic hex string
        hex_chars = []
        for i in range(length):
            hex_chars.append(f"{(_deterministic_counter + i) % 256:02x}")
        
        result = ''.join(hex_chars[:length])
        debug_log(f"Generated deterministic hex ({length} chars): {result}")
        return result

def get_deterministic_random_bytes(length: int) -> bytes:
    """
    Return deterministic bytes for testing.
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Deterministic bytes of specified length
    """
    global _deterministic_counter
    
    if not _debug_mode:
        raise RuntimeError("get_deterministic_random_bytes called outside debug mode")
    
    with _debug_lock:
        _deterministic_counter += 1
        
        # Generate deterministic bytes
        result = bytes((_deterministic_counter + i) % 256 for i in range(length))
        debug_log(f"Generated deterministic bytes ({length} bytes)")
        return result

def get_deterministic_ephemeral_secret() -> bytes:
    """
    Return a fixed ephemeral secret for reproducible Noise handshakes.
    This should be 32 bytes for X25519.
    """
    if not _debug_mode:
        raise RuntimeError("get_deterministic_ephemeral_secret called outside debug mode")
    
    debug_log("Using deterministic ephemeral secret")
    # Fixed ephemeral secret for reproducible Noise handshakes (32 bytes for X25519)
    # This should be different from the C++ client to avoid session ID collisions
    return bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04
    ])

# Convenience functions for common debug operations
def secure_random_scalar() -> Optional[str]:
    """
    Return either deterministic or cryptographically secure random scalar.
    In debug mode, returns the deterministic main secret.
    In normal mode, returns None (caller should generate secure random).
    """
    if _debug_mode:
        return get_deterministic_main_secret()
    return None
