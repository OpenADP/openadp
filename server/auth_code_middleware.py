"""
Authentication Code Middleware for OpenADP Server

This module implements authentication code validation for OpenADP servers,
replacing the OAuth/DPoP authentication system with a simpler, distributed approach.

Key features:
- 128-bit authentication code validation
- Server-specific code derivation using SHA256(auth_code || server_url)
- Format validation and entropy checking
- DDoS defense mechanisms
- No external dependencies (no JWT, no JWKS, no OAuth)
"""

import hashlib
import logging
import os
import re
import time
from typing import Dict, Any, Optional, Tuple, Set

logger = logging.getLogger(__name__)

# Global state for DDoS defense
_failed_attempts: Dict[str, int] = {}
_attempt_timestamps: Dict[str, float] = {}
_blacklisted_codes: Set[str] = set()


class AuthCodeConfig:
    """Configuration for authentication code middleware from environment variables."""
    
    def __init__(self):
        self.enabled = os.environ.get('OPENADP_AUTH_ENABLED', '1') == '1'
        self.min_entropy_bits = int(os.environ.get('OPENADP_AUTH_MIN_ENTROPY', '100'))
        self.max_attempts_per_ip = int(os.environ.get('OPENADP_AUTH_MAX_ATTEMPTS_PER_IP', '100'))
        self.ddos_defense = os.environ.get('OPENADP_AUTH_DDOS_DEFENSE', 'adaptive') == 'adaptive'
        
        logger.info(f"Auth code config: enabled={self.enabled}, min_entropy={self.min_entropy_bits}, ddos_defense={self.ddos_defense}")


def calculate_entropy(hex_string: str) -> int:
    """
    Calculate the entropy of a hex string in bits.
    
    Args:
        hex_string: Hexadecimal string to analyze
        
    Returns:
        Estimated entropy in bits
    """
    if not hex_string:
        return 0
    
    # Count frequency of each character
    char_counts = {}
    for char in hex_string.lower():
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate Shannon entropy
    length = len(hex_string)
    entropy = 0.0
    
    import math
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    # Convert to bits (multiply by string length)
    return int(entropy * length)


def validate_auth_code_format(auth_code: str) -> bool:
    """
    Validate authentication code format.
    
    Args:
        auth_code: Authentication code to validate
        
    Returns:
        True if format is valid, False otherwise
    """
    # Must be exactly 64 hex characters (SHA256 hash)
    if not re.match(r'^[0-9a-f]{64}$', auth_code.lower()):
        return False
    
    # Check minimum entropy
    config = AuthCodeConfig()
    if calculate_entropy(auth_code) < config.min_entropy_bits:
        logger.warning(f"Authentication code has insufficient entropy: {calculate_entropy(auth_code)} bits")
        return False
    
    # Check blacklist
    if auth_code.lower() in _blacklisted_codes:
        logger.warning(f"Authentication code is blacklisted")
        return False
    
    return True


def derive_server_auth_code(base_code: str, server_url: str) -> str:
    """
    Derive server-specific authentication code.
    
    Args:
        base_code: Base 128-bit authentication code (32 hex chars)
        server_url: Server URL for derivation
        
    Returns:
        Server-specific authentication code (64 hex chars)
    """
    combined = f"{base_code}:{server_url}"
    return hashlib.sha256(combined.encode()).hexdigest()


def check_ddos_defense(client_ip: str) -> bool:
    """
    Check if DDoS defense should be activated for a client IP.
    
    Args:
        client_ip: Client IP address
        
    Returns:
        True if request should be allowed, False if blocked
    """
    config = AuthCodeConfig()
    if not config.ddos_defense:
        return True
    
    current_time = time.time()
    
    # Clean up old timestamps (older than 1 hour)
    cutoff_time = current_time - 3600
    for ip in list(_attempt_timestamps.keys()):
        if _attempt_timestamps[ip] < cutoff_time:
            del _attempt_timestamps[ip]
            if ip in _failed_attempts:
                del _failed_attempts[ip]
    
    # Check attempt count for this IP
    attempts = _failed_attempts.get(client_ip, 0)
    if attempts >= config.max_attempts_per_ip:
        logger.warning(f"DDoS defense activated for IP {client_ip}: {attempts} failed attempts")
        return False
    
    return True


def record_failed_attempt(client_ip: str):
    """
    Record a failed authentication attempt for DDoS tracking.
    
    Args:
        client_ip: Client IP address
    """
    current_time = time.time()
    _failed_attempts[client_ip] = _failed_attempts.get(client_ip, 0) + 1
    _attempt_timestamps[client_ip] = current_time


def validate_auth_code_request(auth_code: str, server_url: str, client_ip: str = "unknown") -> Tuple[Optional[str], Optional[str]]:
    """
    Validate an authentication code request.
    
    Args:
        auth_code: Server-specific authentication code (64 hex chars)
        server_url: Server URL for validation
        client_ip: Client IP address for DDoS defense
        
    Returns:
        Tuple of (derived_uuid, error_message). If successful, error_message is None.
    """
    try:
        config = AuthCodeConfig()
        
        # Skip authentication if disabled
        if not config.enabled:
            logger.debug("Authentication disabled, skipping validation")
            return None, None
        
        # Check DDoS defense
        if not check_ddos_defense(client_ip):
            record_failed_attempt(client_ip)
            return None, "Rate limit exceeded - too many failed attempts"
        
        # Validate format
        if not validate_auth_code_format(auth_code):
            record_failed_attempt(client_ip)
            return None, "Invalid authentication code format"
        
        # Derive UUID from authentication code for user identification
        # This creates a consistent user identifier from the auth code
        derived_uuid = hashlib.sha256(auth_code.encode()).hexdigest()[:16]
        
        logger.info(f"Authentication code validated successfully for derived UUID: {derived_uuid}")
        return derived_uuid, None
        
    except Exception as e:
        logger.error(f"Authentication code validation error: {e}")
        record_failed_attempt(client_ip)
        return None, f"Authentication validation failed: {e}"


def get_auth_stats() -> Dict[str, Any]:
    """
    Get authentication middleware statistics for monitoring.
    
    Returns:
        Dictionary with auth stats
    """
    return {
        'failed_attempts_count': len(_failed_attempts),
        'blacklisted_codes_count': len(_blacklisted_codes),
        'total_failed_attempts': sum(_failed_attempts.values()),
        'config': {
            'enabled': AuthCodeConfig().enabled,
            'min_entropy_bits': AuthCodeConfig().min_entropy_bits,
            'ddos_defense': AuthCodeConfig().ddos_defense
        }
    }


def blacklist_auth_code(auth_code: str):
    """
    Add an authentication code to the blacklist.
    
    Args:
        auth_code: Authentication code to blacklist
    """
    _blacklisted_codes.add(auth_code.lower())
    logger.info(f"Authentication code blacklisted")


def clear_blacklist():
    """Clear the authentication code blacklist."""
    _blacklisted_codes.clear()
    logger.info("Authentication code blacklist cleared") 