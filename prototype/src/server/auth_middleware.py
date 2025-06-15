"""
Authentication middleware for OpenADP server.

This module implements Phase 2 server-side authentication:
- JWT token validation against JWKS
- DPoP header validation with replay protection
- JWKS caching with TTL
- Environment-based configuration

Supports both Cloudflare Access and direct OIDC providers.
"""

import json
import os
import time
import logging
from typing import Dict, Any, Optional, Tuple, Set
from urllib.parse import urlparse
from urllib.request import urlopen

# Make JWT import optional for servers without PyJWT installed
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    jwt = None

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64

# Import DPoP validation functions from Phase 1
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from openadp.auth.dpop import validate_dpop_claims, extract_jti_from_dpop

logger = logging.getLogger(__name__)

# Global state for middleware
_jwks_cache = {}
_jwks_cache_expiry = 0
_jti_cache: Set[str] = set()
_jti_cache_timestamps = {}


class AuthConfig:
    """Configuration for authentication middleware from environment variables."""
    
    def __init__(self):
        self.enabled = os.environ.get('OPENADP_AUTH_ENABLED', '1') == '1'
        self.issuer = os.environ.get('OPENADP_AUTH_ISSUER', '')
        self.jwks_url = os.environ.get('OPENADP_AUTH_JWKS_URL', '')
        self.cache_ttl = int(os.environ.get('OPENADP_AUTH_CACHE_TTL', '3600'))
        
        # Auto-derive JWKS URL if not provided
        if self.issuer and not self.jwks_url:
            self.jwks_url = f"{self.issuer.rstrip('/')}/.well-known/jwks.json"
            
        # Warn if JWT package is not available but auth is enabled
        if self.enabled and not JWT_AVAILABLE:
            logger.warning("Authentication enabled but PyJWT package not available - authentication will fail")
            
        logger.info(f"Auth config: enabled={self.enabled}, issuer={self.issuer}, jwks_url={self.jwks_url}, jwt_available={JWT_AVAILABLE}")


def get_jwks(jwks_url: str, cache_ttl: int = 3600) -> Dict[str, Any]:
    """
    Fetch JWKS from the provider with caching.
    
    Args:
        jwks_url: URL to fetch JWKS from
        cache_ttl: Cache TTL in seconds
        
    Returns:
        JWKS dictionary
        
    Raises:
        Exception: If JWKS cannot be fetched
    """
    global _jwks_cache, _jwks_cache_expiry
    
    now = time.time()
    
    # Return cached JWKS if still valid
    if _jwks_cache and now < _jwks_cache_expiry:
        logger.debug("Using cached JWKS")
        return _jwks_cache
    
    # Fetch fresh JWKS
    logger.info(f"Fetching JWKS from {jwks_url}")
    try:
        # Create request with User-Agent header (required by Cloudflare)
        from urllib.request import Request
        req = Request(jwks_url)
        req.add_header('User-Agent', 'OpenADP-Server/1.0')
        with urlopen(req) as response:
            jwks_data = json.loads(response.read().decode('utf-8'))
        
        # Cache the JWKS
        _jwks_cache = jwks_data
        _jwks_cache_expiry = now + cache_ttl
        
        logger.info(f"JWKS cached for {cache_ttl} seconds")
        return jwks_data
        
    except Exception as e:
        logger.error(f"Failed to fetch JWKS from {jwks_url}: {e}")
        raise Exception(f"JWKS fetch failed: {e}")


def validate_jwt_token(token: str, jwks_url: str, expected_issuer: str) -> Dict[str, Any]:
    """
    Validate JWT token signature and claims.
    
    Args:
        token: JWT access token
        jwks_url: JWKS endpoint URL
        expected_issuer: Expected issuer claim
        
    Returns:
        Decoded JWT claims
        
    Raises:
        Exception: If token validation fails
    """
    if not JWT_AVAILABLE:
        raise Exception("JWT validation not available: PyJWT package not installed")
    
    try:
        # Get JWKS for signature verification
        jwks = get_jwks(jwks_url)
        
        # Decode token header to get key ID
        token_header = jwt.get_unverified_header(token)
        kid = token_header.get('kid')
        
        if not kid:
            raise Exception("Missing 'kid' in JWT header")
        
        # Find matching key in JWKS
        key_data = None
        for key in jwks.get('keys', []):
            if key.get('kid') == kid:
                key_data = key
                break
        
        if not key_data:
            raise Exception(f"Key '{kid}' not found in JWKS")
        
        # Convert JWK to cryptography key for verification
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
        
        # Verify and decode token
        claims = jwt.decode(
            token,
            public_key,
            algorithms=['RS256', 'ES256'],
            issuer=expected_issuer,
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_iat': True,
                'verify_iss': True,
                'verify_aud': False,  # Audience validation may vary
                'require': ['exp', 'iat', 'iss', 'sub']
            }
        )
        
        logger.debug(f"JWT validation successful for subject: {claims.get('sub', 'unknown')}")
        return claims
        
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError as e:
        raise Exception(f"Invalid token: {e}")
    except Exception as e:
        raise Exception(f"Token validation failed: {e}")


def validate_dpop_header(dpop_header: str, method: str, url: str, access_token: str) -> Dict[str, Any]:
    """
    Validate DPoP header using Phase 1 validation functions.
    
    Args:
        dpop_header: DPoP JWT header value
        method: HTTP method
        url: Request URL
        access_token: Access token for ath validation
        
    Returns:
        DPoP claims dictionary
        
    Raises:
        Exception: If DPoP validation fails
    """
    try:
        # Extract and check JTI for replay protection
        jti = extract_jti_from_dpop(dpop_header)
        
        # Check JTI cache for replay protection
        if jti in _jti_cache:
            raise Exception(f"Replay attack detected: JTI '{jti}' already used")
        
        # Validate DPoP claims (reusing Phase 1 function)
        dpop_claims = validate_dpop_claims(dpop_header, method, url)
        
        # Validate access token hash (ath claim)
        expected_ath = dpop_claims.get('ath')
        if expected_ath:
            # Calculate expected hash
            import hashlib
            token_hash = hashlib.sha256(access_token.encode('utf-8')).digest()
            expected_ath_calculated = base64.urlsafe_b64encode(token_hash).decode('ascii').rstrip('=')
            
            if expected_ath != expected_ath_calculated:
                raise Exception("Access token hash mismatch in DPoP header")
        
        # Add JTI to cache (with timestamp for cleanup)
        _jti_cache.add(jti)
        _jti_cache_timestamps[jti] = time.time()
        
        # Clean up old JTIs (keep last 5 minutes)
        cleanup_jti_cache()
        
        logger.debug(f"DPoP validation successful for JTI: {jti}")
        return dpop_claims
        
    except Exception as e:
        logger.warning(f"DPoP validation failed: {e}")
        raise Exception(f"DPoP validation failed: {e}")


def cleanup_jti_cache(max_age: int = 300) -> None:
    """
    Clean up old JTIs from the replay protection cache.
    
    Args:
        max_age: Maximum age in seconds to keep JTIs (default: 5 minutes)
    """
    global _jti_cache, _jti_cache_timestamps
    
    now = time.time()
    expired_jtis = []
    
    for jti, timestamp in _jti_cache_timestamps.items():
        if now - timestamp > max_age:
            expired_jtis.append(jti)
    
    for jti in expired_jtis:
        _jti_cache.discard(jti)
        _jti_cache_timestamps.pop(jti, None)
    
    if expired_jtis:
        logger.debug(f"Cleaned up {len(expired_jtis)} expired JTIs from cache")


def validate_auth(request_body: bytes, headers: Dict[str, str], request_method: str = "POST", 
                 request_url: str = "http://localhost:8080") -> Tuple[Optional[str], Optional[str]]:
    """
    Validate authentication for an HTTP request.
    
    Args:
        request_body: HTTP request body (for method validation)
        headers: HTTP headers dictionary
        request_method: HTTP method (default: POST)
        request_url: Full request URL
        
    Returns:
        Tuple of (user_id, error_message). If successful, error_message is None.
    """
    try:
        config = AuthConfig()
        
        # Skip authentication if disabled
        if not config.enabled:
            logger.debug("Authentication disabled, skipping validation")
            return None, None
        
        # Check required configuration
        if not config.issuer:
            return None, "Server misconfiguration: OPENADP_AUTH_ISSUER not set"
        
        # Check if JWT package is available when auth is enabled
        if not JWT_AVAILABLE:
            return None, "Server misconfiguration: PyJWT package not installed but authentication is enabled"
        
        # Extract Authorization header
        auth_header = headers.get('Authorization', '').strip()
        if not auth_header:
            return None, "Missing Authorization header"
        
        # Parse Authorization header (expect "DPoP <access_token>")
        if not auth_header.startswith('DPoP '):
            return None, "Authorization header must use DPoP scheme"
        
        access_token = auth_header[5:]  # Remove "DPoP " prefix
        
        # Extract DPoP header
        dpop_header = headers.get('DPoP', '').strip()
        if not dpop_header:
            return None, "Missing DPoP header"
        
        # Validate JWT token
        try:
            jwt_claims = validate_jwt_token(access_token, config.jwks_url, config.issuer)
        except Exception as e:
            return None, f"JWT validation failed: {e}"
        
        # Validate DPoP header
        try:
            dpop_claims = validate_dpop_header(dpop_header, request_method, request_url, access_token)
        except Exception as e:
            return None, f"DPoP validation failed: {e}"
        
        # Extract user ID from JWT claims
        user_id = jwt_claims.get('sub')
        if not user_id:
            return None, "Missing 'sub' claim in JWT token"
        
        logger.info(f"Authentication successful for user: {user_id}")
        return user_id, None
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return None, f"Authentication failed: {e}"


def get_auth_stats() -> Dict[str, Any]:
    """
    Get authentication middleware statistics for monitoring.
    
    Returns:
        Dictionary with auth stats
    """
    return {
        'jti_cache_size': len(_jti_cache),
        'jwks_cache_expired': time.time() >= _jwks_cache_expiry,
        'jwks_cache_ttl_remaining': max(0, _jwks_cache_expiry - time.time()),
        'jwt_available': JWT_AVAILABLE,
        'config': {
            'enabled': AuthConfig().enabled,
            'issuer': AuthConfig().issuer,
            'jwks_url': AuthConfig().jwks_url
        }
    } 