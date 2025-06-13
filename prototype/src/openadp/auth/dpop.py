"""
DPoP (Demonstration of Proof-of-Possession) header generation.

This module implements RFC 9449 DPoP header creation for proving
possession of private keys bound to access tokens.
"""

import json
import time
import uuid
from typing import Dict, Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import base64


def make_dpop_header(method: str, url: str, private_key: ec.EllipticCurvePrivateKey, 
                    access_token: str = None) -> str:
    """
    Create a DPoP header for the given HTTP request.
    
    Args:
        method: HTTP method (e.g., "POST", "GET")
        url: Full URL of the request
        private_key: EC private key for signing
        access_token: Optional access token for ath claim
        
    Returns:
        Base64url-encoded DPoP JWT header value
    """
    # Parse URL to get the HTTP URI (htu)
    parsed = urlparse(url)
    htu = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # Create JWK from private key for the header
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    def int_to_base64url(value: int, byte_length: int) -> str:
        byte_value = value.to_bytes(byte_length, byteorder='big')
        return base64.urlsafe_b64encode(byte_value).decode('ascii').rstrip('=')
    
    x_b64 = int_to_base64url(public_numbers.x, 32)
    y_b64 = int_to_base64url(public_numbers.y, 32)
    
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": x_b64,
        "y": y_b64,
        "use": "sig",
        "alg": "ES256"
    }
    
    # Create JWT header
    header = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk
    }
    
    # Create JWT payload
    now = int(time.time())
    payload = {
        "jti": str(uuid.uuid4()),  # Unique identifier for replay protection
        "htm": method.upper(),     # HTTP method
        "htu": htu,               # HTTP URI (without query/fragment)
        "iat": now,               # Issued at
        "exp": now + 60           # Expires in 60 seconds
    }
    
    # Add access token hash if provided
    if access_token:
        # Create SHA-256 hash of access token
        token_hash = hashes.Hash(hashes.SHA256())
        token_hash.update(access_token.encode('utf-8'))
        ath_bytes = token_hash.finalize()
        # Base64url encode (without padding)
        ath = base64.urlsafe_b64encode(ath_bytes).decode('ascii').rstrip('=')
        payload["ath"] = ath
    
    # Encode header and payload
    def base64url_encode(data: Dict[str, Any]) -> str:
        json_bytes = json.dumps(data, separators=(',', ':')).encode('utf-8')
        return base64.urlsafe_b64encode(json_bytes).decode('ascii').rstrip('=')
    
    header_b64 = base64url_encode(header)
    payload_b64 = base64url_encode(payload)
    
    # Create signing input
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    # Sign with ES256 (ECDSA using P-256 and SHA-256)
    signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    
    # Convert DER signature to raw format (r || s)
    # DER format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
    der_sig = signature
    
    # Parse DER signature to extract r and s
    if der_sig[0] != 0x30:
        raise ValueError("Invalid DER signature format")
    
    # Skip sequence tag and length
    offset = 2
    
    # Parse r
    if der_sig[offset] != 0x02:
        raise ValueError("Invalid DER signature format - expected INTEGER for r")
    offset += 1
    r_len = der_sig[offset]
    offset += 1
    r_bytes = der_sig[offset:offset + r_len]
    offset += r_len
    
    # Parse s  
    if der_sig[offset] != 0x02:
        raise ValueError("Invalid DER signature format - expected INTEGER for s")
    offset += 1
    s_len = der_sig[offset]
    offset += 1
    s_bytes = der_sig[offset:offset + s_len]
    
    # Remove leading zeros and pad to 32 bytes
    def normalize_coordinate(coord_bytes: bytes) -> bytes:
        # Remove leading zero bytes
        while len(coord_bytes) > 1 and coord_bytes[0] == 0:
            coord_bytes = coord_bytes[1:]
        # Pad to 32 bytes
        if len(coord_bytes) < 32:
            coord_bytes = b'\x00' * (32 - len(coord_bytes)) + coord_bytes
        elif len(coord_bytes) > 32:
            coord_bytes = coord_bytes[-32:]  # Take last 32 bytes
        return coord_bytes
    
    r_normalized = normalize_coordinate(r_bytes)
    s_normalized = normalize_coordinate(s_bytes)
    
    # Concatenate r and s for raw signature
    raw_signature = r_normalized + s_normalized
    
    # Base64url encode signature
    signature_b64 = base64.urlsafe_b64encode(raw_signature).decode('ascii').rstrip('=')
    
    # Create final JWT
    dpop_jwt = f"{header_b64}.{payload_b64}.{signature_b64}"
    
    return dpop_jwt


def extract_jti_from_dpop(dpop_header: str) -> str:
    """
    Extract the jti (JWT ID) from a DPoP header for replay protection.
    
    Args:
        dpop_header: The DPoP JWT header value
        
    Returns:
        The jti claim value
        
    Raises:
        ValueError: If the DPoP header is invalid
    """
    try:
        # Split JWT into parts
        parts = dpop_header.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        # Decode payload (add padding if needed)
        payload_b64 = parts[1]
        # Add padding if needed
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += '=' * padding
            
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        if 'jti' not in payload:
            raise ValueError("Missing jti claim in DPoP header")
            
        return payload['jti']
        
    except Exception as e:
        raise ValueError(f"Failed to extract jti from DPoP header: {e}")


def validate_dpop_claims(dpop_header: str, expected_method: str, expected_url: str) -> Dict[str, Any]:
    """
    Validate DPoP header claims without signature verification.
    
    Args:
        dpop_header: The DPoP JWT header value
        expected_method: Expected HTTP method
        expected_url: Expected HTTP URL
        
    Returns:
        Dictionary of validated claims
        
    Raises:
        ValueError: If claims are invalid
    """
    try:
        # Split JWT into parts
        parts = dpop_header.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        # Decode payload
        payload_b64 = parts[1]
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += '=' * padding
            
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        # Validate required claims
        required_claims = ['jti', 'htm', 'htu', 'iat']
        for claim in required_claims:
            if claim not in payload:
                raise ValueError(f"Missing required claim: {claim}")
        
        # Validate HTTP method
        if payload['htm'] != expected_method.upper():
            raise ValueError(f"HTTP method mismatch: expected {expected_method}, got {payload['htm']}")
        
        # Validate HTTP URI
        parsed = urlparse(expected_url)
        expected_htu = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if payload['htu'] != expected_htu:
            raise ValueError(f"HTTP URI mismatch: expected {expected_htu}, got {payload['htu']}")
        
        # Validate timestamp (allow 60 second clock skew)
        now = int(time.time())
        iat = payload['iat']
        if abs(now - iat) > 120:  # 2 minutes total window
            raise ValueError(f"DPoP timestamp too old or too new: {iat} vs {now}")
        
        # Check expiration if present
        if 'exp' in payload and now > payload['exp']:
            raise ValueError("DPoP header has expired")
        
        return payload
        
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in DPoP payload: {e}")
    except Exception as e:
        raise ValueError(f"Failed to validate DPoP claims: {e}") 