"""
Key generation and management for DPoP authentication.

This module handles:
- EC P-256 keypair generation for DPoP
- Private key persistence with secure file permissions
- JWK (JSON Web Key) format conversion
"""

import json
import os
import stat
from pathlib import Path
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import base64


def generate_keypair() -> Tuple[ec.EllipticCurvePrivateKey, Dict[str, Any]]:
    """
    Generate an EC P-256 keypair for DPoP.
    
    Returns:
        Tuple of (private_key_object, public_jwk_dict)
    """
    # Generate EC P-256 private key
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Get public key
    public_key = private_key.public_key()
    
    # Convert public key to JWK format
    public_numbers = public_key.public_numbers()
    
    # Convert coordinates to base64url (without padding)
    def int_to_base64url(value: int, byte_length: int) -> str:
        """Convert integer to base64url-encoded bytes of specified length."""
        byte_value = value.to_bytes(byte_length, byteorder='big')
        return base64.urlsafe_b64encode(byte_value).decode('ascii').rstrip('=')
    
    # P-256 coordinates are 32 bytes each
    x_b64 = int_to_base64url(public_numbers.x, 32)
    y_b64 = int_to_base64url(public_numbers.y, 32)
    
    # Create JWK
    public_jwk = {
        "kty": "EC",
        "crv": "P-256", 
        "x": x_b64,
        "y": y_b64,
        "use": "sig",
        "alg": "ES256"
    }
    
    return private_key, public_jwk


def save_private_key(private_key: ec.EllipticCurvePrivateKey, filepath: str) -> None:
    """
    Save private key to file with secure permissions (chmod 600).
    
    Args:
        private_key: The EC private key to save
        filepath: Path where to save the key
    """
    # Serialize private key to PEM format
    pem_data = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    
    # Ensure parent directory exists
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    
    # Write to file
    with open(filepath, 'wb') as f:
        f.write(pem_data)
    
    # Set secure permissions (owner read/write only)
    os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)


def load_private_key(filepath: str) -> ec.EllipticCurvePrivateKey:
    """
    Load private key from PEM file.
    
    Args:
        filepath: Path to the private key file
        
    Returns:
        The loaded EC private key
        
    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If key file is invalid
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Private key file not found: {filepath}")
    
    with open(filepath, 'rb') as f:
        pem_data = f.read()
    
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None
    )
    
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Loaded key is not an EC private key")
    
    return private_key


def private_key_to_jwk(private_key: ec.EllipticCurvePrivateKey) -> Dict[str, Any]:
    """
    Convert private key to public JWK format.
    
    Args:
        private_key: The EC private key
        
    Returns:
        Public JWK dictionary
    """
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    def int_to_base64url(value: int, byte_length: int) -> str:
        byte_value = value.to_bytes(byte_length, byteorder='big')
        return base64.urlsafe_b64encode(byte_value).decode('ascii').rstrip('=')
    
    x_b64 = int_to_base64url(public_numbers.x, 32)
    y_b64 = int_to_base64url(public_numbers.y, 32)
    
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": x_b64,
        "y": y_b64,
        "use": "sig",
        "alg": "ES256"
    } 