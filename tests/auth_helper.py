#!/usr/bin/env python3
"""
Authentication Helper for E2E Testing

Provides programmatic token generation from fake Keycloak server
without requiring browser interaction.
"""

import json
import time
import hashlib
import base64
import secrets
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_test_dpop_keypair():
    """Generate a test DPoP keypair for authentication."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # Convert to JWK format
    public_numbers = private_key.public_key().public_numbers()
    
    def int_to_base64url(value: int, byte_length: int) -> str:
        byte_value = value.to_bytes(byte_length, byteorder='big')
        return base64.urlsafe_b64encode(byte_value).decode('ascii').rstrip('=')
    
    x_b64 = int_to_base64url(public_numbers.x, 32)
    y_b64 = int_to_base64url(public_numbers.y, 32)
    
    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": x_b64,
        "y": y_b64,
        "use": "sig",
        "alg": "ES256"
    }
    
    return private_key, public_jwk

def calculate_jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """Calculate JWK thumbprint for DPoP binding."""
    # Create canonical JWK for thumbprint calculation
    canonical_jwk = {
        "crv": jwk["crv"],
        "kty": jwk["kty"],
        "x": jwk["x"],
        "y": jwk["y"]
    }
    
    jwk_json = json.dumps(canonical_jwk, sort_keys=True, separators=(',', ':'))
    thumbprint_bytes = hashlib.sha256(jwk_json.encode()).digest()
    return base64.urlsafe_b64encode(thumbprint_bytes).decode().rstrip('=')

def create_test_token_direct(fake_keycloak_server, username: str = "alice", password: str = "password123", 
                           client_id: str = "cli-test", dpop_jwk: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Create a test token directly from the fake Keycloak server without HTTP requests.
    
    Args:
        fake_keycloak_server: The FakeKeycloakServer instance
        username: Username for authentication
        password: Password for authentication  
        client_id: OAuth client ID
        dpop_jwk: Optional DPoP JWK for token binding
        
    Returns:
        Dictionary containing token data and keys
    """
    # Get the server's internal components
    config = fake_keycloak_server.config
    token_manager = fake_keycloak_server.token_manager
    
    # Find the user
    user = next((u for u in config.users 
                if u["username"] == username and u["password"] == password), None)
    if not user:
        raise ValueError(f"User {username} not found or invalid password")
    
    # Find the client
    client = next((c for c in config.clients if c["client_id"] == client_id), None)
    if not client:
        raise ValueError(f"Client {client_id} not found")
    
    # Create access token with DPoP binding
    access_token = token_manager.create_access_token(user, client_id, dpop_jwk)
    refresh_token = token_manager.create_refresh_token(user, client_id)
    
    return {
        "access_token": access_token,
        "token_type": "DPoP" if dpop_jwk else "Bearer",
        "expires_in": config.token_lifetime,
        "refresh_token": refresh_token,
        "scope": "openid profile email",
        "user": user,
        "client": client
    }

def create_test_auth_data(fake_keycloak_server, username: str = "alice", password: str = "password123",
                         client_id: str = "cli-test") -> Dict[str, Any]:
    """
    Create complete authentication data for testing including DPoP keypair and token.
    
    Args:
        fake_keycloak_server: The FakeKeycloakServer instance
        username: Username for authentication
        password: Password for authentication
        client_id: OAuth client ID
        
    Returns:
        Dictionary containing all authentication materials
    """
    # Generate DPoP keypair
    private_key, public_jwk = generate_test_dpop_keypair()
    
    # Create token with DPoP binding
    token_data = create_test_token_direct(
        fake_keycloak_server, 
        username=username, 
        password=password,
        client_id=client_id,
        dpop_jwk=public_jwk
    )
    
    return {
        "access_token": token_data["access_token"],
        "token_type": token_data["token_type"],
        "expires_in": token_data["expires_in"],
        "refresh_token": token_data["refresh_token"],
        "scope": token_data["scope"],
        "private_key": private_key,
        "public_key_jwk": public_jwk,
        "jwk_thumbprint": calculate_jwk_thumbprint(public_jwk),
        "user": token_data["user"],
        "client": token_data["client"],
        "needs_signing": True  # Indicates this needs handshake signing
    }

def create_dpop_header(method: str, url: str, private_key, access_token: str, 
                      nonce: Optional[str] = None) -> str:
    """
    Create a DPoP header for HTTP requests.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        private_key: DPoP private key
        access_token: Access token to bind
        nonce: Optional nonce from server
        
    Returns:
        DPoP header value (JWT)
    """
    import jwt
    
    # Create DPoP claims
    now = int(time.time())
    claims = {
        "jti": secrets.token_urlsafe(16),
        "htm": method.upper(),
        "htu": url,
        "iat": now,
        "ath": base64.urlsafe_b64encode(
            hashlib.sha256(access_token.encode()).digest()
        ).decode().rstrip('=')
    }
    
    if nonce:
        claims["nonce"] = nonce
    
    # Sign with private key
    return jwt.encode(claims, private_key, algorithm="ES256")

def validate_token_with_fake_keycloak(token: str, fake_keycloak_server) -> Dict[str, Any]:
    """
    Validate a token against the fake Keycloak server.
    
    Args:
        token: JWT token to validate
        fake_keycloak_server: The FakeKeycloakServer instance
        
    Returns:
        Decoded token payload
    """
    import jwt
    
    # Get the server's JWK for validation
    jwk_manager = fake_keycloak_server.jwk_manager
    public_key = jwk_manager.public_key
    
    try:
        # Decode and validate the token
        payload = jwt.decode(token, public_key, algorithms=["ES256"])
        return payload
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Token validation failed: {e}")

def print_auth_debug_info(auth_data: Dict[str, Any]):
    """Print debug information about authentication data."""
    print("🔐 Authentication Debug Info:")
    print(f"  👤 User: {auth_data['user']['username']} ({auth_data['user']['sub']})")
    print(f"  🔧 Client: {auth_data['client']['client_id']}")
    print(f"  🎫 Token Type: {auth_data['token_type']}")
    print(f"  ⏰ Expires In: {auth_data['expires_in']} seconds")
    print(f"  🔑 JWK Thumbprint: {auth_data['jwk_thumbprint'][:16]}...")
    print(f"  📝 Scope: {auth_data['scope']}")
    
    # Decode token to show claims
    try:
        import jwt
        payload = jwt.decode(auth_data['access_token'], options={"verify_signature": False})
        print(f"  📋 Token Claims:")
        print(f"    - iss: {payload.get('iss')}")
        print(f"    - sub: {payload.get('sub')}")
        print(f"    - aud: {payload.get('aud')}")
        print(f"    - exp: {payload.get('exp')}")
        print(f"    - cnf.jkt: {payload.get('cnf', {}).get('jkt', 'None')[:16]}...")
    except Exception as e:
        print(f"  ⚠️  Could not decode token: {e}")

if __name__ == "__main__":
    # Test the auth helper functions
    print("Testing authentication helper functions...")
    
    # Test keypair generation
    private_key, public_jwk = generate_test_dpop_keypair()
    thumbprint = calculate_jwk_thumbprint(public_jwk)
    
    print(f"✅ Generated DPoP keypair")
    print(f"   JWK: {public_jwk}")
    print(f"   Thumbprint: {thumbprint}")
    
    print("✅ Authentication helper functions working correctly")