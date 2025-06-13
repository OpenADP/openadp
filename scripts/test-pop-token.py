#!/usr/bin/env python3
"""
Test script for PoP token generation in OpenADP Phase 0.
Demonstrates device code flow and captures sample tokens.
"""

import json
import base64
import time
import urllib.parse
import urllib.request
import urllib.error
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import jwt
import secrets

KEYCLOAK_URL = "http://localhost:8080"
REALM = "openadp"
CLIENT_ID = "cli-test"

def generate_keypair():
    """Generate RSA keypair for DPoP."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Convert to JWK format for DPoP
    public_numbers = private_key.public_key().public_numbers()
    
    def int_to_base64url_uint(val):
        val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
        return base64.urlsafe_b64encode(val_bytes).decode('ascii').rstrip('=')
    
    jwk = {
        "kty": "RSA",
        "n": int_to_base64url_uint(public_numbers.n),
        "e": int_to_base64url_uint(public_numbers.e),
        "alg": "RS256",
        "use": "sig"
    }
    
    return private_key, jwk

def create_dpop_header(private_key, jwk, method, url, access_token=None):
    """Create DPoP header as per RFC 9449."""
    now = int(time.time())
    jti = secrets.token_urlsafe(32)
    
    dpop_payload = {
        "jti": jti,
        "htm": method,
        "htu": url,
        "iat": now,
    }
    
    if access_token:
        # Add access token hash for bound tokens
        token_hash = hashes.Hash(hashes.SHA256())
        token_hash.update(access_token.encode())
        dpop_payload["ath"] = base64.urlsafe_b64encode(
            token_hash.finalize()
        ).decode('ascii').rstrip('=')
    
    # Create DPoP header
    dpop_header = jwt.encode(
        dpop_payload,
        private_key,
        algorithm="RS256",
        headers={"typ": "dpop+jwt", "jwk": jwk}
    )
    
    return dpop_header

def device_code_flow():
    """Execute OAuth 2.0 Device Code flow."""
    print("🚀 Starting Device Code flow...")
    
    # Generate keypair for future DPoP use
    private_key, jwk = generate_keypair()
    print(f"🔑 Generated keypair (for future DPoP use)")
    
    # Step 1: Device authorization request
    device_auth_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth/device"
    
    data = urllib.parse.urlencode({
        'client_id': CLIENT_ID,
        'scope': 'openid profile email'
    }).encode()
    
    req = urllib.request.Request(device_auth_url, data=data)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    
    try:
        with urllib.request.urlopen(req) as response:
            device_response = json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        print(f"❌ Device auth failed: {e.read().decode()}")
        return None, None
    
    print(f"📱 Device code: {device_response['device_code']}")
    print(f"🔗 Visit: {device_response['verification_uri_complete']}")
    print(f"⏱️  Expires in: {device_response['expires_in']} seconds")
    print("\n👆 Complete authentication in your browser, then press Enter...")
    input()
    
    # Step 2: Poll for token
    token_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    
    for attempt in range(30):  # Poll for up to 5 minutes
        print(f"🔄 Polling attempt {attempt + 1}...")
        
        data = urllib.parse.urlencode({
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_response['device_code'],
            'client_id': CLIENT_ID
        }).encode()
        
        req = urllib.request.Request(token_url, data=data)
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        # Note: DPoP header omitted for Phase 0 - using standard bearer tokens
        
        try:
            with urllib.request.urlopen(req) as response:
                token_response = json.loads(response.read().decode())
                print("✅ Got tokens!")
                return token_response, (private_key, jwk)
        except urllib.error.HTTPError as e:
            error_data = json.loads(e.read().decode())
            if error_data.get('error') == 'authorization_pending':
                time.sleep(10)
                continue
            else:
                print(f"❌ Token request failed: {error_data}")
                return None, None
    
    print("❌ Polling timed out")
    return None, None

def decode_jwt_payload(token):
    """Decode JWT payload without verification (for inspection)."""
    try:
        # Split token and decode payload
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        # Add padding if needed
        payload_b64 = parts[1]
        padding = '=' * (4 - len(payload_b64) % 4)
        payload_b64 += padding
        
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes.decode())
    except Exception as e:
        print(f"❌ Failed to decode JWT: {e}")
        return None

def test_userinfo(access_token, private_key, jwk):
    """Test token introspection at userinfo endpoint."""
    userinfo_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/userinfo"
    
    req = urllib.request.Request(userinfo_url)
    req.add_header('Authorization', f'Bearer {access_token}')
    # Note: Using Bearer token for Phase 0 - DPoP will be added in Phase 1
    
    try:
        with urllib.request.urlopen(req) as response:
            userinfo = json.loads(response.read().decode())
            print("✅ Userinfo endpoint test successful!")
            return userinfo
    except urllib.error.HTTPError as e:
        print(f"❌ Userinfo test failed: {e.read().decode()}")
        return None

def main():
    print("🧪 OpenADP Phase 0 - PoP Token Test")
    print("=" * 50)
    
    # Execute device code flow
    token_response, keys = device_code_flow()
    if not token_response:
        print("❌ Failed to get tokens")
        return
    
    private_key, jwk = keys
    access_token = token_response['access_token']
    
    print("\n📋 Token Response:")
    print(f"  Token Type: {token_response.get('token_type', 'N/A')}")
    print(f"  Expires In: {token_response.get('expires_in', 'N/A')} seconds")
    print(f"  Scope: {token_response.get('scope', 'N/A')}")
    
    # Decode and display access token payload
    print("\n🔍 Access Token Payload:")
    payload = decode_jwt_payload(access_token)
    if payload:
        print(json.dumps(payload, indent=2))
        
        # Check for cnf claim (would indicate DPoP binding in future phases)
        if 'cnf' in payload:
            print("\n✅ Token contains 'cnf' claim - DPoP binding detected!")
            print(f"   JWK Thumbprint: {payload['cnf']}")
        else:
            print("\n📝 Token using standard Bearer format (Phase 0 - DPoP will be added in Phase 1)")
    
    # Test userinfo endpoint
    print("\n🧪 Testing userinfo endpoint...")
    userinfo = test_userinfo(access_token, private_key, jwk)
    if userinfo:
        print("\nUser Info:")
        print(json.dumps(userinfo, indent=2))
    
    print("\n🎉 Phase 0 testing complete!")
    print("\nSample PoP Access Token (first 100 chars):")
    print(f"{access_token[:100]}...")

if __name__ == "__main__":
    main() 