#!/usr/bin/env python3
"""
Manual OAuth Token Exchange Script

This script manually exchanges an authorization code from a callback URL
for access tokens using the PKCE flow with DPoP support.
"""

import sys
import json
import base64
import hashlib
import secrets
import requests
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import ec

# Add the prototype src to path
sys.path.insert(0, 'prototype/src')

from openadp.auth.keys import generate_keypair, private_key_to_jwk, save_private_key, load_private_key
from openadp.auth.dpop import make_dpop_header

# Configuration
ISSUER_URL = "https://auth.openadp.org/realms/openadp"
CLIENT_ID = "cli-test"
CLIENT_SECRET = "openadp-cli-secret-change-in-production"  # Production client secret
REDIRECT_URI = "http://localhost:8889/callback"
PRIVATE_KEY_PATH = "~/.openadp/dpop_private_key.pem"

def generate_pkce_challenge():
    """Generate PKCE code verifier and challenge."""
    # Generate code verifier (43-128 characters, URL-safe)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('ascii').rstrip('=')
    
    # Generate code challenge (SHA256 hash of verifier)
    challenge_bytes = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('ascii').rstrip('=')
    
    return code_verifier, code_challenge

def exchange_code_for_tokens(callback_url, code_verifier=None, state=None):
    """
    Exchange authorization code for tokens.
    
    Args:
        callback_url: The full callback URL with code and state
        code_verifier: PKCE code verifier (if None, will try to generate one)
        state: Expected state parameter (if None, will skip validation)
    """
    print("🔄 Parsing callback URL...")
    
    # Parse the callback URL
    parsed_url = urlparse(callback_url)
    query_params = parse_qs(parsed_url.query)
    
    auth_code = query_params.get('code', [None])[0]
    auth_state = query_params.get('state', [None])[0]
    auth_error = query_params.get('error', [None])[0]
    
    if auth_error:
        print(f"❌ Authorization failed: {auth_error}")
        return None
    
    if not auth_code:
        print("❌ No authorization code found in callback URL")
        return None
    
    print(f"✅ Found authorization code: {auth_code[:20]}...")
    print(f"✅ State parameter: {auth_state}")
    
    # Validate state if provided
    if state and auth_state != state:
        print("❌ State parameter mismatch - possible CSRF attack")
        return None
    
    # Generate or use provided code verifier
    if not code_verifier:
        print("⚠️  No code verifier provided - this will likely fail")
        print("   The authorization was initiated with a specific code verifier")
        print("   that we don't have access to. Trying with a new one anyway...")
        code_verifier, _ = generate_pkce_challenge()
    
    # Load or generate DPoP key pair
    print("🔑 Setting up DPoP key pair...")
    private_key = None
    
    try:
        import os
        key_path = os.path.expanduser(PRIVATE_KEY_PATH)
        if os.path.exists(key_path):
            private_key = load_private_key(key_path)
            print("✅ Loaded existing DPoP private key")
        else:
            print("🔑 Generating new DPoP key pair...")
            private_key, public_jwk = generate_keypair()
            
            # Save the key for future use
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
            save_private_key(private_key, key_path)
            print(f"💾 Saved DPoP private key to {key_path}")
    except Exception as e:
        print(f"⚠️  Key handling error: {e}")
        print("🔑 Generating temporary key pair...")
        private_key, public_jwk = generate_keypair()
    
    # Discover token endpoint
    print("🔍 Discovering OAuth endpoints...")
    well_known_url = f"{ISSUER_URL}/.well-known/openid-configuration"
    
    try:
        response = requests.get(well_known_url, timeout=10)
        response.raise_for_status()
        discovery = response.json()
        token_endpoint = discovery.get('token_endpoint')
        
        # Ensure token endpoint uses HTTPS
        if token_endpoint and token_endpoint.startswith('http://'):
            token_endpoint = token_endpoint.replace('http://', 'https://')
            print(f"🔒 Upgraded token endpoint to HTTPS: {token_endpoint}")
        else:
            print(f"✅ Token endpoint: {token_endpoint}")
    except requests.RequestException as e:
        print(f"⚠️  Discovery failed: {e}")
        print("🔧 Using direct endpoint construction...")
        token_endpoint = f"{ISSUER_URL}/protocol/openid-connect/token"
        print(f"🔗 Token endpoint: {token_endpoint}")
    
    # Prepare token exchange request
    print("🔄 Exchanging authorization code for tokens...")
    
    token_data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code_verifier': code_verifier
    }
    
    # Create DPoP header for token request
    dpop_header = make_dpop_header('POST', token_endpoint, private_key)
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'DPoP': dpop_header
    }
    
    try:
        # Use a session to handle redirects properly
        session = requests.Session()
        response = session.post(token_endpoint, data=token_data, headers=headers, timeout=10, allow_redirects=True)
        
        print(f"📊 Response status: {response.status_code}")
        print(f"📊 Final URL: {response.url}")
        
        if response.status_code == 200:
            token_response = response.json()
            print("✅ Successfully exchanged code for tokens!")
            
            # Create complete token data
            public_jwk = private_key_to_jwk(private_key)
            
            result = {
                'access_token': token_response.get('access_token'),
                'refresh_token': token_response.get('refresh_token'),
                'token_type': token_response.get('token_type', 'DPoP'),
                'expires_in': token_response.get('expires_in'),
                'scope': token_response.get('scope'),
                'jwk_public': public_jwk,
                'private_key': private_key
            }
            
            # Save token cache
            try:
                import os
                cache_dir = os.path.expanduser("~/.openadp")
                cache_path = os.path.join(cache_dir, "token_cache.json")
                
                cache_data = {
                    'access_token': result['access_token'],
                    'refresh_token': result.get('refresh_token'),
                    'token_type': result['token_type'],
                    'expires_in': result.get('expires_in'),
                    'scope': result.get('scope'),
                    'jwk_public': result['jwk_public']
                }
                
                os.makedirs(cache_dir, exist_ok=True)
                with open(cache_path, 'w') as f:
                    json.dump(cache_data, f, indent=2)
                
                print(f"💾 Saved token cache to {cache_path}")
            except Exception as e:
                print(f"⚠️  Failed to save token cache: {e}")
            
            return result
            
        else:
            try:
                error_response = response.json()
            except:
                error_response = response.text
            
            print(f"❌ Token exchange failed: {error_response}")
            
            if response.status_code == 400:
                print("\n💡 Common causes:")
                print("   • Authorization code has expired")
                print("   • Wrong code_verifier (PKCE mismatch)")
                print("   • Code already used")
                print("   • Invalid redirect_uri")
            elif response.status_code == 401:
                print("\n💡 This suggests authentication issues:")
                print("   • Invalid client_id")
                print("   • Client not configured properly")
            
            return None
            
    except requests.RequestException as e:
        print(f"❌ Token exchange request failed: {e}")
        return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python manual_token_exchange.py <callback_url>")
        print("\nExample:")
        print("python manual_token_exchange.py 'http://localhost:8889/callback?state=Y3sfE1hqlQ5xjoFJIE0aOw&session_state=d1e8d943-2d78-4782-89c1-1e9727f16f98&code=f782b4a5-5d5b-48c5-94a1-c18806308c00.d1e8d943-2d78-4782-89c1-1e9727f16f98.11f8fb3c-6e4c-472c-ab98-a0f16f569c2e'")
        sys.exit(1)
    
    callback_url = sys.argv[1]
    
    print("🔐 Manual OAuth Token Exchange")
    print("=" * 50)
    print(f"📋 Callback URL: {callback_url}")
    print()
    
    result = exchange_code_for_tokens(callback_url)
    
    if result:
        print("\n🎉 Token exchange successful!")
        print(f"   Token type: {result['token_type']}")
        print(f"   Expires in: {result.get('expires_in', 'unknown')} seconds")
        print(f"   Scope: {result.get('scope', 'unknown')}")
        print(f"   Access token: {result['access_token'][:50]}...")
        
        if result.get('refresh_token'):
            print(f"   Refresh token: {result['refresh_token'][:50]}...")
        
        print("\n✅ You can now use OpenADP tools with authentication!")
    else:
        print("\n❌ Token exchange failed")
        print("\n💡 If the code has expired, you'll need to restart the authentication flow:")
        print("   python prototype/tools/encrypt.py <filename>")

if __name__ == "__main__":
    main() 