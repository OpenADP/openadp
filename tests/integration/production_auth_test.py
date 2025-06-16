#!/usr/bin/env python3
"""
Production Authentication Test

This script tests authentication against the production Keycloak server
with proper client secret handling for confidential clients.
"""

import sys
import json
import base64
import hashlib
import secrets
import requests
import webbrowser
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import urlparse, parse_qs, urlencode
from cryptography.hazmat.primitives.asymmetric import ec

# Add the prototype src to path
sys.path.insert(0, 'prototype/src')

from openadp.auth.keys import generate_keypair, private_key_to_jwk, save_private_key, load_private_key
from openadp.auth.dpop import make_dpop_header

# Production configuration
ISSUER_URL = "https://auth.openadp.org/realms/openadp"
CLIENT_ID = "cli-test"
CLIENT_SECRET = "openadp-cli-secret-change-in-production"
REDIRECT_PORT = 8889
PRIVATE_KEY_PATH = "~/.openadp/dpop_private_key.pem"

class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback."""
    
    def do_GET(self):
        """Handle OAuth callback GET request."""
        # Parse query parameters
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        # Store the authorization code and state
        self.server.auth_code = query_params.get('code', [None])[0]
        self.server.auth_state = query_params.get('state', [None])[0]
        self.server.auth_error = query_params.get('error', [None])[0]
        
        # Send response to browser
        if self.server.auth_error:
            response_html = f"""
            <html><body>
            <h2>❌ Authorization Failed</h2>
            <p>Error: {self.server.auth_error}</p>
            <p>You can close this window.</p>
            </body></html>
            """
        elif self.server.auth_code:
            response_html = """
            <html><body>
            <h2>✅ Authorization Successful!</h2>
            <p>You can close this window and return to the terminal.</p>
            </body></html>
            """
        else:
            response_html = """
            <html><body>
            <h2>⚠️ Authorization Response</h2>
            <p>No authorization code received. You can close this window.</p>
            </body></html>
            """
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(response_html)))
        self.end_headers()
        self.wfile.write(response_html.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Suppress log messages."""
        pass

def generate_pkce_challenge():
    """Generate PKCE code verifier and challenge."""
    # Generate code verifier (43-128 characters, URL-safe)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('ascii').rstrip('=')
    
    # Generate code challenge (SHA256 hash of verifier)
    challenge_bytes = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('ascii').rstrip('=')
    
    return code_verifier, code_challenge

def run_production_auth_flow():
    """Run OAuth 2.0 Authorization Code flow with PKCE and DPoP for production."""
    
    print("🔐 Production OpenADP Authentication")
    print("=" * 50)
    print(f"🌐 Issuer: {ISSUER_URL}")
    print(f"🔧 Client: {CLIENT_ID}")
    print()
    
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
    
    # Discover endpoints
    print("🔍 Discovering OAuth endpoints...")
    well_known_url = f"{ISSUER_URL}/.well-known/openid-configuration"
    
    try:
        response = requests.get(well_known_url, timeout=10)
        response.raise_for_status()
        discovery = response.json()
        auth_endpoint = discovery.get('authorization_endpoint')
        token_endpoint = discovery.get('token_endpoint')
        
        # Ensure endpoints use HTTPS
        if auth_endpoint and auth_endpoint.startswith('http://'):
            auth_endpoint = auth_endpoint.replace('http://', 'https://')
        if token_endpoint and token_endpoint.startswith('http://'):
            token_endpoint = token_endpoint.replace('http://', 'https://')
            
        print(f"✅ Auth endpoint: {auth_endpoint}")
        print(f"✅ Token endpoint: {token_endpoint}")
    except requests.RequestException as e:
        print(f"⚠️  Discovery failed: {e}")
        print("🔧 Using direct endpoint construction...")
        auth_endpoint = f"{ISSUER_URL}/protocol/openid-connect/auth"
        token_endpoint = f"{ISSUER_URL}/protocol/openid-connect/token"
        print(f"🔗 Auth endpoint: {auth_endpoint}")
        print(f"🔗 Token endpoint: {token_endpoint}")
    
    # Generate PKCE parameters
    code_verifier, code_challenge = generate_pkce_challenge()
    state = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode('ascii').rstrip('=')
    
    # Set up callback server
    redirect_uri = f"http://localhost:{REDIRECT_PORT}/callback"
    
    # Start local callback server
    server = HTTPServer(('localhost', REDIRECT_PORT), CallbackHandler)
    server.auth_code = None
    server.auth_state = None
    server.auth_error = None
    server.timeout = 1  # Short timeout for non-blocking
    
    server_thread = Thread(target=lambda: server.serve_forever())
    server_thread.daemon = True
    server_thread.start()
    
    try:
        # Build authorization URL
        auth_params = {
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'redirect_uri': redirect_uri,
            'scope': 'openid email profile',
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"{auth_endpoint}?{urlencode(auth_params)}"
        
        print("🔗 Opening browser for authorization...")
        print(f"   URL: {auth_url}")
        print(f"⏱️  Waiting up to 10 seconds for authorization...")
        print("   (You can manually visit the URL above if browser doesn't open)")
        
        # Open browser
        webbrowser.open(auth_url)
        
        # Wait for callback
        start_time = time.time()
        while time.time() - start_time < 10:
            server.handle_request()  # Process one request
            
            if server.auth_error:
                print(f"❌ Authorization failed: {server.auth_error}")
                return None
            
            if server.auth_code:
                if server.auth_state != state:
                    print("❌ State parameter mismatch - possible CSRF attack")
                    return None
                
                print("✅ Authorization code received!")
                break
            
            time.sleep(0.1)
        else:
            print("❌ Authorization timed out - user did not complete authorization")
            return None
        
        # Exchange authorization code for tokens with DPoP
        print("🔄 Exchanging authorization code for tokens...")
        
        token_data = {
            'grant_type': 'authorization_code',
            'code': server.auth_code,
            'redirect_uri': redirect_uri,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,  # Include client secret for confidential client
            'code_verifier': code_verifier
        }
        
        # Create DPoP header for token request
        dpop_header = make_dpop_header('POST', token_endpoint, private_key)
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'DPoP': dpop_header
        }
        
        try:
            session = requests.Session()
            response = session.post(token_endpoint, data=token_data, headers=headers, timeout=10, allow_redirects=True)
            
            print(f"📊 Response status: {response.status_code}")
            
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
                return None
                
        except requests.RequestException as e:
            print(f"❌ Token exchange request failed: {e}")
            return None
        
    finally:
        server.shutdown()
        server.server_close()

def main():
    import sys
    
    if len(sys.argv) > 1:
        # Manual mode: use provided callback URL
        callback_url = sys.argv[1]
        print("🔐 Production OpenADP Authentication (Manual Mode)")
        print("=" * 50)
        print(f"📋 Using provided callback URL")
        print()
        
        # Extract code and state from callback URL
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(callback_url)
        query_params = parse_qs(parsed_url.query)
        
        auth_code = query_params.get('code', [None])[0]
        auth_state = query_params.get('state', [None])[0]
        
        if not auth_code:
            print("❌ No authorization code found in callback URL")
            return
        
        print(f"✅ Found authorization code: {auth_code[:20]}...")
        print(f"✅ State parameter: {auth_state}")
        
        # Now we need to exchange this code for tokens
        # But we need the original code_verifier that was used
        print("⚠️  Manual mode detected - attempting token exchange...")
        print("   Note: This may fail due to PKCE code_verifier mismatch")
        
        # Try the manual token exchange approach
        from manual_token_exchange import exchange_code_for_tokens
        result = exchange_code_for_tokens(callback_url)
        
        if result:
            print("\n🎉 Manual token exchange successful!")
            print("=" * 50)
            print(f"   Token type: {result['token_type']}")
            print(f"   Expires in: {result.get('expires_in', 'unknown')} seconds")
            print(f"   Scope: {result.get('scope', 'unknown')}")
            print(f"   Access token: {result['access_token'][:50]}...")
            
            # Test token by decoding JWT
            try:
                import jwt
                payload = jwt.decode(result['access_token'], options={"verify_signature": False})
                user_id = payload.get('sub')
                print(f"   User ID: {user_id}")
                print(f"   Issuer: {payload.get('iss')}")
                print(f"   Audience: {payload.get('aud')}")
            except Exception as e:
                print(f"   ⚠️  Could not decode JWT: {e}")
            
            print("\n✅ You can now use OpenADP tools with production authentication!")
        else:
            print("\n❌ Manual token exchange failed")
            print("💡 The authorization code may have expired or PKCE mismatch occurred")
            print("   Try running without arguments for a fresh interactive flow")
    else:
        # Interactive mode: run full OAuth flow
        result = run_production_auth_flow()
        
        if result:
            print("\n🎉 Production authentication successful!")
            print("=" * 50)
            print(f"   Token type: {result['token_type']}")
            print(f"   Expires in: {result.get('expires_in', 'unknown')} seconds")
            print(f"   Scope: {result.get('scope', 'unknown')}")
            print(f"   Access token: {result['access_token'][:50]}...")
            
            if result.get('refresh_token'):
                print(f"   Refresh token: {result['refresh_token'][:50]}...")
            
            # Test token by decoding JWT
            try:
                import jwt
                payload = jwt.decode(result['access_token'], options={"verify_signature": False})
                user_id = payload.get('sub')
                print(f"   User ID: {user_id}")
                print(f"   Issuer: {payload.get('iss')}")
                print(f"   Audience: {payload.get('aud')}")
            except Exception as e:
                print(f"   ⚠️  Could not decode JWT: {e}")
            
            print("\n✅ You can now use OpenADP tools with production authentication!")
            print("   Try: python prototype/tools/encrypt.py --issuer https://auth.openadp.org/realms/openadp test_file.txt")
        else:
            print("\n❌ Production authentication failed")
            print("\n💡 Usage:")
            print("   Interactive: python production_auth_test.py")
            print("   Manual:      python production_auth_test.py 'http://localhost:8889/callback?code=...'")

if __name__ == "__main__":
    main() 