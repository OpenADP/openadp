"""
OAuth 2.0 Authorization Code flow with PKCE and DPoP support.

This module implements the Authorization Code Grant with PKCE (RFC 7636)
and DPoP token binding (RFC 9449) for secure authentication.
"""

import base64
import hashlib
import json
import secrets
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import requests

from cryptography.hazmat.primitives.asymmetric import ec
from .keys import generate_keypair, private_key_to_jwk
from .dpop import make_dpop_header, calculate_jwk_thumbprint


class PKCEFlowError(Exception):
    """Exception raised during PKCE flow operations."""
    pass


def generate_pkce_challenge() -> Tuple[str, str]:
    """
    Generate PKCE code verifier and challenge.
    
    Returns:
        Tuple of (code_verifier, code_challenge)
    """
    # Generate code verifier (43-128 characters, URL-safe)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('ascii').rstrip('=')
    
    # Generate code challenge (SHA256 hash of verifier)
    challenge_bytes = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('ascii').rstrip('=')
    
    return code_verifier, code_challenge


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


def run_pkce_flow(
    issuer_url: str,
    client_id: str,
    scopes: str = "openid email profile",
    private_key: Optional[ec.EllipticCurvePrivateKey] = None,
    redirect_port: int = 8888,
    timeout: int = 300
) -> Dict[str, Any]:
    """
    Run OAuth 2.0 Authorization Code flow with PKCE and DPoP.
    
    Args:
        issuer_url: Base URL of the OAuth issuer
        client_id: OAuth client ID
        scopes: Space-separated list of requested scopes
        private_key: Optional existing private key (generates new one if None)
        redirect_port: Port for local callback server
        timeout: Maximum time to wait for user authorization (seconds)
        
    Returns:
        Dictionary containing token information and keys
        
    Raises:
        PKCEFlowError: If the flow fails
    """
    # Generate keypair if not provided
    if private_key is None:
        private_key, public_jwk = generate_keypair()
    else:
        public_jwk = private_key_to_jwk(private_key)
    
    # Calculate JWK thumbprint for DPoP binding
    jwk_thumbprint = calculate_jwk_thumbprint(public_jwk)
    
    # Discover endpoints (with fallback for Keycloak 22.0 .well-known issue)
    well_known_url = urljoin(issuer_url.rstrip('/') + '/', '.well-known/openid-configuration')
    
    auth_endpoint = None
    token_endpoint = None
    
    try:
        response = requests.get(well_known_url, timeout=10)
        response.raise_for_status()
        discovery = response.json()
        auth_endpoint = discovery.get('authorization_endpoint')
        token_endpoint = discovery.get('token_endpoint')
        print("✅ Discovered endpoints via .well-known")
    except requests.RequestException as e:
        print(f"⚠️  .well-known discovery failed: {e}")
        print("🔧 Using direct endpoint construction (Keycloak 22.0 workaround)")
    
    # Fallback to direct endpoint construction if discovery failed
    if not auth_endpoint or not token_endpoint:
        base_url = issuer_url.rstrip('/')
        auth_endpoint = f"{base_url}/protocol/openid-connect/auth"
        token_endpoint = f"{base_url}/protocol/openid-connect/token"
        print(f"🔗 Auth endpoint: {auth_endpoint}")
        print(f"🔗 Token endpoint: {token_endpoint}")
    
    # Generate PKCE parameters
    code_verifier, code_challenge = generate_pkce_challenge()
    state = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode('ascii').rstrip('=')
    
    # Set up callback server
    redirect_uri = f"http://localhost:{redirect_port}/callback"
    
    # Start local callback server
    server = HTTPServer(('localhost', redirect_port), CallbackHandler)
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
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scopes,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
            # Note: dpop_jkt parameter removed - will bind token via DPoP header in token request
        }
        
        auth_url = f"{auth_endpoint}?{urlencode(auth_params)}"
        
        print("🔑 Generated keypair for DPoP")
        print(f"🔗 Opening browser for authorization...")
        print(f"   URL: {auth_url}")
        print(f"⏱️  Waiting up to {timeout} seconds for authorization...")
        
        # Open browser
        webbrowser.open(auth_url)
        
        # Wait for callback
        start_time = time.time()
        while time.time() - start_time < timeout:
            server.handle_request()  # Process one request
            
            if server.auth_error:
                raise PKCEFlowError(f"Authorization failed: {server.auth_error}")
            
            if server.auth_code:
                if server.auth_state != state:
                    raise PKCEFlowError("State parameter mismatch - possible CSRF attack")
                
                print("✅ Authorization code received!")
                break
            
            time.sleep(0.1)
        else:
            raise PKCEFlowError("Authorization timed out - user did not complete authorization")
        
        # Exchange authorization code for tokens with DPoP
        token_data = {
            'grant_type': 'authorization_code',
            'code': server.auth_code,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'code_verifier': code_verifier
        }
        
        # Create DPoP header for token request
        dpop_header = make_dpop_header('POST', token_endpoint, private_key)
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'DPoP': dpop_header
        }
        
        try:
            response = requests.post(token_endpoint, data=token_data, headers=headers, timeout=10)
            response.raise_for_status()
            token_response = response.json()
        except requests.RequestException as e:
            raise PKCEFlowError(f"Token exchange failed: {e}")
        
        if 'error' in token_response:
            raise PKCEFlowError(f"Token exchange error: {token_response['error']}")
        
        print("✅ Got DPoP-bound tokens!")
        
        # Return complete token information
        result = {
            'access_token': token_response.get('access_token'),
            'refresh_token': token_response.get('refresh_token'),
            'token_type': token_response.get('token_type', 'DPoP'),
            'expires_in': token_response.get('expires_in'),
            'scope': token_response.get('scope'),
            'jwk_public': public_jwk,
            'private_key': private_key
        }
        
        return result
        
    finally:
        server.shutdown()
        server.server_close()


def refresh_access_token_pkce(
    issuer_url: str,
    client_id: str,
    refresh_token: str,
    private_key: ec.EllipticCurvePrivateKey
) -> Dict[str, Any]:
    """
    Refresh an access token using a refresh token with DPoP.
    
    Args:
        issuer_url: Base URL of the OAuth issuer
        client_id: OAuth client ID
        refresh_token: The refresh token
        private_key: DPoP private key
        
    Returns:
        Dictionary containing new token information
        
    Raises:
        PKCEFlowError: If refresh fails
    """
    # Discover token endpoint (with fallback for Keycloak 22.0 .well-known issue)
    well_known_url = urljoin(issuer_url.rstrip('/') + '/', '.well-known/openid-configuration')
    
    token_endpoint = None
    
    try:
        response = requests.get(well_known_url, timeout=10)
        response.raise_for_status()
        discovery = response.json()
        token_endpoint = discovery.get('token_endpoint')
    except requests.RequestException as e:
        print(f"⚠️  .well-known discovery failed: {e}")
        print("🔧 Using direct endpoint construction (Keycloak 22.0 workaround)")
    
    # Fallback to direct endpoint construction if discovery failed
    if not token_endpoint:
        base_url = issuer_url.rstrip('/')
        token_endpoint = f"{base_url}/protocol/openid-connect/token"
    
    # Prepare refresh request
    token_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': client_id
    }
    
    # Create DPoP header for token request
    dpop_header = make_dpop_header('POST', token_endpoint, private_key)
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'DPoP': dpop_header
    }
    
    try:
        response = requests.post(token_endpoint, data=token_data, headers=headers, timeout=10)
        response.raise_for_status()
        token_response = response.json()
    except requests.RequestException as e:
        raise PKCEFlowError(f"Token refresh failed: {e}")
    
    if 'error' in token_response:
        raise PKCEFlowError(f"Token refresh error: {token_response['error']}")
    
    # Return new token information
    public_jwk = private_key_to_jwk(private_key)
    
    result = {
        'access_token': token_response.get('access_token'),
        'refresh_token': token_response.get('refresh_token', refresh_token),  # Keep old if not provided
        'token_type': token_response.get('token_type', 'DPoP'),
        'expires_in': token_response.get('expires_in'),
        'scope': token_response.get('scope'),
        'jwk_public': public_jwk,
        'private_key': private_key
    }
    
    return result 