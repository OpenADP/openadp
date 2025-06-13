"""
OAuth 2.0 Device Code flow implementation for OpenADP.

This module handles the Device Authorization Grant flow (RFC 8628)
with DPoP token binding for secure authentication.
"""

import json
import time
import requests
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urljoin

from cryptography.hazmat.primitives.asymmetric import ec
from .keys import generate_keypair, private_key_to_jwk


class DeviceFlowError(Exception):
    """Exception raised during device flow operations."""
    pass


def run_device_flow(
    issuer_url: str,
    client_id: str,
    scopes: str = "openid email profile",
    private_key: Optional[ec.EllipticCurvePrivateKey] = None,
    timeout: int = 600
) -> Dict[str, Any]:
    """
    Run OAuth 2.0 Device Code flow to obtain tokens.
    
    Args:
        issuer_url: Base URL of the OAuth issuer (e.g., "http://localhost:8080/realms/openadp")
        client_id: OAuth client ID
        scopes: Space-separated list of requested scopes
        private_key: Optional existing private key (generates new one if None)
        timeout: Maximum time to wait for user authorization (seconds)
        
    Returns:
        Dictionary containing:
        - access_token: The access token
        - refresh_token: The refresh token (if available)
        - token_type: Token type (usually "Bearer" or "DPoP")
        - expires_in: Token lifetime in seconds
        - scope: Granted scopes
        - jwk_public: Public JWK for DPoP
        - private_key: The private key object
        
    Raises:
        DeviceFlowError: If the flow fails
    """
    # Generate keypair if not provided
    if private_key is None:
        private_key, public_jwk = generate_keypair()
    else:
        public_jwk = private_key_to_jwk(private_key)
    
    # Discover endpoints
    well_known_url = urljoin(issuer_url.rstrip('/') + '/', '.well-known/openid-configuration')
    
    try:
        response = requests.get(well_known_url, timeout=10)
        response.raise_for_status()
        discovery = response.json()
    except requests.RequestException as e:
        raise DeviceFlowError(f"Failed to discover OAuth endpoints: {e}")
    
    device_auth_endpoint = discovery.get('device_authorization_endpoint')
    token_endpoint = discovery.get('token_endpoint')
    
    if not device_auth_endpoint:
        raise DeviceFlowError("Device authorization endpoint not found in discovery document")
    if not token_endpoint:
        raise DeviceFlowError("Token endpoint not found in discovery document")
    
    # Step 1: Request device authorization
    device_auth_data = {
        'client_id': client_id,
        'scope': scopes
    }
    
    try:
        response = requests.post(device_auth_endpoint, data=device_auth_data, timeout=10)
        response.raise_for_status()
        device_response = response.json()
    except requests.RequestException as e:
        raise DeviceFlowError(f"Device authorization request failed: {e}")
    
    # Extract device flow parameters
    device_code = device_response.get('device_code')
    user_code = device_response.get('user_code')
    verification_uri = device_response.get('verification_uri')
    verification_uri_complete = device_response.get('verification_uri_complete')
    expires_in = device_response.get('expires_in', 600)
    interval = device_response.get('interval', 5)
    
    if not all([device_code, user_code, verification_uri]):
        raise DeviceFlowError("Incomplete device authorization response")
    
    print(f"🔑 Generated keypair (for future DPoP use)")
    print(f"📱 Device code: {device_code}")
    
    # Use complete URI if available, otherwise construct it
    if verification_uri_complete:
        auth_url = verification_uri_complete
    else:
        auth_url = f"{verification_uri}?user_code={user_code}"
    
    print(f"🔗 Visit: {auth_url}")
    print(f"⏱️  Expires in: {expires_in} seconds")
    print()
    print("👆 Complete authentication in your browser, then press Enter...")
    
    # Wait for user to start authentication
    input()
    
    # Step 2: Poll for tokens
    start_time = time.time()
    poll_count = 0
    
    while time.time() - start_time < min(timeout, expires_in):
        poll_count += 1
        print(f"🔄 Polling attempt {poll_count}...")
        
        # Prepare token request
        token_data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_code,
            'client_id': client_id
        }
        
        # Add DPoP public key if supported
        # Note: Standard Device Flow doesn't directly support DPoP binding
        # This is a preparation for when the IdP supports it
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        try:
            response = requests.post(token_endpoint, data=token_data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Success!
                token_response = response.json()
                print("✅ Got tokens!")
                
                # Return complete token information
                result = {
                    'access_token': token_response.get('access_token'),
                    'refresh_token': token_response.get('refresh_token'),
                    'token_type': token_response.get('token_type', 'Bearer'),
                    'expires_in': token_response.get('expires_in'),
                    'scope': token_response.get('scope'),
                    'jwk_public': public_jwk,
                    'private_key': private_key
                }
                
                return result
                
            elif response.status_code == 400:
                error_response = response.json()
                error_code = error_response.get('error')
                
                if error_code == 'authorization_pending':
                    # User hasn't completed authorization yet
                    time.sleep(interval)
                    continue
                elif error_code == 'slow_down':
                    # Increase polling interval
                    interval += 5
                    time.sleep(interval)
                    continue
                elif error_code == 'expired_token':
                    raise DeviceFlowError("Device code expired - please restart the flow")
                elif error_code == 'access_denied':
                    raise DeviceFlowError("User denied authorization")
                else:
                    raise DeviceFlowError(f"Token request failed: {error_code}")
            else:
                raise DeviceFlowError(f"Token request failed with status {response.status_code}")
                
        except requests.RequestException as e:
            raise DeviceFlowError(f"Token request failed: {e}")
    
    raise DeviceFlowError("Device flow timed out - user did not complete authorization in time")


def refresh_access_token(
    issuer_url: str,
    client_id: str,
    refresh_token: str,
    private_key: ec.EllipticCurvePrivateKey
) -> Dict[str, Any]:
    """
    Refresh an access token using a refresh token.
    
    Args:
        issuer_url: Base URL of the OAuth issuer
        client_id: OAuth client ID
        refresh_token: The refresh token
        private_key: Private key for DPoP binding
        
    Returns:
        Dictionary containing new token information
        
    Raises:
        DeviceFlowError: If refresh fails
    """
    # Discover token endpoint
    well_known_url = urljoin(issuer_url.rstrip('/') + '/', '.well-known/openid-configuration')
    
    try:
        response = requests.get(well_known_url, timeout=10)
        response.raise_for_status()
        discovery = response.json()
    except requests.RequestException as e:
        raise DeviceFlowError(f"Failed to discover OAuth endpoints: {e}")
    
    token_endpoint = discovery.get('token_endpoint')
    if not token_endpoint:
        raise DeviceFlowError("Token endpoint not found in discovery document")
    
    # Prepare refresh request
    token_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': client_id
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    try:
        response = requests.post(token_endpoint, data=token_data, headers=headers, timeout=10)
        response.raise_for_status()
        token_response = response.json()
        
        # Convert private key to JWK
        public_jwk = private_key_to_jwk(private_key)
        
        return {
            'access_token': token_response.get('access_token'),
            'refresh_token': token_response.get('refresh_token', refresh_token),  # May be rotated
            'token_type': token_response.get('token_type', 'Bearer'),
            'expires_in': token_response.get('expires_in'),
            'scope': token_response.get('scope'),
            'jwk_public': public_jwk,
            'private_key': private_key
        }
        
    except requests.RequestException as e:
        raise DeviceFlowError(f"Token refresh failed: {e}")


def validate_token_response(token_data: Dict[str, Any]) -> None:
    """
    Validate that a token response contains required fields.
    
    Args:
        token_data: Token response dictionary
        
    Raises:
        DeviceFlowError: If required fields are missing
    """
    required_fields = ['access_token', 'token_type']
    missing_fields = [field for field in required_fields if not token_data.get(field)]
    
    if missing_fields:
        raise DeviceFlowError(f"Token response missing required fields: {missing_fields}")
    
    # Validate token type
    token_type = token_data.get('token_type', '').lower()
    if token_type not in ['bearer', 'dpop']:
        print(f"⚠️  Warning: Unexpected token type '{token_type}', expected 'Bearer' or 'DPoP'")


def get_userinfo(issuer_url: str, access_token: str) -> Dict[str, Any]:
    """
    Get user information using an access token.
    
    Args:
        issuer_url: Base URL of the OAuth issuer
        access_token: The access token
        
    Returns:
        User information dictionary
        
    Raises:
        DeviceFlowError: If userinfo request fails
    """
    # Discover userinfo endpoint
    well_known_url = urljoin(issuer_url.rstrip('/') + '/', '.well-known/openid-configuration')
    
    try:
        response = requests.get(well_known_url, timeout=10)
        response.raise_for_status()
        discovery = response.json()
    except requests.RequestException as e:
        raise DeviceFlowError(f"Failed to discover OAuth endpoints: {e}")
    
    userinfo_endpoint = discovery.get('userinfo_endpoint')
    if not userinfo_endpoint:
        raise DeviceFlowError("Userinfo endpoint not found in discovery document")
    
    # Make userinfo request
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    try:
        response = requests.get(userinfo_endpoint, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
        
    except requests.RequestException as e:
        raise DeviceFlowError(f"Userinfo request failed: {e}") 