#!/usr/bin/env python3
"""
Debug Authentication Endpoints

This script checks what endpoints the Keycloak server is returning
and helps diagnose the HTTP/HTTPS mismatch issue.
"""

import requests
import json

def check_discovery_endpoints():
    """Check what endpoints are returned by the discovery document."""
    print("🔍 Debugging Authentication Endpoints")
    print("=" * 60)
    
    issuer_urls = [
        "https://auth.openadp.org/realms/openadp",
        "http://auth.openadp.org/realms/openadp"
    ]
    
    for issuer_url in issuer_urls:
        print(f"\n🌐 Testing issuer: {issuer_url}")
        well_known_url = f"{issuer_url}/.well-known/openid-configuration"
        
        try:
            print(f"📡 Requesting: {well_known_url}")
            response = requests.get(well_known_url, timeout=10)
            response.raise_for_status()
            
            config = response.json()
            
            print(f"✅ Discovery successful!")
            print(f"   - Issuer: {config.get('issuer', 'Not found')}")
            print(f"   - Authorization Endpoint: {config.get('authorization_endpoint', 'Not found')}")
            print(f"   - Token Endpoint: {config.get('token_endpoint', 'Not found')}")
            print(f"   - JWKS URI: {config.get('jwks_uri', 'Not found')}")
            print(f"   - UserInfo Endpoint: {config.get('userinfo_endpoint', 'Not found')}")
            
            # Check if endpoints match the issuer protocol
            token_endpoint = config.get('token_endpoint', '')
            auth_endpoint = config.get('authorization_endpoint', '')
            
            if issuer_url.startswith('https://') and not token_endpoint.startswith('https://'):
                print(f"⚠️  PROTOCOL MISMATCH: Issuer uses HTTPS but token endpoint uses HTTP")
            elif issuer_url.startswith('http://') and not token_endpoint.startswith('http://'):
                print(f"⚠️  PROTOCOL MISMATCH: Issuer uses HTTP but token endpoint uses HTTPS")
            else:
                print(f"✅ Protocol consistency check passed")
                
        except requests.RequestException as e:
            print(f"❌ Failed to connect: {e}")
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON response: {e}")

def test_token_endpoint():
    """Test direct access to the token endpoint to see what methods are allowed."""
    print(f"\n🔧 Testing Token Endpoint Access")
    print("=" * 60)
    
    # Test both HTTP and HTTPS versions
    token_endpoints = [
        "https://auth.openadp.org/realms/openadp/protocol/openid-connect/token",
        "http://auth.openadp.org/realms/openadp/protocol/openid-connect/token"
    ]
    
    for endpoint in token_endpoints:
        print(f"\n🎯 Testing endpoint: {endpoint}")
        
        try:
            # Try OPTIONS request to see what methods are allowed
            response = requests.options(endpoint, timeout=10)
            print(f"   OPTIONS status: {response.status_code}")
            
            if 'Allow' in response.headers:
                print(f"   Allowed methods: {response.headers['Allow']}")
            else:
                print(f"   No 'Allow' header found")
                
        except requests.RequestException as e:
            print(f"   ❌ OPTIONS failed: {e}")
        
        try:
            # Try GET request (should fail but might give us useful info)
            response = requests.get(endpoint, timeout=10)
            print(f"   GET status: {response.status_code}")
            
        except requests.RequestException as e:
            print(f"   ❌ GET failed: {e}")
        
        try:
            # Try POST request with minimal data (should also fail but differently)
            response = requests.post(endpoint, data={'test': 'value'}, timeout=10)
            print(f"   POST status: {response.status_code}")
            
        except requests.RequestException as e:
            print(f"   ❌ POST failed: {e}")

def main():
    """Main debug function."""
    print("🚀 OpenADP Authentication Endpoint Debug")
    print("=" * 60)
    
    check_discovery_endpoints()
    test_token_endpoint()
    
    print(f"\n" + "=" * 60)
    print("🔍 Debug Summary:")
    print("If you see protocol mismatches above, the issue is likely:")
    print("1. Keycloak is configured to return HTTP URLs in discovery")
    print("2. But clients are trying to access HTTPS URLs")
    print("3. This causes the 405 Method Not Allowed error")
    print("\n💡 Solutions:")
    print("1. Configure Keycloak to return HTTPS URLs in discovery")
    print("2. Or update client configuration to use HTTP")
    print("3. Check Keycloak's frontend URL configuration")

if __name__ == "__main__":
    main() 