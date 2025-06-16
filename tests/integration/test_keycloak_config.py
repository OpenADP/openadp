#!/usr/bin/env python3
"""
Test script to debug Keycloak client configuration for PKCE + DPoP.
"""

import requests
import json
from urllib.parse import urlencode

def test_keycloak_config():
    """Test Keycloak configuration step by step."""
    
    print("🔍 Testing Keycloak Configuration")
    print("=" * 50)
    
    # Test 1: Check discovery document
    print("1. Testing discovery document...")
    try:
        response = requests.get("http://localhost:8081/realms/openadp/.well-known/openid-configuration")
        response.raise_for_status()
        discovery = response.json()
        
        print(f"   ✅ Authorization endpoint: {discovery.get('authorization_endpoint')}")
        print(f"   ✅ Token endpoint: {discovery.get('token_endpoint')}")
        
        # Check if PKCE is supported
        code_challenge_methods = discovery.get('code_challenge_methods_supported', [])
        print(f"   ✅ PKCE methods supported: {code_challenge_methods}")
        
        if 'S256' not in code_challenge_methods:
            print("   ⚠️  S256 not in supported methods - this might be an issue")
            
    except Exception as e:
        print(f"   ❌ Discovery failed: {e}")
        return
    
    # Test 2: Try a simple authorization request (without DPoP first)
    print("\n2. Testing basic authorization request...")
    
    auth_params = {
        'response_type': 'code',
        'client_id': 'cli-test',
        'redirect_uri': 'http://localhost:8889/callback',
        'scope': 'openid email profile',
        'state': 'test-state-123',
        'code_challenge': 'test-challenge',
        'code_challenge_method': 'S256'
    }
    
    auth_url = f"{discovery['authorization_endpoint']}?{urlencode(auth_params)}"
    print(f"   🔗 Authorization URL: {auth_url}")
    
    # Test the authorization endpoint
    try:
        # Just test if the endpoint accepts our parameters (should redirect or show login)
        response = requests.get(auth_url, allow_redirects=False, timeout=5)
        print(f"   📊 Response status: {response.status_code}")
        
        if response.status_code == 302:
            print("   ✅ Redirect response (normal for auth endpoint)")
            location = response.headers.get('Location', '')
            if 'login' in location.lower():
                print("   ✅ Redirected to login page - client config looks OK")
            else:
                print(f"   🔍 Redirected to: {location}")
        elif response.status_code == 400:
            print("   ❌ Bad Request - likely client configuration issue")
            print(f"   📄 Response: {response.text[:200]}...")
        else:
            print(f"   🔍 Unexpected status: {response.status_code}")
            print(f"   📄 Response: {response.text[:200]}...")
            
    except Exception as e:
        print(f"   ❌ Authorization endpoint test failed: {e}")
    
    # Test 3: Check if we can get client info (if endpoint exists)
    print("\n3. Checking client configuration...")
    print("   💡 To verify client config, check Keycloak Admin Console:")
    print("   🔗 http://localhost:8081/admin")
    print("   📍 Realms → openadp → Clients → cli-test")
    print("   ✅ Required settings:")
    print("      - Access Type: public")
    print("      - Standard Flow Enabled: ON")
    print("      - Valid Redirect URIs: http://localhost:8889/callback")
    print("      - Web Origins: * (for testing)")

if __name__ == "__main__":
    test_keycloak_config() 