#!/usr/bin/env python3
"""
Fix OpenADP Realm Configuration
Diagnoses and fixes issues with the OpenADP realm.
"""

import requests
import json
import sys
import os

def get_admin_token(base_url, admin_user, admin_password):
    """Get admin access token"""
    token_url = f"{base_url}/realms/master/protocol/openid-connect/token"
    
    data = {
        'grant_type': 'password',
        'client_id': 'admin-cli',
        'username': admin_user,
        'password': admin_password
    }
    
    response = requests.post(token_url, data=data)
    if response.status_code != 200:
        raise Exception(f"Failed to get admin token: {response.status_code} - {response.text}")
    
    return response.json()['access_token']

def make_request(base_url, token, method, endpoint, data=None):
    """Make authenticated request to Keycloak Admin API"""
    url = f"{base_url}/admin{endpoint}"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    if method.upper() == 'GET':
        response = requests.get(url, headers=headers)
    elif method.upper() == 'PUT':
        response = requests.put(url, headers=headers, json=data)
    else:
        raise ValueError(f"Unsupported method: {method}")
    
    return response

def main():
    KEYCLOAK_URL = "http://localhost:8081"
    ADMIN_USER = "admin"
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'mZMENyzLWI0g')
    REALM_NAME = "openadp"
    
    print("🔧 Diagnosing OpenADP Realm Configuration")
    print("=" * 50)
    
    try:
        # Get admin token
        token = get_admin_token(KEYCLOAK_URL, ADMIN_USER, ADMIN_PASSWORD)
        print("✅ Connected to Keycloak admin API")
        
        # Get realm configuration
        response = make_request(KEYCLOAK_URL, token, 'GET', f'/realms/{REALM_NAME}')
        if response.status_code != 200:
            print(f"❌ Failed to get realm: {response.status_code} - {response.text}")
            return
        
        realm_config = response.json()
        print(f"✅ Found realm '{REALM_NAME}'")
        print(f"   - Enabled: {realm_config.get('enabled', 'UNKNOWN')}")
        print(f"   - ID: {realm_config.get('id', 'UNKNOWN')}")
        print(f"   - SSL Required: {realm_config.get('sslRequired', 'UNKNOWN')}")
        
        # Check if we need to fix SSL requirement
        if realm_config.get('sslRequired') == 'external':
            print("\n🔧 Fixing SSL requirement for development...")
            realm_config['sslRequired'] = 'none'
            
            response = make_request(KEYCLOAK_URL, token, 'PUT', f'/realms/{REALM_NAME}', realm_config)
            if response.status_code == 204:
                print("✅ Updated SSL requirement to 'none'")
            else:
                print(f"❌ Failed to update realm: {response.status_code} - {response.text}")
                return
        
        # Test the OpenID configuration endpoint
        print(f"\n🧪 Testing OpenID configuration endpoint...")
        test_response = requests.get(f"{KEYCLOAK_URL}/realms/{REALM_NAME}/.well-known/openid_configuration")
        if test_response.status_code == 200:
            config = test_response.json()
            print("✅ OpenID configuration endpoint working!")
            print(f"   - Issuer: {config.get('issuer', 'NOT FOUND')}")
            print(f"   - Authorization endpoint: {config.get('authorization_endpoint', 'NOT FOUND')}")
            print(f"   - Token endpoint: {config.get('token_endpoint', 'NOT FOUND')}")
            print(f"   - DPoP support: {'dpop_signing_alg_values_supported' in config}")
        else:
            print(f"❌ OpenID configuration still not working: {test_response.status_code}")
            print(f"   Response: {test_response.text}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 