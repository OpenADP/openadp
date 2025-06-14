#!/usr/bin/env python3
"""
Recreate OpenADP Realm
Deletes and recreates the OpenADP realm to fix configuration issues.
"""

import requests
import json
import sys
import os
import time

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
    elif method.upper() == 'POST':
        response = requests.post(url, headers=headers, json=data)
    elif method.upper() == 'DELETE':
        response = requests.delete(url, headers=headers)
    else:
        raise ValueError(f"Unsupported method: {method}")
    
    return response

def main():
    KEYCLOAK_URL = "http://localhost:8081"
    ADMIN_USER = "admin"
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'mZMENyzLWI0g')
    REALM_NAME = "openadp"
    CLIENT_ID = "cli-test"
    
    print("🔄 Recreating OpenADP Realm")
    print("=" * 50)
    
    try:
        # Get admin token
        token = get_admin_token(KEYCLOAK_URL, ADMIN_USER, ADMIN_PASSWORD)
        print("✅ Connected to Keycloak admin API")
        
        # Delete existing realm
        print(f"\n🗑️  Deleting existing realm '{REALM_NAME}'...")
        response = make_request(KEYCLOAK_URL, token, 'DELETE', f'/realms/{REALM_NAME}')
        if response.status_code == 204:
            print("✅ Deleted existing realm")
        elif response.status_code == 404:
            print("ℹ️  Realm didn't exist")
        else:
            print(f"⚠️  Delete response: {response.status_code}")
        
        # Wait a moment
        time.sleep(2)
        
        # Create new realm with minimal configuration
        print(f"\n📁 Creating new realm '{REALM_NAME}'...")
        realm_config = {
            "realm": REALM_NAME,
            "displayName": "OpenADP Authentication",
            "enabled": True,
            "sslRequired": "none",  # Important for development
            "registrationAllowed": False,
            "loginWithEmailAllowed": True,
            "duplicateEmailsAllowed": False,
            "resetPasswordAllowed": True,
            "editUsernameAllowed": False,
            "bruteForceProtected": True,
            "defaultRoles": ["default-roles-openadp"],
            "requiredCredentials": ["password"],
            "passwordPolicy": "length(8) and digits(1) and lowerCase(1) and upperCase(1)"
        }
        
        response = make_request(KEYCLOAK_URL, token, 'POST', '/realms', realm_config)
        if response.status_code == 201:
            print("✅ Created new realm")
        else:
            print(f"❌ Failed to create realm: {response.status_code} - {response.text}")
            return
        
        # Wait for realm to be ready
        time.sleep(3)
        
        # Create DPoP-enabled client
        print(f"\n🔧 Creating client '{CLIENT_ID}'...")
        client_config = {
            "clientId": CLIENT_ID,
            "name": "OpenADP CLI Test Client",
            "description": "Client for testing OpenADP authentication with DPoP",
            "enabled": True,
            "clientAuthenticatorType": "client-secret",
            "secret": "openadp-cli-secret-change-in-production",
            "redirectUris": [
                "http://localhost:*",
                "https://localhost:*",
                "urn:ietf:wg:oauth:2.0:oob"
            ],
            "webOrigins": ["+"],
            "publicClient": False,
            "protocol": "openid-connect",
            "attributes": {
                "pkce.code.challenge.method": "S256",
                "oauth2.device.authorization.grant.enabled": "false",
                "oidc.ciba.grant.enabled": "false",
                "backchannel.logout.session.required": "true",
                "backchannel.logout.revoke.offline.tokens": "false",
                "dpop.bound.access.tokens": "true",
                "use.refresh.tokens": "true",
                "id.token.as.detached.signature": "false",
                "tls.client.certificate.bound.access.tokens": "false",
                "require.pushed.authorization.requests": "false",
                "client_credentials.use_refresh_token": "false",
                "token.response.type.bearer.lower-case": "false"
            },
            "authenticationFlowBindingOverrides": {},
            "fullScopeAllowed": True,
            "nodeReRegistrationTimeout": -1,
            "defaultClientScopes": [
                "web-origins",
                "acr", 
                "profile",
                "roles",
                "email"
            ],
            "optionalClientScopes": [
                "address",
                "phone",
                "offline_access",
                "microprofile-jwt"
            ]
        }
        
        response = make_request(KEYCLOAK_URL, token, 'POST', f'/realms/{REALM_NAME}/clients', client_config)
        if response.status_code == 201:
            print("✅ Created client with DPoP support")
        else:
            print(f"❌ Failed to create client: {response.status_code} - {response.text}")
            return
        
        # Create test user
        print(f"\n👤 Creating test user...")
        user_config = {
            "username": "testuser",
            "email": "test@openadp.org",
            "emailVerified": True,
            "enabled": True,
            "firstName": "Test",
            "lastName": "User",
            "credentials": [
                {
                    "type": "password",
                    "value": "TestPass123!",
                    "temporary": False
                }
            ]
        }
        
        response = make_request(KEYCLOAK_URL, token, 'POST', f'/realms/{REALM_NAME}/users', user_config)
        if response.status_code == 201:
            print("✅ Created test user")
        else:
            print(f"❌ Failed to create user: {response.status_code} - {response.text}")
            return
        
        # Test the OpenID configuration endpoint
        print(f"\n🧪 Testing OpenID configuration endpoint...")
        time.sleep(2)  # Give it a moment to be ready
        test_response = requests.get(f"{KEYCLOAK_URL}/realms/{REALM_NAME}/.well-known/openid_configuration")
        if test_response.status_code == 200:
            config = test_response.json()
            print("✅ OpenID configuration endpoint working!")
            print(f"   - Issuer: {config.get('issuer', 'NOT FOUND')}")
            print(f"   - Authorization endpoint: {config.get('authorization_endpoint', 'NOT FOUND')}")
            print(f"   - Token endpoint: {config.get('token_endpoint', 'NOT FOUND')}")
            print(f"   - DPoP support: {'dpop_signing_alg_values_supported' in config}")
            
            print("\n🎉 OpenADP Keycloak Setup Complete!")
            print("=" * 50)
            print(f"🌐 Keycloak URL: {KEYCLOAK_URL}")
            print(f"🏛️  Realm: {REALM_NAME}")
            print(f"🔧 Client ID: {CLIENT_ID}")
            print(f"🔑 Client Secret: openadp-cli-secret-change-in-production")
            print(f"👤 Test User: testuser / TestPass123!")
            print(f"\n🔗 OpenID Configuration:")
            print(f"   {KEYCLOAK_URL}/realms/{REALM_NAME}/.well-known/openid_configuration")
            print(f"\n🎯 Ready for Phase 4 authentication testing!")
        else:
            print(f"❌ OpenID configuration still not working: {test_response.status_code}")
            print(f"   Response: {test_response.text}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 