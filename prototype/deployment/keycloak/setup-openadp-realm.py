#!/usr/bin/env python3
"""
OpenADP Keycloak Realm Setup Script
Automatically creates the OpenADP realm and configures the cli-test client with DPoP support.
"""

import requests
import json
import sys
import time
import os
from urllib.parse import urljoin

class KeycloakAdmin:
    def __init__(self, base_url, admin_user, admin_password):
        self.base_url = base_url.rstrip('/')
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.access_token = None
        
    def get_admin_token(self):
        """Get admin access token"""
        token_url = f"{self.base_url}/realms/master/protocol/openid-connect/token"
        
        data = {
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': self.admin_user,
            'password': self.admin_password
        }
        
        response = requests.post(token_url, data=data)
        if response.status_code != 200:
            raise Exception(f"Failed to get admin token: {response.status_code} - {response.text}")
        
        self.access_token = response.json()['access_token']
        return self.access_token
    
    def make_request(self, method, endpoint, data=None):
        """Make authenticated request to Keycloak Admin API"""
        if not self.access_token:
            self.get_admin_token()
        
        url = f"{self.base_url}/admin{endpoint}"
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, json=data)
        elif method.upper() == 'PUT':
            response = requests.put(url, headers=headers, json=data)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        return response
    
    def realm_exists(self, realm_name):
        """Check if realm exists"""
        response = self.make_request('GET', f'/realms/{realm_name}')
        return response.status_code == 200
    
    def create_realm(self, realm_name):
        """Create OpenADP realm"""
        if self.realm_exists(realm_name):
            print(f"✅ Realm '{realm_name}' already exists")
            return True
        
        realm_config = {
            "realm": realm_name,
            "displayName": "OpenADP Authentication",
            "enabled": True,
            "registrationAllowed": False,
            "loginWithEmailAllowed": True,
            "duplicateEmailsAllowed": False,
            "resetPasswordAllowed": True,
            "editUsernameAllowed": False,
            "bruteForceProtected": True,
            "permanentLockout": False,
            "maxFailureWaitSeconds": 900,
            "minimumQuickLoginWaitSeconds": 60,
            "waitIncrementSeconds": 60,
            "quickLoginCheckMilliSeconds": 1000,
            "maxDeltaTimeSeconds": 43200,
            "failureFactor": 30,
            "defaultRoles": ["default-roles-openadp"],
            "requiredCredentials": ["password"],
            "passwordPolicy": "length(8) and digits(1) and lowerCase(1) and upperCase(1)",
            "otpPolicyType": "totp",
            "otpPolicyAlgorithm": "HmacSHA1",
            "otpPolicyInitialCounter": 0,
            "otpPolicyDigits": 6,
            "otpPolicyLookAheadWindow": 1,
            "otpPolicyPeriod": 30,
            "sslRequired": "external",
            "attributes": {
                "frontendUrl": "https://auth.openadp.org",
                "forceBackendUrlToFrontendUrl": "true",
                "hostname": "auth.openadp.org",
                "hostnameStrict": "true",
                "hostnameStrictHttps": "true"
            }
        }
        
        response = self.make_request('POST', '/realms', realm_config)
        if response.status_code == 201:
            print(f"✅ Created realm '{realm_name}'")
            return True
        else:
            print(f"❌ Failed to create realm: {response.status_code} - {response.text}")
            return False
    
    def client_exists(self, realm_name, client_id):
        """Check if client exists"""
        response = self.make_request('GET', f'/realms/{realm_name}/clients')
        if response.status_code == 200:
            clients = response.json()
            return any(client['clientId'] == client_id for client in clients)
        return False
    
    def create_client(self, realm_name, client_id):
        """Create DPoP-enabled client"""
        if self.client_exists(realm_name, client_id):
            print(f"✅ Client '{client_id}' already exists in realm '{realm_name}'")
            return True
        
        client_config = {
            "clientId": client_id,
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
                "dpop.legacy.mode": "true",
                "dpop.cnf.claim.enabled": "true",
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
            "protocolMappers": [
                {
                    "name": "audience resolve",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-resolve-mapper",
                    "consentRequired": False,
                    "config": {}
                }
            ],
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
        
        response = self.make_request('POST', f'/realms/{realm_name}/clients', client_config)
        if response.status_code == 201:
            print(f"✅ Created client '{client_id}' with DPoP support")
            return True
        else:
            print(f"❌ Failed to create client: {response.status_code} - {response.text}")
            return False
    
    def create_test_user(self, realm_name, username, password, email):
        """Create a test user"""
        # Check if user exists
        response = self.make_request('GET', f'/realms/{realm_name}/users?username={username}')
        if response.status_code == 200 and response.json():
            print(f"✅ User '{username}' already exists")
            return True
        
        user_config = {
            "username": username,
            "email": email,
            "emailVerified": True,
            "enabled": True,
            "firstName": "Test",
            "lastName": "User",
            "credentials": [
                {
                    "type": "password",
                    "value": password,
                    "temporary": False
                }
            ]
        }
        
        response = self.make_request('POST', f'/realms/{realm_name}/users', user_config)
        if response.status_code == 201:
            print(f"✅ Created test user '{username}'")
            return True
        else:
            print(f"❌ Failed to create user: {response.status_code} - {response.text}")
            return False

def main():
    # Configuration
    KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', "https://auth.openadp.org")
    ADMIN_USER = "admin"
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'mZMENyzLWI0g')
    REALM_NAME = "openadp"
    CLIENT_ID = "cli-test"
    
    print("🚀 Setting up OpenADP Keycloak Configuration")
    print("=" * 50)
    
    try:
        # Initialize admin client
        admin = KeycloakAdmin(KEYCLOAK_URL, ADMIN_USER, ADMIN_PASSWORD)
        
        # Wait for Keycloak to be ready
        print("⏳ Waiting for Keycloak to be ready...")
        for i in range(30):
            try:
                admin.get_admin_token()
                break
            except Exception as e:
                if i == 29:
                    raise Exception("Keycloak not ready after 30 attempts")
                time.sleep(2)
        
        print("✅ Connected to Keycloak admin API")
        
        # Create realm
        print(f"\n📁 Creating realm '{REALM_NAME}'...")
        if not admin.create_realm(REALM_NAME):
            sys.exit(1)
        
        # Create client
        print(f"\n🔧 Creating client '{CLIENT_ID}'...")
        if not admin.create_client(REALM_NAME, CLIENT_ID):
            sys.exit(1)
        
        # Create test user
        print(f"\n👤 Creating test user...")
        if not admin.create_test_user(REALM_NAME, "testuser", "TestPass123!", "test@openadp.org"):
            sys.exit(1)
        
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
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 