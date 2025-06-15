#!/usr/bin/env python3
"""
Fix Keycloak Proxy Configuration

This script configures Keycloak to properly handle being behind an HTTPS proxy
(Cloudflare) so it advertises HTTPS URLs in the discovery document.
"""

import requests
import json
import sys
import os

# Keycloak configuration - HTTPS access through Cloudflare
KEYCLOAK_URL = "https://auth.openadp.org"
REALM = "openadp"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "mZMENyzLWI0g"  # From setup scripts

def get_admin_token():
    """Get admin access token."""
    token_url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    
    data = {
        'grant_type': 'password',
        'client_id': 'admin-cli',
        'username': ADMIN_USERNAME,
        'password': ADMIN_PASSWORD
    }
    
    try:
        response = requests.post(token_url, data=data, timeout=30)
        response.raise_for_status()
        return response.json()['access_token']
    except requests.RequestException as e:
        raise Exception(f"Failed to get admin token: {e}")

def get_realm_config(access_token):
    """Get current realm configuration."""
    realm_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}"
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.get(realm_url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise Exception(f"Failed to get realm config: {e}")

def update_realm_config(access_token, realm_config):
    """Update realm configuration."""
    realm_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}"
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.put(realm_url, headers=headers, json=realm_config, timeout=30)
        response.raise_for_status()
        return True
    except requests.RequestException as e:
        raise Exception(f"Failed to update realm config: {e}")

def test_discovery_endpoint():
    """Test the OpenID configuration discovery endpoint."""
    discovery_url = f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration"
    
    try:
        response = requests.get(discovery_url, timeout=10)
        response.raise_for_status()
        config = response.json()
        
        print(f"📡 Discovery endpoint results:")
        print(f"   - Issuer: {config.get('issuer', 'NOT FOUND')}")
        print(f"   - Authorization Endpoint: {config.get('authorization_endpoint', 'NOT FOUND')}")
        print(f"   - Token Endpoint: {config.get('token_endpoint', 'NOT FOUND')}")
        print(f"   - JWKS URI: {config.get('jwks_uri', 'NOT FOUND')}")
        
        # Check protocol consistency
        issuer = config.get('issuer', '')
        token_endpoint = config.get('token_endpoint', '')
        
        if issuer.startswith('https://') and token_endpoint.startswith('https://'):
            print("✅ All endpoints use HTTPS - proxy configuration is working!")
            return True
        else:
            print("⚠️  Endpoints still use HTTP - proxy configuration needed")
            return False
            
    except requests.RequestException as e:
        print(f"❌ Failed to test discovery endpoint: {e}")
        return False

def main():
    """Main function."""
    print("🔧 Configuring Keycloak for HTTPS Proxy (Cloudflare)")
    print("=" * 60)
    print(f"🌐 External URL: {KEYCLOAK_URL}")
    print(f"🏰 Realm: {REALM}")
    print(f"🔒 Goal: Advertise HTTPS URLs in discovery document")
    
    try:
        # Test current discovery endpoint
        print(f"\n📡 Testing current discovery endpoint...")
        if test_discovery_endpoint():
            print("✅ Proxy configuration already working correctly!")
            return
        
        # Get admin token
        print(f"\n🔐 Getting admin token...")
        access_token = get_admin_token()
        print("✅ Connected to Keycloak admin API")
        
        # Get current realm configuration
        print(f"\n📋 Getting current realm configuration...")
        realm_config = get_realm_config(access_token)
        
        # Show current configuration
        current_attributes = realm_config.get('attributes', {})
        print(f"   Current frontendUrl: {current_attributes.get('frontendUrl', 'NOT SET')}")
        print(f"   Current sslRequired: {realm_config.get('sslRequired', 'NOT SET')}")
        
        # Configure for HTTPS proxy
        print(f"\n🔧 Configuring realm for HTTPS proxy...")
        
        # Ensure attributes dict exists
        if 'attributes' not in realm_config:
            realm_config['attributes'] = {}
        
        # Set proxy-aware configuration
        realm_config['attributes'].update({
            'frontendUrl': KEYCLOAK_URL,
            'forceBackendUrlToFrontendUrl': 'true'
        })
        
        # Ensure SSL is required for external requests
        realm_config['sslRequired'] = 'external'
        
        # Update the realm
        print(f"   Setting frontendUrl: {KEYCLOAK_URL}")
        print(f"   Setting forceBackendUrlToFrontendUrl: true")
        print(f"   Setting sslRequired: external")
        
        update_realm_config(access_token, realm_config)
        print(f"✅ Updated realm configuration for proxy")
        
        # Wait for changes to propagate
        print(f"\n⏱️  Waiting for configuration to propagate...")
        import time
        time.sleep(5)
        
        # Test the discovery endpoint again
        print(f"\n🧪 Testing updated discovery endpoint...")
        if test_discovery_endpoint():
            print("\n🎉 SUCCESS! Keycloak proxy configuration working!")
            print("✅ Discovery endpoint now returns HTTPS URLs")
            print("✅ Clients can now authenticate through Cloudflare")
            print("\n📋 Next steps:")
            print("   1. Test the encrypt.py tool")
            print("   2. Authentication should now work through https://auth.openadp.org")
        else:
            print("\n⚠️  Configuration may need more time to propagate")
            print("   Wait a few minutes and test authentication again")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\n🔧 Manual Fix Instructions:")
        print("   1. Go to https://auth.openadp.org/admin")
        print("   2. Login as admin")
        print("   3. Select 'openadp' realm")
        print("   4. Go to Realm Settings")
        print("   5. In attributes, set:")
        print("      - frontendUrl: https://auth.openadp.org")
        print("      - forceBackendUrlToFrontendUrl: true")
        print("   6. Set sslRequired: external")
        print("   7. Save settings")
        sys.exit(1)

if __name__ == "__main__":
    main() 