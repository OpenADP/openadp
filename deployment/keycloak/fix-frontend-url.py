#!/usr/bin/env python3
"""
Fix Keycloak Frontend URL Configuration

This script fixes the OpenADP realm configuration to ensure it advertises
HTTPS URLs in the discovery document instead of HTTP URLs.
"""

import requests
import json
import sys
import os

# Keycloak configuration - Production instance via tunnel
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
        response = requests.post(token_url, data=data, timeout=10)
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
        response = requests.get(realm_url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise Exception(f"Failed to get realm config: {e}")

def update_realm_config(access_token, realm_config):
    """Update realm configuration with correct frontend URL."""
    realm_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}"
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.put(realm_url, headers=headers, json=realm_config, timeout=10)
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
            print("✅ All endpoints use HTTPS - configuration is correct!")
            return True
        elif issuer.startswith('http://') and token_endpoint.startswith('http://'):
            print("⚠️  All endpoints use HTTP - need to fix frontend URL")
            return False
        else:
            print("❌ Mixed protocols - configuration needs fixing")
            return False
            
    except requests.RequestException as e:
        print(f"❌ Failed to test discovery endpoint: {e}")
        return False

def main():
    """Main function."""
    print("🔧 Fixing Keycloak Frontend URL Configuration")
    print("=" * 60)
    print(f"🌐 Keycloak URL: {KEYCLOAK_URL}")
    print(f"🏰 Realm: {REALM}")
    
    try:
        # Test current discovery endpoint
        print(f"\n📡 Testing current discovery endpoint...")
        if test_discovery_endpoint():
            print("✅ Configuration already correct - no changes needed!")
            return
        
        # Get admin token
        print(f"\n🔐 Getting admin token...")
        access_token = get_admin_token()
        print("✅ Connected to Keycloak admin API")
        
        # Get current realm configuration
        print(f"\n📋 Getting current realm configuration...")
        realm_config = get_realm_config(access_token)
        
        current_frontend_url = realm_config.get('attributes', {}).get('frontendUrl', 'NOT SET')
        print(f"   Current frontend URL: {current_frontend_url}")
        
        # Update frontend URL configuration
        print(f"\n🔧 Updating frontend URL configuration...")
        
        # Ensure attributes dict exists
        if 'attributes' not in realm_config:
            realm_config['attributes'] = {}
        
        # Set the correct frontend URL
        realm_config['attributes']['frontendUrl'] = KEYCLOAK_URL
        
        # Also ensure SSL is required for external connections
        realm_config['sslRequired'] = 'external'
        
        # Update the realm
        update_realm_config(access_token, realm_config)
        print(f"✅ Updated realm configuration")
        print(f"   New frontend URL: {KEYCLOAK_URL}")
        print(f"   SSL Required: external")
        
        # Wait a moment for changes to propagate
        print(f"\n⏱️  Waiting for configuration to propagate...")
        import time
        time.sleep(3)
        
        # Test the discovery endpoint again
        print(f"\n🧪 Testing updated discovery endpoint...")
        if test_discovery_endpoint():
            print("\n🎉 SUCCESS! Keycloak is now properly configured!")
            print("✅ Discovery endpoint now returns HTTPS URLs")
            print("✅ Authentication should work correctly")
        else:
            print("\n⚠️  Configuration update may need more time to propagate")
            print("   Try testing authentication in a few minutes")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 