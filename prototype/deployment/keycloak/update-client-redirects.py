#!/usr/bin/env python3
"""
Update Keycloak Client Redirect URIs

This script updates the cli-test client in the openadp realm to include
localhost redirect URIs for local testing with the global IdP.
"""

import requests
import json
import sys

# Keycloak configuration - Production instance
KEYCLOAK_URL = "https://auth.openadp.org"  # Production via tunnel
REALM = "openadp"
CLIENT_ID = "cli-test"
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
    
    response = requests.post(token_url, data=data)
    response.raise_for_status()
    
    return response.json()['access_token']

def get_client_info(access_token):
    """Get client information."""
    clients_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients"
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    response = requests.get(clients_url, headers=headers)
    response.raise_for_status()
    
    clients = response.json()
    
    for client in clients:
        if client.get('clientId') == CLIENT_ID:
            return client
    
    raise Exception(f"Client '{CLIENT_ID}' not found")

def update_client_redirects(access_token, client_uuid):
    """Update client redirect URIs."""
    client_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{client_uuid}"
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    # Get current client configuration
    response = requests.get(client_url, headers=headers)
    response.raise_for_status()
    client_config = response.json()
    
    # Update redirect URIs to include localhost variants
    redirect_uris = [
        "http://localhost:8888/callback",
        "http://localhost:8889/callback", 
        "http://127.0.0.1:8888/callback",
        "http://127.0.0.1:8889/callback"
    ]
    
    client_config['redirectUris'] = redirect_uris
    
    # Update the client
    response = requests.put(client_url, headers=headers, json=client_config)
    response.raise_for_status()
    
    print(f"✅ Updated client '{CLIENT_ID}' redirect URIs:")
    for uri in redirect_uris:
        print(f"   - {uri}")

def main():
    """Main function."""
    try:
        print("🔐 Getting admin token...")
        access_token = get_admin_token()
        
        print("🔍 Finding client...")
        client_info = get_client_info(access_token)
        client_uuid = client_info['id']
        
        print(f"📝 Updating client '{CLIENT_ID}' ({client_uuid})...")
        update_client_redirects(access_token, client_uuid)
        
        print("✅ Client redirect URIs updated successfully!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 