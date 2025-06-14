#!/usr/bin/env python3
"""
Script to create and configure Keycloak client for OpenADP.
"""

import requests
import json

def get_admin_token():
    """Get admin access token from Keycloak."""
    token_url = "http://localhost:8081/realms/master/protocol/openid-connect/token"
    
    data = {
        'grant_type': 'password',
        'client_id': 'admin-cli',
        'username': 'admin',
        'password': 'admin'
    }
    
    response = requests.post(token_url, data=data)
    response.raise_for_status()
    return response.json()['access_token']

def create_client():
    """Create the cli-test client in Keycloak."""
    
    print("🔧 Creating Keycloak client configuration...")
    
    try:
        # Get admin token
        admin_token = get_admin_token()
        print("✅ Got admin token")
        
        headers = {
            'Authorization': f'Bearer {admin_token}',
            'Content-Type': 'application/json'
        }
        
        # Client configuration
        client_config = {
            "clientId": "cli-test",
            "name": "OpenADP CLI Test Client",
            "description": "Client for OpenADP CLI tools with DPoP support",
            "protocol": "openid-connect",
            "publicClient": True,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": False,
            "authorizationServicesEnabled": False,
            "redirectUris": [
                "http://localhost:8888/callback",
                "http://localhost:8889/callback"
            ],
            "webOrigins": ["*"],
            "attributes": {
                "dpop.bound.access.tokens": "true",
                "pkce.code.challenge.method": "S256"
            }
        }
        
        # Create client
        clients_url = "http://localhost:8081/admin/realms/openadp/clients"
        response = requests.post(clients_url, headers=headers, json=client_config)
        
        if response.status_code == 201:
            print("✅ Client created successfully!")
            return True
        elif response.status_code == 409:
            print("⚠️  Client already exists, updating configuration...")
            
            # Get existing client
            response = requests.get(clients_url, headers=headers, params={'clientId': 'cli-test'})
            clients = response.json()
            
            if clients:
                client_id = clients[0]['id']
                update_url = f"{clients_url}/{client_id}"
                
                # Update client
                response = requests.put(update_url, headers=headers, json=client_config)
                if response.status_code == 204:
                    print("✅ Client updated successfully!")
                    return True
                else:
                    print(f"❌ Failed to update client: {response.status_code}")
                    print(response.text)
                    return False
            else:
                print("❌ Client not found for update")
                return False
        else:
            print(f"❌ Failed to create client: {response.status_code}")
            print(response.text)
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    if create_client():
        print("\n🎉 Client configuration complete!")
        print("Now you can test the authentication flow.")
    else:
        print("\n💡 Manual configuration required:")
        print("1. Go to: http://localhost:8081/admin")
        print("2. Login: admin / admin")
        print("3. Navigate: Realms → openadp → Clients")
        print("4. Create client 'cli-test' with:")
        print("   - Standard Flow Enabled: ON")
        print("   - Valid Redirect URIs: http://localhost:8889/callback")
        print("   - Access Type: public") 