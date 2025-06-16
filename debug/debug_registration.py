#!/usr/bin/env python3
"""Debug script to investigate registration failure."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'prototype', 'src'))

from tests.conftest import openadp_servers
from tests.fake_keycloak import FakeKeycloakServer
from tests.auth_helper import create_test_auth_data
from client.client import Client

def main():
    # Start fake Keycloak
    fake_keycloak = FakeKeycloakServer()
    fake_keycloak.start()

    try:
        # Create auth data
        auth_data = create_test_auth_data(fake_keycloak)
        print('✅ Auth data created successfully')
        
        # Initialize client
        servers = ['http://localhost:9100', 'http://localhost:9101', 'http://localhost:9102']
        client = Client(servers_url=None, fallback_servers=servers)
        print(f'✅ Client initialized with {client.get_live_server_count()} servers')
        
        # Try registration with detailed error reporting
        success, error = client.register_secret(
            'test@example.com', 'test_device', 'test_backup', 1,
            42, b'test_secret_data', 10, 0,
            auth_data=auth_data
        )
        
        print(f'📊 Registration result: success={success}, error={error}')
        
        # Try with individual server clients to see specific errors
        for i, server_client in enumerate(client.live_servers):
            print(f'\n🔍 Trying server {i+1}: {server_client.server_url}')
            try:
                result, err = server_client.register_secret(
                    'test@example.com', 'test_device', 'test_backup', 1,
                    '42', 'test_secret_data', 10, 0,
                    encrypted=True, auth_data=auth_data
                )
                print(f'  📊 Result: {result}, Error: {err}')
            except Exception as e:
                print(f'  ❌ Exception: {e}')
                import traceback
                traceback.print_exc()
                
    finally:
        fake_keycloak.stop()

if __name__ == "__main__":
    main() 