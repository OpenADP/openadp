#!/usr/bin/env python3
"""Detailed debug script to investigate registration responses."""

import sys
import os
import json
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
        
        if client.get_live_server_count() == 0:
            print("❌ No live servers - cannot test registration")
            return
        
        # Try with the first server client directly to see detailed response
        server_client = client.live_servers[0]
        print(f'\n🔍 Testing with server: {server_client.server_url}')
        
        # Enable more detailed logging
        import logging
        logging.basicConfig(level=logging.DEBUG)
        
        try:
            # Try registration with detailed error capture
            result, error = server_client.register_secret(
                'test@example.com', 'test_device', 'test_backup', 1,
                '42', 'test_secret_data_bytes', 10, 0,
                encrypted=True, auth_data=auth_data
            )
            
            print(f'📊 Server response:')
            print(f'  Result: {result}')
            print(f'  Error: {error}')
            print(f'  Type of result: {type(result)}')
            print(f'  Type of error: {type(error)}')
            
            # Check if it's a boolean result
            if isinstance(result, bool):
                print(f'  Boolean result: {result}')
            
        except Exception as e:
            print(f'❌ Exception during registration: {e}')
            import traceback
            traceback.print_exc()
            
    finally:
        fake_keycloak.stop()

if __name__ == "__main__":
    main() 