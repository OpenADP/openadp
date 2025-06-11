#!/usr/bin/env python3

import sys
import os
import socket
import ssl
import json

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_direct_connection():
    """Test direct connection to server"""
    print("🔍 Testing Direct Server Connection")
    print("=" * 50)
    
    # Load servers.json
    servers_file = os.path.join(os.path.dirname(__file__), '..', '..', 'api', 'servers.json')
    try:
        with open(servers_file, 'r') as f:
            config = json.load(f)
        servers = config['servers']
        print(f"📋 Loaded {len(servers)} servers from configuration")
    except Exception as e:
        print(f"❌ Failed to load servers.json: {e}")
        return
    
    for i, server in enumerate(servers, 1):
        url = server['url']
        public_key = server['public_key']
        
        print(f"\n🖥️  SERVER {i}: {url}")
        print(f"   Public Key: {public_key}")
        print("-" * 40)
        
        try:
            # Test with NoiseKKJSONRPCClient
            from client.noise_jsonrpc_client import NoiseKKJSONRPCClient
            
            print("🔐 Testing Noise-KK connection...")
            client = NoiseKKJSONRPCClient(url, public_key, timeout=10.0)
            
            # Try to connect and do handshake
            client._connect()
            print("✅ Connection and handshake successful!")
            
            # Try echo test
            result, error = client.echo("test")
            if error:
                print(f"❌ Echo failed: {error}")
            else:
                print(f"✅ Echo successful: {result}")
                
            client.close()
            
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test_direct_connection() 