#!/usr/bin/env python3
"""
Debug script to help identify server public key mismatches.

This script attempts to connect to servers and diagnose why 
Noise-KK handshakes are failing.
"""

import json
import ssl
import socket
import sys
import os

# Add the src directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))


def test_server_connectivity(server_url):
    """Test basic connectivity to server"""
    print(f"\n🔍 Testing connectivity to {server_url}")
    
    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(server_url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        # Test basic TCP connection
        print(f"   Testing TCP connection to {hostname}:{port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        result = sock.connect_ex((hostname, port))
        sock.close()
        
        if result == 0:
            print(f"   ✅ TCP connection successful")
        else:
            print(f"   ❌ TCP connection failed: {result}")
            return False
        
        # Test TLS connection
        print(f"   Testing TLS connection...")
        context = ssl.create_default_context()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10.0)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.connect((hostname, port))
                print(f"   ✅ TLS connection successful")
                print(f"   📜 TLS version: {ssock.version()}")
                
        return True
        
    except Exception as e:
        print(f"   ❌ Connection failed: {e}")
        return False


def test_noise_handshake(server_url, server_public_key):
    """Test Noise-KK handshake with given public key"""
    print(f"\n🔐 Testing Noise-KK handshake...")
    print(f"   Server: {server_url}")
    print(f"   Using public key: {server_public_key[:30]}...")
    
    try:
        from client.noise_jsonrpc_client import NoiseKKJSONRPCClient
        
        client = NoiseKKJSONRPCClient(server_url, server_public_key, timeout=10.0)
        
        # Try a simple echo test
        result = client.echo("handshake_test")
        if result[0] == "handshake_test" and result[1] is None:
            print(f"   ✅ Noise-KK handshake successful!")
            print(f"   ✅ Echo test passed")
            return True
        else:
            print(f"   ❌ Echo test failed: {result}")
            return False
            
    except Exception as e:
        print(f"   ❌ Noise-KK handshake failed: {e}")
        return False


def diagnose_servers():
    """Diagnose all servers in servers.json"""
    print("🛠️  OpenADP Server Diagnosis")
    print("=" * 50)
    
    # Load servers.json
    try:
        with open("../api/servers.json", 'r') as f:
            data = json.load(f)
            servers = data.get('servers', [])
    except Exception as e:
        print(f"❌ Could not load servers.json: {e}")
        return
    
    print(f"Found {len(servers)} servers in configuration")
    
    results = []
    
    for i, server in enumerate(servers):
        url = server.get('url', 'unknown')
        public_key = server.get('public_key', 'unknown')
        
        print(f"\n{'='*60}")
        print(f"🌐 Server {i+1}: {url}")
        print(f"{'='*60}")
        
        # Test basic connectivity
        tcp_ok = test_server_connectivity(url)
        
        # Test Noise-KK handshake
        noise_ok = False
        if tcp_ok:
            noise_ok = test_noise_handshake(url, public_key)
        
        results.append({
            'url': url,
            'tcp_ok': tcp_ok,
            'noise_ok': noise_ok,
            'public_key': public_key
        })
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 Summary")
    print(f"{'='*60}")
    
    for i, result in enumerate(results):
        status = "✅" if result['noise_ok'] else "❌"
        print(f"{status} Server {i+1}: {result['url']}")
        if result['tcp_ok'] and not result['noise_ok']:
            print(f"   🔍 TCP works but Noise-KK fails - likely key mismatch")
        elif not result['tcp_ok']:
            print(f"   🔍 TCP connection failed - server may be down")
    
    # Recommendations
    print(f"\n📋 Recommendations:")
    
    working_servers = [r for r in results if r['noise_ok']]
    failing_servers = [r for r in results if r['tcp_ok'] and not r['noise_ok']]
    
    if len(working_servers) > 0:
        print(f"✅ {len(working_servers)} servers working correctly")
    
    if len(failing_servers) > 0:
        print(f"🔧 {len(failing_servers)} servers need public key updates:")
        for server in failing_servers:
            print(f"   - {server['url']}")
            print(f"     Current key: {server['public_key'][:30]}...")
            print(f"     Action: Get real public key from server logs/admin")


def main():
    """Main diagnosis function"""
    print("This script diagnoses Noise-KK connection issues")
    print("It will test each server in servers.json for:")
    print("  1. Basic TCP connectivity")  
    print("  2. TLS connection")
    print("  3. Noise-KK handshake")
    print()
    
    diagnose_servers()
    
    print(f"\n{'='*60}")
    print("🔧 Next Steps:")
    print("1. For servers with TCP but failing Noise-KK:")
    print("   - Check server logs for actual public key") 
    print("   - Update servers.json with correct public key")
    print("2. For servers with TCP failures:")
    print("   - Verify server is running")
    print("   - Check firewall/network settings")
    print("3. Test again with: python3 encrypt.py test_file")


if __name__ == "__main__":
    main() 