#!/usr/bin/env python3
"""
Setup script that:
1. Starts a local OpenADP server in debug mode
2. Queries its public key using openadp-serverinfo
3. Generates a servers.json file with the correct format
4. Starts a Python HTTP server to host the registry
"""

import subprocess
import json
import time
import sys
import os
import signal
import threading
from datetime import datetime

def start_openadp_server(port=8090):
    """Start OpenADP server in debug mode"""
    print(f"🚀 Starting OpenADP server on port {port}...")
    
    # Start server in background
    proc = subprocess.Popen([
        './build/openadp-server',
        '-port', str(port),
        '-debug'
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    
    # Give server time to start
    time.sleep(2)
    
    return proc

def get_server_public_key(port=8090):
    """Query server info to get public key"""
    print(f"🔍 Querying server info for port {port}...")
    
    try:
        result = subprocess.run([
            './build/openadp-serverinfo',
            '-server', f'http://127.0.0.1:{port}',
            '-format', 'json'
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            print(f"❌ Failed to query server info: {result.stderr}")
            return None
            
        # Parse the JSON output
        info = json.loads(result.stdout)
        public_key = info.get('noise_nk_public_key')
        
        if public_key:
            print(f"✅ Got public key: {public_key}")
            return public_key
        else:
            print("❌ No public key found in server info")
            print(f"Available fields: {list(info.keys())}")
            return None
            
    except subprocess.TimeoutExpired:
        print("❌ Timeout querying server info")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse server info JSON: {e}")
        return None
    except Exception as e:
        print(f"❌ Error querying server info: {e}")
        return None

def create_servers_json(servers_data, filename="test_servers.json"):
    """Create servers.json file with proper format"""
    print(f"📝 Creating {filename}...")
    
    servers_config = {
        "version": "1.0",
        "updated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "servers": servers_data
    }
    
    with open(filename, 'w') as f:
        json.dump(servers_config, f, indent=2)
    
    print(f"✅ Created {filename}")
    return filename

def start_http_server(port=9999, directory="."):
    """Start Python HTTP server to host the registry"""
    print(f"🌐 Starting HTTP server on port {port} serving directory {directory}...")
    
    proc = subprocess.Popen([
        sys.executable, '-m', 'http.server', str(port),
        '--directory', directory
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    
    time.sleep(1)
    return proc

def monitor_server_output(proc, name):
    """Monitor and print server output in a separate thread"""
    def read_output():
        for line in iter(proc.stdout.readline, ''):
            if line:
                print(f"[{name}] {line.rstrip()}")
    
    thread = threading.Thread(target=read_output, daemon=True)
    thread.start()
    return thread

def main():
    openadp_proc = None
    http_proc = None
    
    try:
        # Configuration
        openadp_port = 8090
        http_port = 9999
        servers_file = "test_servers.json"
        
        # Start OpenADP server
        openadp_proc = start_openadp_server(openadp_port)
        
        # Monitor server output
        monitor_thread = monitor_server_output(openadp_proc, "OpenADP")
        
        # Wait a bit more for server to fully initialize
        time.sleep(3)
        
        # Get server public key
        public_key = get_server_public_key(openadp_port)
        if not public_key:
            print("❌ Failed to get server public key")
            return 1
        
        # Create servers configuration
        servers_data = [
            {
                "url": f"http://127.0.0.1:{openadp_port}",
                "public_key": public_key,
                "country": "US"
            }
        ]
        
        # Create servers.json file
        create_servers_json(servers_data, servers_file)
        
        # Start HTTP server to host the registry
        http_proc = start_http_server(http_port)
        
        # Print setup summary
        print("\n" + "="*60)
        print("🎉 SETUP COMPLETE!")
        print("="*60)
        print(f"OpenADP Server: http://127.0.0.1:{openadp_port}")
        print(f"Public Key: {public_key}")
        print(f"Registry HTTP Server: http://127.0.0.1:{http_port}")
        print(f"Registry URL: http://127.0.0.1:{http_port}/{servers_file}")
        print("="*60)
        print("\nNow you can test with:")
        print(f"export OPENADP_SERVERS_URL=http://127.0.0.1:{http_port}/{servers_file}")
        print("python3 sdk/python/tools/ocrypt-register.py --user-id debug_test_user --app-id debug_test_app --long-term-secret 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --password test123")
        print("\nPress Ctrl+C to stop all servers...")
        
        # Keep running until interrupted
        try:
            while True:
                time.sleep(1)
                # Check if processes are still running
                if openadp_proc.poll() is not None:
                    print("❌ OpenADP server stopped unexpectedly")
                    break
                if http_proc.poll() is not None:
                    print("❌ HTTP server stopped unexpectedly")
                    break
        except KeyboardInterrupt:
            print("\n🛑 Shutting down servers...")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
        
    finally:
        # Clean up processes
        if openadp_proc:
            try:
                openadp_proc.terminate()
                openadp_proc.wait(timeout=5)
            except:
                openadp_proc.kill()
                
        if http_proc:
            try:
                http_proc.terminate()
                http_proc.wait(timeout=5)
            except:
                http_proc.kill()
        
        print("✅ Cleanup complete")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 