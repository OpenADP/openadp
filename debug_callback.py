#!/usr/bin/env python3
"""
Debug OAuth Callback Server

This script tests the OAuth callback server functionality to identify
why authentication gets stuck.
"""

import socket
import time
import sys
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'prototype', 'src'))

def test_port_availability():
    """Test if callback ports are available."""
    print("🔍 Testing port availability...")
    
    for port in [8888, 8889]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('localhost', port))
            print(f"✅ Port {port}: Available")
            sock.close()
        except OSError as e:
            print(f"❌ Port {port}: In use or blocked - {e}")
            sock.close()

class DebugCallbackHandler(BaseHTTPRequestHandler):
    """Debug callback handler with verbose logging."""
    
    def do_GET(self):
        print(f"📥 Received GET request: {self.path}")
        print(f"   Client: {self.client_address}")
        print(f"   Headers: {dict(self.headers)}")
        
        # Send a simple response
        response_html = """
        <html><body>
        <h2>🐛 Debug Callback Server</h2>
        <p>Request received successfully!</p>
        <p>Path: <code>{}</code></p>
        <p>You can close this window.</p>
        </body></html>
        """.format(self.path)
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(response_html)))
        self.end_headers()
        self.wfile.write(response_html.encode('utf-8'))
        
        # Signal that we got a request
        self.server.got_request = True
    
    def log_message(self, format, *args):
        """Custom logging to see all requests."""
        print(f"🌐 HTTP: {format % args}")

def test_callback_server():
    """Test the callback server functionality."""
    print("\n🔍 Testing callback server...")
    
    port = 8889
    try:
        # Start debug callback server
        server = HTTPServer(('localhost', port), DebugCallbackHandler)
        server.got_request = False
        server.timeout = 1  # Non-blocking
        
        print(f"🚀 Debug callback server started on http://localhost:{port}")
        print("📱 Test URL: http://localhost:8889/callback?code=test123&state=test")
        print("⏱️  Waiting 10 seconds for manual test...")
        
        # Run server for 10 seconds
        start_time = time.time()
        while time.time() - start_time < 10:
            server.handle_request()
            if server.got_request:
                print("✅ Callback server received request successfully!")
                break
            time.sleep(0.1)
        else:
            print("⏰ No requests received - this might be the issue")
            
        server.server_close()
        
    except Exception as e:
        print(f"❌ Callback server test failed: {e}")

def test_curl_callback():
    """Test callback with curl."""
    print("\n🔍 Testing callback with curl...")
    
    import subprocess
    try:
        result = subprocess.run([
            'curl', '-s', '-i', 
            'http://localhost:8889/callback?code=test123&state=test'
        ], capture_output=True, text=True, timeout=5)
        
        print(f"📊 Curl exit code: {result.returncode}")
        if result.stdout:
            print(f"📄 Response: {result.stdout[:200]}...")
        if result.stderr:
            print(f"❌ Error: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("⏰ Curl request timed out")
    except Exception as e:
        print(f"❌ Curl test failed: {e}")

def main():
    """Run all debug tests."""
    print("🐛 OAuth Callback Debug Tool")
    print("=" * 40)
    
    # Test 1: Port availability
    test_port_availability()
    
    # Test 2: Callback server
    test_callback_server()
    
    # Test 3: Check if localhost is accessible
    print("\n🔍 Testing localhost connectivity...")
    try:
        import requests
        response = requests.get('http://httpbin.org/get', timeout=5)
        print("✅ Internet connectivity OK")
    except Exception as e:
        print(f"❌ Internet connectivity issue: {e}")
    
    print("\n💡 Debug suggestions:")
    print("1. Try manually visiting: http://localhost:8889/callback?code=test&state=test")
    print("2. Check if any firewall is blocking localhost connections")
    print("3. Verify browser can reach localhost (some environments block this)")
    print("4. Try using 127.0.0.1 instead of localhost")

if __name__ == "__main__":
    main() 