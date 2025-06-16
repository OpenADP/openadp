#!/usr/bin/env python3
"""Test callback server with concurrent request."""

import subprocess
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'✅ Callback received: {self.path}')
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Success')
        self.server.received = True
    
    def log_message(self, format, *args):
        pass

def run_server():
    """Run callback server."""
    server = HTTPServer(('localhost', 8889), CallbackHandler)
    server.received = False
    server.timeout = 1
    print('🚀 Callback server started on http://localhost:8889')
    
    for i in range(50):  # Run for 5 seconds
        server.handle_request()
        if getattr(server, 'received', False):
            print('✅ Request received successfully!')
            break
        if i % 10 == 0:
            print(f'   Waiting... ({i//10}s)')
    
    server.server_close()
    print('🔒 Callback server stopped')

def test_curl():
    """Test with curl after a delay."""
    time.sleep(1)  # Wait for server to start
    print('📡 Sending curl request...')
    
    result = subprocess.run([
        'curl', '-s', '-w', 'HTTP_%{http_code}', 
        'http://localhost:8889/callback?code=test123&state=test'
    ], capture_output=True, text=True)
    
    print(f'📊 Curl result: exit={result.returncode}')
    print(f'📄 Response: {result.stdout}')
    if result.stderr:
        print(f'❌ Error: {result.stderr}')

def main():
    """Run concurrent test."""
    print('🔄 Testing concurrent callback server and client...')
    
    # Run server and test concurrently
    server_thread = threading.Thread(target=run_server)
    curl_thread = threading.Thread(target=test_curl)
    
    server_thread.start()
    curl_thread.start()
    
    server_thread.join()
    curl_thread.join()
    
    print('✅ Concurrent test complete')

if __name__ == '__main__':
    main() 