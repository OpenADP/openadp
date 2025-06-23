#!/usr/bin/env python3
"""
Simple HTTP server for testing Ghost Notes locally.
Run with: python3 serve.py
"""

import http.server
import socketserver
import webbrowser
import os
import sys
from pathlib import Path

def main():
    PORT = 8080
    
    # Change to script directory
    os.chdir(Path(__file__).parent)
    
    Handler = http.server.SimpleHTTPRequestHandler
    Handler.extensions_map['.js'] = 'application/javascript'
    Handler.extensions_map['.mjs'] = 'application/javascript'
    Handler.extensions_map['.json'] = 'application/json'
    Handler.extensions_map['.wasm'] = 'application/wasm'
    
    # Custom handler to add security headers
    class CustomHandler(Handler):
        def end_headers(self):
            # Add PWA and security headers
            self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
            self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
            self.send_header('Service-Worker-Allowed', '/')
            super().end_headers()
    
    try:
        with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
            url = f"http://localhost:{PORT}"
            print(f"👻 Ghost Notes server starting...")
            print(f"🌐 Server running at: {url}")
            print(f"🧪 Test page: {url}/test.html")
            print(f"📱 Main app: {url}/index.html")
            print("🔒 Press Ctrl+C to stop")
            
            # Try to open browser
            try:
                webbrowser.open(f"{url}/test.html")
                print("🚀 Opened test page in browser")
            except:
                print("💡 Manually open browser to the URL above")
            
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n👻 Server stopped. Your notes have vanished into the ether...")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 