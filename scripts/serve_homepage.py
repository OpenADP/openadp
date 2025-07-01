#!/usr/bin/env python3
"""
Simple HTTP server for testing OpenADP homepage locally.
Run with: python3 scripts/serve_homepage.py
"""

import http.server
import socketserver
import webbrowser
import os
import sys
from pathlib import Path

def main():
    PORT = 8080
    
    # Change to homepage directory (located at ../openadp_home_page)
    homepage_dir = Path(__file__).parent.parent.parent / "openadp_home_page"
    
    if not homepage_dir.exists():
        print(f"❌ Homepage directory not found: {homepage_dir}")
        print("💡 Run './scripts/sync_to_homepage.sh' first to create the homepage")
        sys.exit(1)
    
    os.chdir(homepage_dir)
    
    Handler = http.server.SimpleHTTPRequestHandler
    Handler.extensions_map['.js'] = 'application/javascript'
    Handler.extensions_map['.mjs'] = 'application/javascript'
    Handler.extensions_map['.json'] = 'application/json'
    Handler.extensions_map['.wasm'] = 'application/wasm'
    Handler.extensions_map['.md'] = 'text/markdown'
    Handler.extensions_map['.html'] = 'text/html'
    Handler.extensions_map['.css'] = 'text/css'
    
    # Custom handler to add security headers
    class CustomHandler(Handler):
        def end_headers(self):
            # Add CORS and security headers for modern web apps
            self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
            self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
            self.send_header('Service-Worker-Allowed', '/')
            # Enable ES6 modules
            self.send_header('Cross-Origin-Resource-Policy', 'cross-origin')
            super().end_headers()
    
    try:
        with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
            url = f"http://localhost:{PORT}"
            print(f"🏠 OpenADP Homepage server starting...")
            print(f"🌐 Server running at: {url}")
            print(f"📱 Main homepage: {url}/index.html")
            print(f"🚀 Developer guide: {url}/developer-quickstart.html")
            print(f"👻 Ghost Notes app: {url}/ghost-notes/index.html")
            print(f"🧪 Ghost Notes test: {url}/ghost-notes/test.html")
            print("🔒 Press Ctrl+C to stop")
            
            # Try to open browser
            try:
                webbrowser.open(f"{url}/index.html")
                print("🚀 Opened homepage in browser")
            except:
                print("💡 Manually open browser to the URL above")
            
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n🏠 Homepage server stopped. Thanks for using OpenADP!")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 