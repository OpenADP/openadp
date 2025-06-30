#!/usr/bin/env python3
"""
Test Server Management Script

This script manages test servers for cross-language testing:
- Launches configurable number of test servers
- Queries server info using build/openadp-serverinfo 
- Generates proper servers.json with public keys
- Provides file:// and http:// access to server registry
- Handles server teardown

Usage:
  python manage_test_servers.py --launch 3 --start-port 8080
  python manage_test_servers.py --teardown
  python manage_test_servers.py --generate-json --servers "http://127.0.0.1:8080,http://127.0.0.1:8081"
"""

import os
import sys
import subprocess
import tempfile
import time
import json
import argparse
import signal
import threading
import http.server
import socketserver
from urllib.parse import urlparse

def log(message):
    print(f"[SERVER_MGR] {message}")

class TestServerManager:
    def __init__(self):
        self.servers = []
        self.temp_files = []
        self.registry_server = None
        
    def launch_servers(self, num_servers, start_port=8080, auth_enabled=True):
        """Launch the specified number of test servers"""
        log(f"🚀 Launching {num_servers} test servers starting at port {start_port}")
        
        for i in range(num_servers):
            port = start_port + i
            success = self._launch_single_server(port, auth_enabled)
            if not success:
                log(f"❌ Failed to launch server on port {port}")
                return False
                
        log(f"✅ Successfully launched {len(self.servers)} servers")
        return True
    
    def _launch_single_server(self, port, auth_enabled):
        """Launch a single test server"""
        log(f"Starting server on port {port}...")
        
        # Create temporary database
        temp_db = tempfile.mktemp(suffix=f"_test_server_{port}.db")
        self.temp_files.append(temp_db)
        
        # Check if server binary exists
        server_binary = "build/openadp-server"
        if not os.path.exists(server_binary):
            server_binary = "cmd/openadp-server/openadp-server"
            if not os.path.exists(server_binary):
                log(f"❌ Server binary not found at {server_binary}")
                return False
        
        cmd = [
            server_binary,
            "-port", str(port),
            "-db", temp_db,
            "-auth", "true" if auth_enabled else "false",
        ]
        
        try:
            # Create log files for server output
            log_dir = "logs"
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            stdout_log = open(f"{log_dir}/server_{port}_stdout.log", "w")
            stderr_log = open(f"{log_dir}/server_{port}_stderr.log", "w")
            
            process = subprocess.Popen(
                cmd,
                stdout=stdout_log,
                stderr=stderr_log
            )
            
            # Wait for server to start
            time.sleep(3)
            
            # Test if server is responding
            test_success = self._test_server_response(port)
            
            if test_success:
                self.servers.append({
                    'port': port,
                    'process': process,
                    'db_file': temp_db,
                    'url': f"http://127.0.0.1:{port}",
                    'stdout_log': stdout_log,
                    'stderr_log': stderr_log
                })
                log(f"✅ Server started successfully on port {port}")
                return True
            else:
                log(f"❌ Server on port {port} not responding")
                process.terminate()
                stdout_log.close()
                stderr_log.close()
                return False
                
        except Exception as e:
            log(f"❌ Failed to start server on port {port}: {e}")
            # Clean up any open file handles
            try:
                stdout_log.close()
                stderr_log.close()
            except:
                pass
            return False
    
    def _test_server_response(self, port):
        """Test if a server is responding"""
        try:
            # Try to ping the server
            result = subprocess.run([
                "curl", "-s", "-m", "5", 
                f"http://127.0.0.1:{port}",
                "-d", '{"jsonrpc":"2.0","method":"Echo","params":["ping"],"id":1}',
                "-H", "Content-Type: application/json"
            ], capture_output=True, timeout=10)
            
            return result.returncode == 0
        except:
            return False
    
    def query_server_info(self, server_url):
        """Query server info using build/openadp-serverinfo"""
        log(f"Querying server info for {server_url}")
        
        # Check if serverinfo binary exists
        serverinfo_binary = "build/openadp-serverinfo"
        if not os.path.exists(serverinfo_binary):
            log(f"❌ openadp-serverinfo binary not found at {serverinfo_binary}")
            return None
        
        try:
            cmd = [serverinfo_binary, "-server", server_url, "-format", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse the JSON output
                server_info = json.loads(result.stdout)
                log(f"✅ Retrieved server info for {server_url}")
                return server_info
            else:
                log(f"❌ Failed to query server info for {server_url}: {result.stderr}")
                return None
                
        except Exception as e:
            log(f"❌ Error querying server info for {server_url}: {e}")
            return None
    
    def generate_servers_json(self, server_urls=None):
        """Generate servers.json with proper public keys"""
        if server_urls is None:
            server_urls = [server['url'] for server in self.servers]
        
        log(f"📝 Generating servers.json for {len(server_urls)} servers")
        
        servers_data = []
        
        for url in server_urls:
            server_info = self.query_server_info(url)
            if server_info:
                # Extract the required information
                server_entry = {
                    "url": url,
                    "public_key": server_info.get("noise_nk_public_key", ""),
                    "capabilities": server_info.get("capabilities", [])
                }
                servers_data.append(server_entry)
                log(f"✅ Added server {url} with public key: {server_entry['public_key'][:16]}...")
            else:
                log(f"❌ Failed to get info for server {url}, skipping")
        
        # Create the servers.json structure
        servers_json = {
            "servers": servers_data,
            "generated_at": time.time(),
            "generator": "manage_test_servers.py"
        }
        
        # Write to file
        json_file = "test_servers.json"
        with open(json_file, 'w') as f:
            json.dump(servers_json, f, indent=2)
        
        log(f"✅ Generated {json_file} with {len(servers_data)} servers")
        return json_file
    
    def start_registry_server(self, servers_json_file, port=8082):
        """Start an HTTP server to serve the servers.json file"""
        log(f"🌐 Starting registry server on port {port}")
        
        class RegistryHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, json_file=None, **kwargs):
                self.json_file = json_file
                super().__init__(*args, **kwargs)
            
            def do_GET(self):
                if self.path in ['/servers.json', '/api/servers.json']:
                    try:
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        with open(self.json_file, 'rb') as f:
                            self.wfile.write(f.read())
                    except Exception as e:
                        self.send_error(500, f"Error serving JSON: {e}")
                else:
                    self.send_error(404, "Not found")
        
        # Try different ports if the requested one is taken
        for attempt_port in [port, port+1, port+2, port+3]:
            try:
                handler = lambda *args, **kwargs: RegistryHandler(*args, json_file=servers_json_file, **kwargs)
                httpd = socketserver.TCPServer(("", attempt_port), handler)
                httpd.port = attempt_port
                
                # Start server in background thread
                server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
                server_thread.start()
                
                # Wait a bit and test
                time.sleep(1)
                test_result = subprocess.run([
                    "curl", "-s", "-m", "3", f"http://127.0.0.1:{attempt_port}/servers.json"
                ], capture_output=True)
                
                if test_result.returncode == 0:
                    self.registry_server = httpd
                    log(f"✅ Registry server started on port {attempt_port}")
                    return f"http://127.0.0.1:{attempt_port}"
                else:
                    httpd.shutdown()
                    
            except Exception as e:
                log(f"Failed to start registry server on port {attempt_port}: {e}")
                continue
        
        log("❌ Could not start registry server on any port")
        return None
    
    def get_servers_url(self, format_type="http"):
        """Get the servers URL in the requested format"""
        if format_type == "file":
            json_file = self.generate_servers_json()
            return f"file://{os.path.abspath(json_file)}"
        elif format_type == "http":
            json_file = self.generate_servers_json()
            registry_url = self.start_registry_server(json_file)
            if registry_url:
                return f"{registry_url}/servers.json"
            else:
                # Fallback to file URL
                return f"file://{os.path.abspath(json_file)}"
        else:
            raise ValueError(f"Unknown format type: {format_type}")
    
    def teardown(self):
        """Teardown all servers and cleanup"""
        log("🧹 Tearing down servers...")
        
        # Stop all server processes
        for server in self.servers:
            try:
                process = server['process']
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                
                # Close log files
                if 'stdout_log' in server:
                    server['stdout_log'].close()
                if 'stderr_log' in server:
                    server['stderr_log'].close()
                    
                log(f"✅ Stopped server on port {server['port']}")
            except Exception as e:
                log(f"❌ Error stopping server on port {server['port']}: {e}")
        
        # Stop registry server
        if self.registry_server:
            try:
                self.registry_server.shutdown()
                log("✅ Stopped registry server")
            except Exception as e:
                log(f"❌ Error stopping registry server: {e}")
        
        # Clean up temporary files
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception as e:
                log(f"❌ Error removing {temp_file}: {e}")
        
        # Clean up JSON files
        for json_file in ["test_servers.json", "test_servers_registry.json"]:
            try:
                if os.path.exists(json_file):
                    os.remove(json_file)
            except:
                pass
        
        self.servers = []
        self.registry_server = None
        self.temp_files = []
        
        log("✅ Teardown complete")

def main():
    parser = argparse.ArgumentParser(description="Manage test servers for cross-language testing")
    parser.add_argument("--launch", type=int, help="Launch N test servers")
    parser.add_argument("--start-port", type=int, default=8080, help="Starting port for servers")
    parser.add_argument("--teardown", action="store_true", help="Teardown existing servers")
    parser.add_argument("--generate-json", action="store_true", help="Generate servers.json")
    parser.add_argument("--servers", help="Comma-separated list of server URLs")
    parser.add_argument("--format", choices=["file", "http"], default="http", 
                       help="Output format for servers URL")
    parser.add_argument("--registry-port", type=int, default=8082, 
                       help="Port for registry server")
    
    args = parser.parse_args()
    
    manager = TestServerManager()
    
    try:
        if args.teardown:
            # This is a simple teardown - in practice you'd want to track PIDs
            log("🧹 Attempting to teardown any running test servers...")
            subprocess.run(["pkill", "-f", "openadp-server.*-port.*80[0-9][0-9]"], capture_output=True)
            log("✅ Teardown signal sent")
            return 0
            
        elif args.launch:
            # Launch servers
            success = manager.launch_servers(args.launch, args.start_port)
            if not success:
                return 1
            
            # Generate JSON and get URL
            servers_url = manager.get_servers_url(args.format)
            print(f"SERVERS_URL={servers_url}")
            
            # Keep servers running
            log("🏃 Servers are running. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                manager.teardown()
                
        elif args.generate_json:
            if args.servers:
                server_urls = [url.strip() for url in args.servers.split(',')]
                json_file = manager.generate_servers_json(server_urls)
                
                if args.format == "file":
                    print(f"file://{os.path.abspath(json_file)}")
                elif args.format == "http":
                    registry_url = manager.start_registry_server(json_file, args.registry_port)
                    if registry_url:
                        print(f"{registry_url}/servers.json")
                        # Keep registry server running
                        log("Registry server running. Press Ctrl+C to stop.")
                        try:
                            while True:
                                time.sleep(1)
                        except KeyboardInterrupt:
                            manager.teardown()
                    else:
                        print(f"file://{os.path.abspath(json_file)}")
                        return 1
            else:
                log("❌ --servers required when using --generate-json")
                return 1
        else:
            parser.print_help()
            return 1
            
    except KeyboardInterrupt:
        log("Interrupted by user")
        manager.teardown()
        return 0
    except Exception as e:
        log(f"❌ Error: {e}")
        manager.teardown()
        return 1

if __name__ == "__main__":
    sys.exit(main()) 
