#!/usr/bin/env python3
"""
Test Server Setup Tool

This tool sets up a proper test environment for cross-language debugging:
1. Starts multiple OpenADP servers on different ports
2. Queries each server for its public key using openadp-serverinfo
3. Builds a correct servers.json file with real Ed25519 keys
4. Hosts the servers.json via HTTP for test access
5. Provides cleanup functionality

This enables proper Noise-NK handshakes instead of failing with dummy keys.
"""

import os
import sys
import json
import subprocess
import tempfile
import time
import threading
import http.server
import socketserver
from pathlib import Path

class TestServerManager:
    def __init__(self):
        self.server_processes = []
        self.server_configs = []
        self.registry_server = None
        self.temp_files = []
        
    def start_openadp_server(self, port, debug_mode=True):
        """Start an OpenADP server on the specified port"""
        print(f"Starting OpenADP server on port {port}...")
        
        # Create temporary database for this server
        temp_db = tempfile.mktemp(suffix=f"_server_{port}.db")
        self.temp_files.append(temp_db)
        
        # Build command
        cmd = [
            "build/openadp-server",
            "-port", str(port),
            "-db", temp_db,
            "-auth", "true"
        ]
        
        if debug_mode:
            cmd.append("-debug")
        
        try:
            # Start server process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(os.environ, OPENADP_DEBUG="1" if debug_mode else "0")
            )
            
            # Wait for server to start
            time.sleep(3)
            
            # Test if server is responding
            test_cmd = ["curl", "-s", f"http://127.0.0.1:{port}"]
            test_result = subprocess.run(test_cmd, capture_output=True, timeout=5)
            
            if test_result.returncode == 0:
                print(f"✅ OpenADP server started successfully on port {port}")
                self.server_processes.append(process)
                return process
            else:
                print(f"❌ OpenADP server on port {port} not responding")
                process.terminate()
                return None
                
        except Exception as e:
            print(f"❌ Failed to start OpenADP server on port {port}: {e}")
            return None
    
    def get_server_info(self, port):
        """Get server info including public key using openadp-serverinfo tool"""
        print(f"Querying server info for port {port}...")
        
        try:
            cmd = [
                "cmd/openadp-serverinfo/openadp-serverinfo",
                "-server", f"http://127.0.0.1:{port}",
                "-format", "json"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse the JSON response
                server_info = json.loads(result.stdout)
                print(f"✅ Retrieved server info for port {port}")
                return server_info
            else:
                print(f"❌ Failed to get server info for port {port}")
                print(f"Error: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"❌ Exception getting server info for port {port}: {e}")
            return None
    
    def build_servers_json(self, server_ports):
        """Build a proper servers.json file with real server public keys"""
        print("Building servers.json with real server keys...")
        
        servers = []
        
        for port in server_ports:
            server_info = self.get_server_info(port)
            if server_info:
                # Extract public key from server info
                public_key = server_info.get("noise_nk_public_key", "")
                if not public_key:
                    print(f"⚠️  No public key found for server on port {port}")
                    continue
                
                server_config = {
                    "url": f"http://127.0.0.1:{port}",
                    "public_key": f"ed25519:{public_key}",
                    "country": "test",
                    "description": f"Test OpenADP server on port {port}"
                }
                
                servers.append(server_config)
                self.server_configs.append(server_config)
                print(f"✅ Added server {port} with key: {public_key[:32]}...")
            else:
                print(f"❌ Skipping server on port {port} due to info query failure")
        
        if not servers:
            print("❌ No servers available for servers.json")
            return None
        
        # Create servers.json
        servers_json = {
            "servers": servers
        }
        
        # Write to file
        with open("test_servers_registry.json", "w") as f:
            json.dump(servers_json, f, indent=2)
        
        print(f"✅ Created servers.json with {len(servers)} servers")
        print(f"📄 Saved to: test_servers_registry.json")
        
        return servers_json
    
    def start_registry_server(self, port=8082):
        """Start HTTP server to host the servers.json file"""
        print(f"Starting registry server on port {port}...")
        
        class RegistryHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                # Suppress logging for cleaner output
                pass
            
            def do_GET(self):
                # Support both the main file and the expected API path
                if self.path == '/test_servers_registry.json' or self.path == '/test_servers_registry.json/api/servers.json':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    try:
                        with open('test_servers_registry.json', 'rb') as f:
                            self.wfile.write(f.read())
                    except FileNotFoundError:
                        self.send_response(404)
                        self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()
        
        try:
            httpd = socketserver.TCPServer(("", port), RegistryHandler)
            
            # Start server in background thread
            server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            server_thread.start()
            
            # Wait for server to start
            time.sleep(1)
            
            print(f"✅ Registry server started on port {port}")
            self.registry_server = httpd
            return httpd
            
        except Exception as e:
            print(f"❌ Failed to start registry server: {e}")
            return None
    
    def setup_test_environment(self, server_ports=[8083, 8084], registry_port=8085, debug_mode=True):
        """Set up complete test environment with real servers and proper keys"""
        print("🚀 Setting up test environment with real OpenADP servers...")
        print(f"Server ports: {server_ports}")
        print(f"Registry port: {registry_port}")
        print(f"Debug mode: {debug_mode}")
        print("-" * 60)
        
        # Step 1: Start OpenADP servers
        print("Step 1: Starting OpenADP servers...")
        successful_servers = []
        
        for port in server_ports:
            process = self.start_openadp_server(port, debug_mode)
            if process:
                successful_servers.append(port)
            else:
                print(f"⚠️  Failed to start server on port {port}")
        
        if not successful_servers:
            print("❌ No servers started successfully")
            return False
        
        print(f"✅ Started {len(successful_servers)} servers: {successful_servers}")
        
        # Step 2: Build servers.json with real keys
        print("\nStep 2: Building servers.json with real keys...")
        servers_json = self.build_servers_json(successful_servers)
        
        if not servers_json:
            print("❌ Failed to build servers.json")
            return False
        
        # Step 3: Start registry server
        print("\nStep 3: Starting registry server...")
        registry_server = self.start_registry_server(registry_port)
        
        if not registry_server:
            print("❌ Failed to start registry server")
            return False
        
        # Step 4: Verification
        print("\nStep 4: Verifying setup...")
        try:
            # Test registry access
            test_cmd = ["curl", "-s", f"http://127.0.0.1:{registry_port}/test_servers_registry.json"]
            test_result = subprocess.run(test_cmd, capture_output=True, timeout=5)
            
            if test_result.returncode == 0:
                registry_data = json.loads(test_result.stdout)
                print(f"✅ Registry accessible with {len(registry_data['servers'])} servers")
            else:
                print("❌ Registry not accessible")
                return False
        
        except Exception as e:
            print(f"❌ Registry verification failed: {e}")
            return False
        
        print("\n🎉 Test environment setup complete!")
        print(f"📋 Summary:")
        print(f"   - OpenADP servers: {len(successful_servers)} running")
        print(f"   - Registry server: port {registry_port}")
        print(f"   - Servers.json: test_servers_registry.json")
        print(f"   - Ready for cross-language testing!")
        
        return True
    
    def cleanup(self):
        """Clean up all servers and temporary files"""
        print("\n🧹 Cleaning up test environment...")
        
        # Stop server processes
        for process in self.server_processes:
            try:
                process.terminate()
                process.wait(timeout=5)
                print("✅ Stopped OpenADP server")
            except:
                try:
                    process.kill()
                    print("✅ Killed OpenADP server")
                except:
                    print("⚠️  Failed to stop OpenADP server")
        
        # Stop registry server
        if self.registry_server:
            try:
                self.registry_server.shutdown()
                self.registry_server.server_close()
                print("✅ Stopped registry server")
            except:
                print("⚠️  Failed to stop registry server")
        
        # Clean up temporary files
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    print(f"✅ Removed {temp_file}")
            except:
                print(f"⚠️  Failed to remove {temp_file}")
        
        # Clean up generated files
        try:
            if os.path.exists("test_servers_registry.json"):
                os.remove("test_servers_registry.json")
                print("✅ Removed test_servers_registry.json")
        except:
            print("⚠️  Failed to remove test_servers_registry.json")
        
        print("✅ Cleanup complete")

def main():
    """Main function for standalone usage"""
    import signal
    
    manager = TestServerManager()
    
    def signal_handler(sig, frame):
        print("\n🛑 Interrupt received, cleaning up...")
        manager.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Set up test environment
    success = manager.setup_test_environment()
    
    if success:
        print("\n✨ Test environment is ready!")
        print("Press Ctrl+C to stop and cleanup")
        
        try:
            # Keep running until interrupted
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        print("\n❌ Failed to set up test environment")
        manager.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main() 