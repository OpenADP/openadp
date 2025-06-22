#!/usr/bin/env python3
"""
Noise-NK Cross-Platform Compatibility Test Runner

This script runs the Python server and JavaScript client to demonstrate
that our Noise-NK implementations are fully compatible across platforms.
"""

import subprocess
import time
import os
import sys
import signal
import json
from pathlib import Path

def run_server():
    """Start the Python server."""
    print("🚀 Starting Python Noise-NK server...")
    
    # Change to Python SDK directory
    python_dir = Path(__file__).parent / "python"
    
    # Start server process
    server_process = subprocess.Popen(
        [sys.executable, "noise_server.py"],
        cwd=python_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True
    )
    
    # Wait for server to start and create server_info.json
    server_info_path = python_dir / "server_info.json"
    timeout = 10  # seconds
    start_time = time.time()
    
    while not server_info_path.exists():
        if time.time() - start_time > timeout:
            print("❌ Server failed to start within timeout")
            server_process.terminate()
            return None
            
        if server_process.poll() is not None:
            print("❌ Server process terminated unexpectedly")
            output = server_process.stdout.read()
            print(f"Server output: {output}")
            return None
            
        time.sleep(0.1)
    
    print("✅ Python server started successfully")
    return server_process

def run_client():
    """Run the JavaScript client."""
    print("🔗 Starting JavaScript Noise-NK client...")
    
    # Change to JavaScript SDK directory
    js_dir = Path(__file__).parent / "javascript"
    
    # Run client
    try:
        result = subprocess.run(
            ["node", "noise_client.js"],
            cwd=js_dir,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        print("📤 Client output:")
        print(result.stdout)
        
        if result.stderr:
            print("⚠️  Client errors:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("✅ JavaScript client completed successfully")
            return True
        else:
            print(f"❌ JavaScript client failed with exit code {result.returncode}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ JavaScript client timed out")
        return False
    except Exception as e:
        print(f"❌ Error running JavaScript client: {e}")
        return False

def main():
    """Run the compatibility test."""
    print("🔐 Noise-NK Cross-Platform Compatibility Test")
    print("=" * 50)
    print()
    
    server_process = None
    
    try:
        # Start Python server
        server_process = run_server()
        if not server_process:
            print("❌ Failed to start server")
            return False
        
        # Give server a moment to fully initialize
        time.sleep(2)
        
        # Run JavaScript client
        client_success = run_client()
        
        if client_success:
            print()
            print("🎉 SUCCESS! Cross-platform compatibility confirmed!")
            print("✅ Python server and JavaScript client communicate perfectly")
            print("✅ Noise-NK handshake completed successfully")
            print("✅ Secure message exchange working")
            print("✅ All test messages echoed correctly")
            print()
            print("🔗 The implementations are fully compatible!")
            return True
        else:
            print()
            print("❌ FAILURE! Compatibility test failed")
            return False
    
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
        return False
    
    finally:
        # Clean up server process
        if server_process:
            print("🛑 Stopping Python server...")
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("⚠️  Server didn't stop gracefully, force killing...")
                server_process.kill()
            
            # Clean up server info file
            server_info_path = Path(__file__).parent / "python" / "server_info.json"
            if server_info_path.exists():
                server_info_path.unlink()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 