#!/usr/bin/env python3
"""
Standalone Noise-NK Cross-Platform Compatibility Test

This script tests the compatibility between the Python Noise-NK server and JavaScript client.
It can be run independently for debugging or as part of the main test suite.

Usage:
    ./test_noise_nk_compatibility.py              # Run the test
    ./test_noise_nk_compatibility.py --verbose    # Verbose output
    ./test_noise_nk_compatibility.py --no-cleanup # Don't clean up files (for debugging)
"""

import os
import sys
import subprocess
import time
import argparse
import json
from pathlib import Path

def log(message: str, verbose: bool = False):
    """Log a message with timestamp"""
    if verbose:
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
    else:
        print(message)

def run_command(cmd, cwd=None, timeout=60):
    """Run a command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd, 
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return False, "", str(e)

def check_dependencies(verbose=False):
    """Check if all required dependencies are available"""
    log("🔍 Checking dependencies...", verbose)
    
    # Check Node.js
    success, stdout, stderr = run_command(["node", "--version"])
    if not success:
        log("❌ Node.js not found. Please install Node.js.")
        return False
    
    node_version = stdout.strip()
    log(f"✅ Node.js: {node_version}", verbose)
    
    # Check Python environment
    try:
        # Add the Python SDK to path
        sys.path.insert(0, str(Path("sdk/python")))
        import openadp
        log("✅ OpenADP Python SDK available", verbose)
    except ImportError:
        log("❌ OpenADP Python SDK not found. Make sure you're in the right environment.")
        return False
    
    # Check if JavaScript SDK exists
    js_sdk_path = Path("sdk/javascript")
    if not js_sdk_path.exists():
        log("❌ JavaScript SDK directory not found")
        return False
    
    # Check if noise_client.js exists
    client_path = js_sdk_path / "noise_client.js"
    if not client_path.exists():
        log("❌ noise_client.js not found")
        return False
    
    # Check if Python noise_server.py exists
    server_path = Path("sdk/python/noise_server.py")
    if not server_path.exists():
        log("❌ noise_server.py not found")
        return False
    
    log("✅ All dependencies available", verbose)
    return True

def install_js_dependencies(verbose=False):
    """Install JavaScript dependencies if needed"""
    js_sdk_path = Path("sdk/javascript")
    node_modules_path = js_sdk_path / "node_modules"
    
    if node_modules_path.exists():
        log("✅ JavaScript dependencies already installed", verbose)
        return True
    
    log("📦 Installing JavaScript dependencies...", verbose)
    success, stdout, stderr = run_command(["npm", "install"], cwd=js_sdk_path)
    
    if success:
        log("✅ JavaScript dependencies installed", verbose)
        return True
    else:
        log(f"❌ Failed to install JavaScript dependencies: {stderr}")
        return False

def test_noise_nk_compatibility(verbose=False, no_cleanup=False):
    """Test Noise-NK cross-platform compatibility"""
    log("🔒 Testing Noise-NK cross-platform compatibility...")
    
    server_process = None
    server_info_path = Path("sdk/python/server_info.json")
    
    try:
        # Start Python Noise server
        log("🚀 Starting Python Noise-NK server...", verbose)
        server_process = subprocess.Popen(
            ["python", "noise_server.py"],
            cwd="sdk/python",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for server to start
        log("⏳ Waiting for server to start...", verbose)
        max_wait = 10
        wait_time = 0
        
        while wait_time < max_wait:
            if server_info_path.exists():
                time.sleep(1)  # Give it another second to fully initialize
                break
            time.sleep(0.5)
            wait_time += 0.5
        
        if not server_info_path.exists():
            if server_process.poll() is not None:
                _, stderr = server_process.communicate()
                log(f"❌ Server failed to start: {stderr}")
                return False
            else:
                log("❌ Server didn't create server_info.json in time")
                return False
        
        # Read server info
        with open(server_info_path) as f:
            server_info = json.load(f)
        
        log(f"📡 Server started on {server_info['host']}:{server_info['port']}", verbose)
        log(f"🔑 Server public key: {server_info['public_key'][:32]}...", verbose)
        
        # Run JavaScript client
        log("🔗 Running JavaScript client test...", verbose)
        success, stdout, stderr = run_command(
            ["node", "noise_client.js"],
            cwd="sdk/javascript",
            timeout=60
        )
        
        if success and "All tests completed successfully!" in stdout:
            log("✅ Noise-NK compatibility test: PASSED")
            
            if verbose:
                # Show some key metrics from the output
                lines = stdout.split('\n')
                for line in lines:
                    if "handshake completed" in line.lower() or "tests completed" in line.lower():
                        log(f"   {line.strip()}", verbose)
            
            return True
        else:
            log("❌ Noise-NK compatibility test: FAILED")
            
            if stderr:
                log(f"Error output: {stderr}")
            
            if verbose:
                log("Full output:", verbose)
                log(stdout, verbose)
            
            return False
    
    except Exception as e:
        log(f"❌ Exception during test: {e}")
        return False
    
    finally:
        # Clean up server process
        if server_process:
            try:
                log("🛑 Stopping server...", verbose)
                server_process.terminate()
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
                server_process.wait()
            except Exception:
                pass
        
        # Clean up server_info.json unless no_cleanup is specified
        if not no_cleanup:
            try:
                if server_info_path.exists():
                    server_info_path.unlink()
                    log("🧹 Cleaned up server_info.json", verbose)
            except Exception:
                pass

def main():
    parser = argparse.ArgumentParser(description="Noise-NK Cross-Platform Compatibility Test")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--no-cleanup", action="store_true", help="Don't clean up files (for debugging)")
    
    args = parser.parse_args()
    
    print("🔐 Noise-NK Cross-Platform Compatibility Test")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies(args.verbose):
        sys.exit(1)
    
    # Install JavaScript dependencies
    if not install_js_dependencies(args.verbose):
        sys.exit(1)
    
    # Run the test
    start_time = time.time()
    success = test_noise_nk_compatibility(args.verbose, args.no_cleanup)
    duration = time.time() - start_time
    
    print("=" * 50)
    if success:
        print(f"🎉 Test completed successfully in {duration:.2f}s")
        print("🔗 Python server and JavaScript client are fully compatible!")
        sys.exit(0)
    else:
        print(f"💥 Test failed after {duration:.2f}s")
        print("🔧 Check the error messages above for details")
        sys.exit(1)

if __name__ == "__main__":
    main() 