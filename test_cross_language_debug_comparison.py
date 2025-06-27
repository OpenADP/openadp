#!/usr/bin/env python3
"""
Cross-Language Debug Output Comparison Test

This test runs encryption/decryption operations with Python, Go, and C++ implementations
in debug mode and compares their debug output to ensure they perform identical 
cryptographic operations.
"""

import os
import sys
import subprocess
import tempfile
import time
import re
import threading
import http.server
import socketserver

def log(message):
    print(f"[TEST] {message}")

def start_registry_server():
    """Start a simple HTTP server to serve the registry JSON file for C++"""
    log("Starting registry server on port 8082...")
    
    class RegistryHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/servers.json':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                with open('test_servers_registry.json', 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
    
    try:
        httpd = socketserver.TCPServer(("", 8082), RegistryHandler)
        
        # Start server in background thread
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()
        
        # Wait a bit for server to start
        time.sleep(1)
        
        log("✅ Registry server started successfully")
        return httpd
        
    except Exception as e:
        log(f"❌ Failed to start registry server: {e}")
        return None

def start_test_server():
    """Start a test server for the debug comparison"""
    log("Starting test server on port 8080...")
    
    # Create temporary database
    temp_db = tempfile.mktemp(suffix="_debug_test.db")
    
    cmd = [
        "build/openadp-server",
        "-port", "8080",
        "-db", temp_db,
        "-auth", "true"
    ]
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for server to start
        time.sleep(3)
        
        # Test if server is responding
        ping_cmd = ["curl", "-s", "http://127.0.0.1:8080"]
        result = subprocess.run(ping_cmd, capture_output=True, timeout=5)
        
        if result.returncode == 0:
            log("✅ Test server started successfully")
            return process, temp_db
        else:
            log("❌ Test server failed to start properly")
            process.terminate()
            return None, temp_db
            
    except Exception as e:
        log(f"❌ Failed to start test server: {e}")
        return None, temp_db

def cleanup_server(process, temp_db):
    """Clean up the test server"""
    if process:
        try:
            process.terminate()
            process.wait(timeout=5)
        except:
            try:
                process.kill()
            except:
                pass
    
    try:
        if os.path.exists(temp_db):
            os.remove(temp_db)
    except:
        pass

def extract_debug_operations(debug_output):
    """Extract key cryptographic operations from debug output"""
    operations = []
    
    # Look for key debug patterns
    patterns = [
        r"\[DEBUG\] (Using deterministic .+)",
        r"\[DEBUG\] (Main secret: .+)",
        r"\[DEBUG\] (Polynomial coefficient \d+: .+)",
        r"\[DEBUG\] (Share \d+ \(x=\d+\): .+)",
        r"\[DEBUG\] (Ephemeral secret: .+)",
        r"\[DEBUG\] (Ed25519 public key: .+)",
        r"\[DEBUG\] (Noise handshake .+)",
        r"\[DEBUG\] (AES-GCM .+)",
        r"\[DEBUG\] (HKDF .+)",
        r"\[DEBUG\] (SHA256 .+)",
    ]
    
    for line in debug_output.split('\n'):
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                operations.append(match.group(1))
    
    return operations

def run_python_debug_encrypt():
    """Run Python encryption with debug output"""
    log("Running Python encryption with debug...")
    
    cmd = [
        "python3", "sdk/python/openadp-encrypt.py",
        "--file", "test_debug_input.txt",
        "--password", "debug_test_pass",
        "--user-id", "debug_test_user",
        "--servers", "http://127.0.0.1:8080",
        "--debug"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.returncode, result.stdout, result.stderr

def run_go_debug_encrypt():
    """Run Go encryption with debug output"""
    log("Running Go encryption with debug...")
    
    cmd = [
        "build/openadp-encrypt",
        "--file", "test_debug_input.txt",
        "--password", "debug_test_pass",
        "--user-id", "debug_test_user",
        "--servers", "http://127.0.0.1:8080",
        "--debug"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.returncode, result.stdout, result.stderr

def run_cpp_debug_encrypt():
    """Run C++ encryption with debug output"""
    log("Running C++ encryption with debug...")
    
    # C++ uses different interface - needs input, output, metadata files and registry URL
    cmd = [
        "sdk/cpp/build/openadp-encrypt",
        "--input", "test_debug_input.txt",
        "--output", "test_debug_input_cpp.enc",
        "--metadata", "test_debug_input_cpp.meta",
        "--password", "debug_test_pass",
        "--user-id", "debug_test_user",
        "--servers-url", "http://127.0.0.1:8082/servers.json",  # Use our local registry
        "--debug"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.returncode, result.stdout, result.stderr

def compare_debug_outputs():
    """Compare debug outputs between Python, Go, and C++ implementations"""
    log("🔍 Starting cross-language debug comparison...")
    
    # Create test input file
    test_content = b"Hello, debug comparison test! This tests identical crypto operations."
    with open("test_debug_input.txt", 'wb') as f:
        f.write(test_content)
    
    # Start registry server for C++
    registry_server = start_registry_server()
    if not registry_server:
        log("❌ Cannot start registry server")
        return False
    
    # Start test server
    server_process, temp_db = start_test_server()
    if not server_process:
        log("❌ Cannot start test server")
        if registry_server:
            registry_server.shutdown()
        return False
    
    try:
        # Run Python encryption with debug
        py_code, py_stdout, py_stderr = run_python_debug_encrypt()
        log(f"Python exit code: {py_code}")
        
        if py_code != 0:
            log("❌ Python encryption failed")
            log(f"Python stdout: {py_stdout}")
            log(f"Python stderr: {py_stderr}")
            return False
        
        # Clean up Python output file for Go test
        if os.path.exists("test_debug_input.txt.enc"):
            os.remove("test_debug_input.txt.enc")
        
        # Run Go encryption with debug  
        go_code, go_stdout, go_stderr = run_go_debug_encrypt()
        log(f"Go exit code: {go_code}")
        
        if go_code != 0:
            log("❌ Go encryption failed")
            log(f"Go stdout: {go_stdout}")
            log(f"Go stderr: {go_stderr}")
            return False
        
        # Clean up Go output file for C++ test
        if os.path.exists("test_debug_input.txt.enc"):
            os.remove("test_debug_input.txt.enc")
        
        # Run C++ encryption with debug
        cpp_code, cpp_stdout, cpp_stderr = run_cpp_debug_encrypt()
        log(f"C++ exit code: {cpp_code}")
        
        if cpp_code != 0:
            log("❌ C++ encryption failed")
            log(f"C++ stdout: {cpp_stdout}")
            log(f"C++ stderr: {cpp_stderr}")
            return False
        
        # Extract debug operations
        log("📊 Extracting debug operations...")
        
        py_operations = extract_debug_operations(py_stderr)
        go_operations = extract_debug_operations(go_stderr)
        cpp_operations = extract_debug_operations(cpp_stderr)
        
        log(f"Python debug operations: {len(py_operations)}")
        log(f"Go debug operations: {len(go_operations)}")
        log(f"C++ debug operations: {len(cpp_operations)}")
        
        # Show raw debug output for analysis
        log("\n" + "="*60)
        log("RAW PYTHON DEBUG OUTPUT:")
        log("="*60)
        log(py_stderr)
        
        log("\n" + "="*60)
        log("RAW GO DEBUG OUTPUT:")
        log("="*60)
        log(go_stderr)
        
        log("\n" + "="*60)
        log("RAW C++ DEBUG OUTPUT:")
        log("="*60)
        log(cpp_stderr)
        
        # Display operations for comparison
        log("\n" + "="*60)
        log("PYTHON DEBUG OPERATIONS:")
        log("="*60)
        for i, op in enumerate(py_operations, 1):
            log(f" {i:2}. {op}")
        
        log("\n" + "="*60)
        log("GO DEBUG OPERATIONS:")
        log("="*60)
        for i, op in enumerate(go_operations, 1):
            log(f" {i:2}. {op}")
        
        log("\n" + "="*60)
        log("C++ DEBUG OPERATIONS:")
        log("="*60)
        for i, op in enumerate(cpp_operations, 1):
            log(f" {i:2}. {op}")
        
        # Compare operations
        log("\n" + "="*60)
        log("COMPARISON RESULTS:")
        log("="*60)
        
        # Check if all have same number of operations
        if len(py_operations) == len(go_operations) == len(cpp_operations):
            log(f"✅ All implementations have {len(py_operations)} debug operations")
            
            # Check if operations match
            all_match = True
            for i, (py_op, go_op, cpp_op) in enumerate(zip(py_operations, go_operations, cpp_operations)):
                if py_op == go_op == cpp_op:
                    log(f"✅ Operation {i+1}: All match")
                else:
                    log(f"❌ Operation {i+1}: Mismatch")
                    log(f"   Python: {py_op}")
                    log(f"   Go:     {go_op}")
                    log(f"   C++:    {cpp_op}")
                    all_match = False
            
            if all_match:
                log("✅ All debug operations match perfectly!")
                log("🎉 Cross-language cryptographic operations are identical!")
                return True
            else:
                log("❌ Some debug operations don't match")
                return False
        else:
            log(f"❌ Different number of operations: Python={len(py_operations)}, Go={len(go_operations)}, C++={len(cpp_operations)}")
            return False
    
    finally:
        # Cleanup
        cleanup_server(server_process, temp_db)
        if registry_server:
            registry_server.shutdown()
        
        # Clean up test files
        for file in ["test_debug_input.txt", "test_debug_input.txt.enc", 
                     "test_debug_input_cpp.enc", "test_debug_input_cpp.meta"]:
            try:
                if os.path.exists(file):
                    os.remove(file)
            except:
                pass

def main():
    log("🚀 Cross-Language Debug Output Comparison Test (Python, Go, C++)")
    log("This test verifies that all implementations produce identical cryptographic operations")
    
    # Check if tools exist
    if not os.path.exists("sdk/python/openadp-encrypt.py"):
        log("❌ Python encrypt tool not found")
        return 1
    
    if not os.path.exists("build/openadp-encrypt"):
        log("❌ Go encrypt tool not found")
        return 1
    
    if not os.path.exists("sdk/cpp/build/openadp-encrypt"):
        log("❌ C++ encrypt tool not found")
        return 1
    
    if not os.path.exists("build/openadp-server"):
        log("❌ Go server not found")
        return 1
    
    # Run the comparison
    if compare_debug_outputs():
        log("🎉 Cross-language debug comparison PASSED!")
        return 0
    else:
        log("💥 Cross-language debug comparison FAILED!")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 