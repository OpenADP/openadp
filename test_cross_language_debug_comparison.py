#!/usr/bin/env python3
"""
Cross-Language Debug Output Comparison Test

This test runs encryption/decryption operations with both Python and Go implementations
in debug mode and compares their debug output to ensure they perform identical 
cryptographic operations.
"""

import os
import sys
import subprocess
import tempfile
import time
import re

def log(message):
    print(f"[TEST] {message}")

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
        ping_cmd = ["curl", "-s", "http://localhost:8080"]
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
        "--servers", "http://localhost:8080",
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
        "--servers", "http://localhost:8080",
        "--debug"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.returncode, result.stdout, result.stderr

def compare_debug_outputs():
    """Compare debug outputs between Python and Go implementations"""
    log("🔍 Starting cross-language debug comparison...")
    
    # Create test input file
    test_content = b"Hello, debug comparison test! This tests identical crypto operations."
    with open("test_debug_input.txt", 'wb') as f:
        f.write(test_content)
    
    # Start test server
    server_process, temp_db = start_test_server()
    if not server_process:
        log("❌ Cannot start test server")
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
        
        # Extract debug operations
        log("📊 Extracting debug operations...")
        
        py_operations = extract_debug_operations(py_stderr)
        go_operations = extract_debug_operations(go_stderr)
        
        log(f"Python debug operations: {len(py_operations)}")
        log(f"Go debug operations: {len(go_operations)}")
        
        # Show raw debug output for analysis
        log("\n" + "="*60)
        log("RAW PYTHON DEBUG OUTPUT:")
        log("="*60)
        log(py_stderr)
        
        log("\n" + "="*60)
        log("RAW GO DEBUG OUTPUT:")
        log("="*60)
        log(go_stderr)
        
        # Display operations for comparison
        log("\n" + "="*60)
        log("PYTHON DEBUG OPERATIONS:")
        log("="*60)
        for i, op in enumerate(py_operations, 1):
            log(f"{i:2d}. {op}")
        
        log("\n" + "="*60)
        log("GO DEBUG OPERATIONS:")
        log("="*60)
        for i, op in enumerate(go_operations, 1):
            log(f"{i:2d}. {op}")
        
        # Compare operations
        log("\n" + "="*60)
        log("COMPARISON RESULTS:")
        log("="*60)
        
        if len(py_operations) != len(go_operations):
            log(f"❌ Different number of operations: Python={len(py_operations)}, Go={len(go_operations)}")
            return False
        
        mismatches = []
        for i, (py_op, go_op) in enumerate(zip(py_operations, go_operations), 1):
            if py_op != go_op:
                mismatches.append((i, py_op, go_op))
        
        if mismatches:
            log(f"❌ Found {len(mismatches)} mismatches:")
            for i, py_op, go_op in mismatches:
                log(f"   {i:2d}. Python: {py_op}")
                log(f"       Go:     {go_op}")
            return False
        else:
            log("✅ All debug operations match perfectly!")
            log("🎉 Cross-language cryptographic operations are identical!")
            return True
            
    finally:
        # Cleanup
        cleanup_server(server_process, temp_db)
        for f in ["test_debug_input.txt", "test_debug_input.txt.enc"]:
            try:
                if os.path.exists(f):
                    os.remove(f)
            except:
                pass

def main():
    log("🚀 Cross-Language Debug Output Comparison Test")
    log("This test verifies that Python and Go implementations produce identical cryptographic operations")
    
    # Check if tools exist
    if not os.path.exists("sdk/python/openadp-encrypt.py"):
        log("❌ Python encrypt tool not found")
        return 1
    
    if not os.path.exists("build/openadp-encrypt"):
        log("❌ Go encrypt tool not found")
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