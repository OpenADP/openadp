#!/usr/bin/env python3
"""
Cross-Language Encrypt/Decrypt Test Script

This script tests all 4 combinations of encryption and decryption between Python and Go:
1. Python encrypt -> Python decrypt
2. Python encrypt -> Go decrypt
3. Go encrypt -> Python decrypt
4. Go encrypt -> Go decrypt

It runs local Go OpenADP servers for each test to ensure proper isolation.
"""

import os
import sys
import time
import subprocess
import tempfile
import shutil
import threading
import json
import hashlib
from pathlib import Path

# Test configuration
TEST_PASSWORD = "test_password_123"
TEST_USER_ID = "test_user_cross_lang"
TEST_CONTENT = b"Hello, OpenADP Cross-Language Test! This is a test file for encryption/decryption compatibility between Python and Go implementations."

# Server configuration for testing
SERVER_PORTS = [8080, 8081, 8082]  # Use multiple servers for comprehensive testing
SERVER_PROCESSES = []
SERVER_URLS = [f"http://localhost:{port}" for port in SERVER_PORTS]

# Detect if we're running from cross-language directory or project root
if os.path.basename(os.getcwd()) == "cross-language":
    # Running from tests/cross-language directory
    SDK_PYTHON_PATH = "../../sdk/python"
    BUILD_PATH = "../../build"
else:
    # Running from project root
    SDK_PYTHON_PATH = "sdk/python"
    BUILD_PATH = "build"

def log(message):
    """Log a message with timestamp"""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

def start_local_servers():
    """Start local Go OpenADP servers for testing"""
    log("Starting local OpenADP servers...")
    
    # Clean up any existing server processes
    cleanup_servers()
    
    for i, port in enumerate(SERVER_PORTS):
        log(f"Starting server on port {port}...")
        
        # Create temporary database for this server
        temp_db = tempfile.mktemp(suffix=f"_server_{port}.db")
        
        # Start server process using built executable
        cmd = [
            BUILD_PATH + "/openadp-server",
            "-port", str(port),
            "-db", temp_db,
            "-auth", "true"
        ]
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="."
            )
            SERVER_PROCESSES.append((process, temp_db))
            log(f"Server started on port {port} (PID: {process.pid})")
        except Exception as e:
            log(f"Failed to start server on port {port}: {e}")
            return False
    
    # Wait for servers to start up
    log("Waiting for servers to initialize...")
    time.sleep(5)
    
    # Verify servers are responding
    for url in SERVER_URLS:
        if not ping_server(url):
            log(f"Server at {url} is not responding")
            cleanup_servers()
            return False
        log(f"Server at {url} is ready")
    
    return True

def ping_server(url):
    """Check if server is responding"""
    try:
        import requests
        response = requests.post(
            f"{url}",
            json={
                "jsonrpc": "2.0",
                "method": "Echo",
                "params": ["ping"],
                "id": 1
            },
            timeout=5
        )
        return response.status_code == 200
    except:
        return False

def cleanup_servers():
    """Clean up server processes and temporary files"""
    log("Cleaning up servers...")
    
    for process, temp_db in SERVER_PROCESSES:
        try:
            process.terminate()
            process.wait(timeout=5)
        except:
            try:
                process.kill()
            except:
                pass
        
        # Clean up temporary database
        try:
            if os.path.exists(temp_db):
                os.remove(temp_db)
        except:
            pass
    
    SERVER_PROCESSES.clear()

def create_test_file(content=None):
    """Create a temporary test file"""
    if content is None:
        content = TEST_CONTENT
    
    temp_file = tempfile.mktemp(suffix=".txt")
    with open(temp_file, 'wb') as f:
        f.write(content)
    
    return temp_file

def run_python_encrypt(input_file, output_file=None):
    """Run Python encryption"""
    if output_file is None:
        output_file = input_file + ".enc"
    
    cmd = [
        "python3", SDK_PYTHON_PATH + "/openadp-encrypt.py",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running Python encrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Python encrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr
    
    if not os.path.exists(output_file):
        log(f"Python encrypt didn't create output file: {output_file}")
        return False, "Output file not created"
    
    log("Python encrypt succeeded")
    return True, None

def run_python_decrypt(input_file, output_file=None):
    """Run Python decryption"""
    if output_file is None:
        output_file = input_file.replace(".enc", "_decrypted.txt")
    
    cmd = [
        "python3", SDK_PYTHON_PATH + "/openadp-decrypt.py",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running Python decrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Python decrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr
    
    expected_output = input_file.replace(".enc", "")
    if not os.path.exists(expected_output):
        log(f"Python decrypt didn't create output file: {expected_output}")
        return False, "Output file not created"
    
    log("Python decrypt succeeded")
    return True, None

def run_go_encrypt(input_file, output_file=None):
    """Run Go encryption"""
    if output_file is None:
        output_file = input_file + ".enc"
    
    cmd = [
        BUILD_PATH + "/openadp-encrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running Go encrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=".")
    
    if result.returncode != 0:
        log(f"Go encrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr
    
    if not os.path.exists(output_file):
        log(f"Go encrypt didn't create output file: {output_file}")
        return False, "Output file not created"
    
    log("Go encrypt succeeded")
    return True, None

def run_go_decrypt(input_file, output_file=None):
    """Run Go decryption"""
    if output_file is None:
        output_file = input_file.replace(".enc", "_decrypted.txt")
    
    cmd = [
        BUILD_PATH + "/openadp-decrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running Go decrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=".")
    
    if result.returncode != 0:
        log(f"Go decrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr
    
    expected_output = input_file.replace(".enc", "")
    if not os.path.exists(expected_output):
        log(f"Go decrypt didn't create output file: {expected_output}")
        return False, "Output file not created"
    
    log("Go decrypt succeeded")
    return True, None

def verify_file_content(file_path, expected_content):
    """Verify that a file contains the expected content"""
    try:
        with open(file_path, 'rb') as f:
            actual_content = f.read()
        
        if actual_content == expected_content:
            log(f"File content verification passed: {file_path}")
            return True
        else:
            log(f"File content verification failed: {file_path}")
            log(f"Expected: {expected_content[:50]}...")
            log(f"Actual:   {actual_content[:50]}...")
            return False
    except Exception as e:
        log(f"Failed to read file {file_path}: {e}")
        return False

def run_test_case(test_name, encrypt_func, decrypt_func):
    """Run a single test case"""
    log(f"\n{'='*60}")
    log(f"TEST CASE: {test_name}")
    log(f"{'='*60}")
    
    # Create test file
    test_file = create_test_file()
    encrypted_file = test_file + ".enc"
    
    try:
        # Step 1: Encrypt
        log("Step 1: Encryption")
        success, error = encrypt_func(test_file)
        if not success:
            log(f"❌ Encryption failed: {error}")
            return False
        
        # Verify encrypted file exists and is different from original
        if not os.path.exists(encrypted_file):
            log(f"❌ Encrypted file not found: {encrypted_file}")
            return False
        
        with open(encrypted_file, 'rb') as f:
            encrypted_content = f.read()
        
        if encrypted_content == TEST_CONTENT:
            log("❌ Encrypted file is identical to original (not encrypted)")
            return False
        
        log(f"✅ Encryption successful, encrypted file size: {len(encrypted_content)} bytes")
        
        # Step 2: Decrypt
        log("Step 2: Decryption")
        success, error = decrypt_func(encrypted_file)
        if not success:
            log(f"❌ Decryption failed: {error}")
            return False
        
        # Step 3: Verify decrypted content
        log("Step 3: Content verification")
        decrypted_file = encrypted_file.replace(".enc", "")
        if not verify_file_content(decrypted_file, TEST_CONTENT):
            log("❌ Decrypted content doesn't match original")
            return False
        
        log(f"✅ {test_name} PASSED")
        return True
        
    except Exception as e:
        log(f"❌ Test case failed with exception: {e}")
        return False
    
    finally:
        # Clean up test files
        for file_path in [test_file, encrypted_file, encrypted_file.replace(".enc", "")]:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except:
                pass

def main():
    """Main test function"""
    log("🚀 Starting Cross-Language Encrypt/Decrypt Tests")
    log(f"Test password: {TEST_PASSWORD}")
    log(f"Test user ID: {TEST_USER_ID}")
    log(f"Test content length: {len(TEST_CONTENT)} bytes")
    
    # Step 1: Start local servers
    if not start_local_servers():
        log("❌ Failed to start local servers")
        sys.exit(1)
    
    try:
        # Step 2: Run all test cases
        test_cases = [
            ("Python Encrypt -> Python Decrypt", run_python_encrypt, run_python_decrypt),
            ("Python Encrypt -> Go Decrypt", run_python_encrypt, run_go_decrypt),
            ("Go Encrypt -> Python Decrypt", run_go_encrypt, run_python_decrypt),
            ("Go Encrypt -> Go Decrypt", run_go_encrypt, run_go_decrypt),
        ]
        
        results = []
        for test_name, encrypt_func, decrypt_func in test_cases:
            result = run_test_case(test_name, encrypt_func, decrypt_func)
            results.append((test_name, result))
            
            # Wait between tests to avoid server overload
            time.sleep(2)
        
        # Step 3: Summary
        log(f"\n{'='*60}")
        log("TEST SUMMARY")
        log(f"{'='*60}")
        
        passed = 0
        failed = 0
        
        for test_name, result in results:
            status = "✅ PASSED" if result else "❌ FAILED"
            log(f"{test_name}: {status}")
            
            if result:
                passed += 1
            else:
                failed += 1
        
        log(f"\nTotal: {len(results)} tests")
        log(f"Passed: {passed}")
        log(f"Failed: {failed}")
        
        if failed == 0:
            log("🎉 All tests PASSED! Cross-language compatibility verified.")
            exit_code = 0
        else:
            log("💥 Some tests FAILED. Check the logs above for details.")
            exit_code = 1
        
    finally:
        # Step 4: Cleanup
        cleanup_servers()
        log("🧹 Cleanup completed")
    
    sys.exit(exit_code)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n🛑 Test interrupted by user")
        cleanup_servers()
        sys.exit(1)
    except Exception as e:
        log(f"\n💥 Test failed with unexpected error: {e}")
        cleanup_servers()
        sys.exit(1) 