#!/usr/bin/env python3
"""
Enhanced Cross-Language Encrypt/Decrypt Test Script (16x16 Matrix)

This script tests all 16 combinations of encryption and decryption between Go, Python, JavaScript, and Rust:

ENCRYPT -> DECRYPT:
1.  Go -> Go            5.  Python -> Go          9.  JavaScript -> Go       13. Rust -> Go
2.  Go -> Python        6.  Python -> Python      10. JavaScript -> Python   14. Rust -> Python  
3.  Go -> JavaScript    7.  Python -> JavaScript  11. JavaScript -> JavaScript 15. Rust -> JavaScript
4.  Go -> Rust          8.  Python -> Rust        12. JavaScript -> Rust     16. Rust -> Rust

It runs local Go OpenADP servers once for all tests to ensure optimal performance.
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
TEST_PASSWORD = "test_password_16x16"
TEST_USER_ID = "test_user_16x16_cross_lang"
TEST_CONTENT = b"Hello, OpenADP 16x16 Cross-Language Test! This tests all combinations of Go/Python/JavaScript/Rust encrypt/decrypt compatibility for comprehensive interoperability validation across all four language implementations."

# Server configuration for testing
SERVER_PORTS = [8080, 8081, 8082]  # Use multiple servers for comprehensive testing
SERVER_PROCESSES = []
SERVER_URLS = [f"http://localhost:{port}" for port in SERVER_PORTS]

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
        
        # Start server process using built executable with Noise-NK encryption
        cmd = [
            "./build/openadp-server",
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

def create_test_file(content=None, suffix=".txt"):
    """Create a temporary test file"""
    if content is None:
        content = TEST_CONTENT
    
    temp_file = tempfile.mktemp(suffix=suffix)
    with open(temp_file, 'wb') as f:
        f.write(content)
    
    return temp_file

def run_go_encrypt(input_file, output_file=None):
    """Run Go encryption"""
    if output_file is None:
        output_file = input_file + ".enc"
    
    cmd = [
        "./build/openadp-encrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running Go encrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
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
        # Go decrypt tool strips .enc extension by default
        output_file = input_file.replace(".enc", "")
    
    cmd = [
        "./build/openadp-decrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running Go decrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Go decrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr
    
    # Check if default output file exists (only possibility: .enc removed)
    if os.path.exists(output_file):
        log("Go decrypt succeeded")
        return True, None
    else:
        log(f"Go decrypt didn't create output file: {output_file}")
        return False, "Output file not created"

def run_python_encrypt(input_file, output_file=None):
    """Run Python encryption"""
    if output_file is None:
        output_file = input_file + ".enc"
    
    cmd = [
        "python3", "sdk/python/openadp-encrypt.py",
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
        output_file = input_file.replace(".enc", "")
    
    cmd = [
        "python3", "sdk/python/openadp-decrypt.py",
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
    
    if not os.path.exists(output_file):
        log(f"Python decrypt didn't create output file: {output_file}")
        return False, "Output file not created"
    
    log("Python decrypt succeeded")
    return True, None

def run_javascript_encrypt(input_file, output_file=None):
    """Run JavaScript encryption"""
    if output_file is None:
        output_file = input_file + ".enc"
    
    cmd = [
        "node", "sdk/javascript/openadp-encrypt.js",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running JavaScript encrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"JavaScript encrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr
    
    if not os.path.exists(output_file):
        log(f"JavaScript encrypt didn't create output file: {output_file}")
        return False, "Output file not created"
    
    log("JavaScript encrypt succeeded")
    return True, None

def run_javascript_decrypt(input_file, output_file=None):
    """Run JavaScript decryption"""
    if output_file is None:
        output_file = input_file.replace(".enc", "")
    
    cmd = [
        "node", "sdk/javascript/openadp-decrypt.js",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running JavaScript decrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"JavaScript decrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr
    
    if not os.path.exists(output_file):
        log(f"JavaScript decrypt didn't create output file: {output_file}")
        return False, "Output file not created"
    
    log("JavaScript decrypt succeeded")
    return True, None

def run_rust_encrypt(input_file, output_file=None):
    """Run Rust encryption"""
    if output_file is None:
        output_file = input_file + ".enc"
    
    cmd = [
        "./sdk/rust/target/release/openadp-encrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running Rust encrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Rust encrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr
    
    if not os.path.exists(output_file):
        log(f"Rust encrypt didn't create output file: {output_file}")
        return False, "Output file not created"
    
    log("Rust encrypt succeeded")
    return True, None

def run_rust_decrypt(input_file, output_file=None):
    """Run Rust decryption"""
    if output_file is None:
        output_file = input_file.replace(".enc", "")
    
    cmd = [
        "./sdk/rust/target/release/openadp-decrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running Rust decrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Rust decrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr
    
    if not os.path.exists(output_file):
        log(f"Rust decrypt didn't create output file: {output_file}")
        return False, "Output file not created"
    
    log("Rust decrypt succeeded")
    return True, None

def verify_file_content(file_path, expected_content):
    """Verify that a file contains the expected content"""
    try:
        if not os.path.exists(file_path):
            log(f"File does not exist: {file_path}")
            return False
        
        with open(file_path, 'rb') as f:
            actual_content = f.read()
        
        if actual_content == expected_content:
            log(f"✅ File content verified: {file_path}")
            return True
        else:
            log(f"❌ File content mismatch: {file_path}")
            log(f"Expected length: {len(expected_content)}")
            log(f"Actual length: {len(actual_content)}")
            # Show first 100 bytes for debugging
            log(f"Expected: {expected_content[:100]}")
            log(f"Actual: {actual_content[:100]}")
            return False
    except Exception as e:
        log(f"Error verifying file content: {e}")
        return False

def run_test_case(test_name, encrypt_func, decrypt_func):
    """Run a single test case"""
    log(f"\n{'='*60}")
    log(f"🧪 Running test: {test_name}")
    log(f"{'='*60}")
    
    # Create test input file
    input_file = create_test_file()
    temp_files = [input_file]
    
    try:
        # Step 1: Encrypt
        log(f"📤 Step 1: Encryption")
        encrypted_file = input_file + ".enc"
        temp_files.append(encrypted_file)
        
        encrypt_success, encrypt_error = encrypt_func(input_file, encrypted_file)
        if not encrypt_success:
            log(f"❌ Encryption failed: {encrypt_error}")
            return False
        
        log(f"✅ Encryption successful: {encrypted_file}")
        
        # Step 2: Decrypt
        log(f"📥 Step 2: Decryption")
        decrypted_file = encrypted_file.replace(".enc", "")
        temp_files.append(decrypted_file)
        
        decrypt_success, decrypt_error = decrypt_func(encrypted_file, decrypted_file)
        if not decrypt_success:
            log(f"❌ Decryption failed: {decrypt_error}")
            return False
        
        log(f"✅ Decryption successful: {decrypted_file}")
        
        # Step 3: Verify content
        log(f"🔍 Step 3: Content verification")
        if verify_file_content(decrypted_file, TEST_CONTENT):
            log(f"🎉 Test PASSED: {test_name}")
            return True
        else:
            log(f"❌ Test FAILED: {test_name} (content mismatch)")
            return False
    
    except Exception as e:
        log(f"❌ Test FAILED: {test_name} (exception: {e})")
        return False
    
    finally:
        # Clean up temporary files
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except:
                pass

def main():
    """Main test function"""
    log("🚀 Starting Enhanced Cross-Language Test (16x16 Matrix)")
    log(f"Test content length: {len(TEST_CONTENT)} bytes")
    log(f"Test password: {TEST_PASSWORD}")
    log(f"Test user ID: {TEST_USER_ID}")
    
    # Check required tools exist
    required_tools = [
        "./build/openadp-encrypt",
        "./build/openadp-decrypt", 
        "sdk/python/openadp-encrypt.py",
        "sdk/python/openadp-decrypt.py",
        "sdk/javascript/openadp-encrypt.js",
        "sdk/javascript/openadp-decrypt.js",
        "./sdk/rust/target/release/openadp-encrypt",
        "./sdk/rust/target/release/openadp-decrypt"
    ]
    
    for tool in required_tools:
        if not os.path.exists(tool):
            log(f"❌ Required tool not found: {tool}")
            log("Please build all tools before running tests")
            return False
    
    log("✅ All required tools found")
    
    # Start local servers
    if not start_local_servers():
        log("❌ Failed to start local servers")
        return False
    
    try:
        # Define all 16 test combinations (4x4 matrix)
        test_cases = [
            # Go encrypt -> *
            ("1.  Go -> Go", run_go_encrypt, run_go_decrypt),
            ("2.  Go -> Python", run_go_encrypt, run_python_decrypt),
            ("3.  Go -> JavaScript", run_go_encrypt, run_javascript_decrypt),
            ("4.  Go -> Rust", run_go_encrypt, run_rust_decrypt),
            
            # Python encrypt -> *
            ("5.  Python -> Go", run_python_encrypt, run_go_decrypt),
            ("6.  Python -> Python", run_python_encrypt, run_python_decrypt),
            ("7.  Python -> JavaScript", run_python_encrypt, run_javascript_decrypt),
            ("8.  Python -> Rust", run_python_encrypt, run_rust_decrypt),
            
            # JavaScript encrypt -> *
            ("9.  JavaScript -> Go", run_javascript_encrypt, run_go_decrypt),
            ("10. JavaScript -> Python", run_javascript_encrypt, run_python_decrypt),
            ("11. JavaScript -> JavaScript", run_javascript_encrypt, run_javascript_decrypt),
            ("12. JavaScript -> Rust", run_javascript_encrypt, run_rust_decrypt),
            
            # Rust encrypt -> *
            ("13. Rust -> Go", run_rust_encrypt, run_go_decrypt),
            ("14. Rust -> Python", run_rust_encrypt, run_python_decrypt),
            ("15. Rust -> JavaScript", run_rust_encrypt, run_javascript_decrypt),
            ("16. Rust -> Rust", run_rust_encrypt, run_rust_decrypt),
        ]
        
        # Run all test cases
        results = []
        for test_name, encrypt_func, decrypt_func in test_cases:
            success = run_test_case(test_name, encrypt_func, decrypt_func)
            results.append((test_name, success))
            
            # Brief pause between tests
            time.sleep(1)
        
        # Print summary
        log(f"\n{'='*60}")
        log("📊 TEST SUMMARY")
        log(f"{'='*60}")
        
        passed = 0
        failed = 0
        
        for test_name, success in results:
            status = "✅ PASS" if success else "❌ FAIL"
            log(f"{status} {test_name}")
            if success:
                passed += 1
            else:
                failed += 1
        
        log(f"\n📈 Results: {passed} passed, {failed} failed out of {len(results)} tests")
        
        if failed == 0:
            log("🎉 ALL TESTS PASSED! Complete cross-language compatibility confirmed across all 4 languages!")
            return True
        else:
            log(f"❌ {failed} tests failed. Cross-language compatibility issues detected.")
            return False
    
    finally:
        cleanup_servers()

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        log("Test interrupted by user")
        cleanup_servers()
        sys.exit(1)
    except Exception as e:
        log(f"Test failed with exception: {e}")
        cleanup_servers()
        sys.exit(1) 