#!/usr/bin/env python3
"""
Enhanced Cross-Language Encrypt/Decrypt Test Script (5×5 Matrix)

This script tests all 25 combinations of encryption and decryption between C++, Go, Python, Rust, and JavaScript:

ENCRYPT -> DECRYPT:
1.  C++ -> C++            6.  C++ -> Go            11. C++ -> Python         16. C++ -> Rust          21. C++ -> JavaScript
2.  Go -> C++             7.  Go -> Go             12. Go -> Python          17. Go -> Rust           22. Go -> JavaScript  
3.  Python -> C++         8.  Python -> Go         13. Python -> Python      18. Python -> Rust       23. Python -> JavaScript
4.  Rust -> C++           9.  Rust -> Go           14. Rust -> Python        19. Rust -> Rust         24. Rust -> JavaScript
5.  JavaScript -> C++     10. JavaScript -> Go     15. JavaScript -> Python  20. JavaScript -> Rust   25. JavaScript -> JavaScript

It runs local Go OpenADP servers once for all tests to ensure optimal performance.
Tools that are not available will be gracefully skipped with clear reporting.
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
TEST_PASSWORD = "test_password_25x25"
TEST_USER_ID = "test_user_25x25_cross_lang"
TEST_CONTENT = b"Hello, OpenADP 25x25 Cross-Language Test! This tests all combinations of C++/Go/Python/JavaScript/Rust encrypt/decrypt compatibility for comprehensive interoperability validation across all five language implementations."

# Server configuration for testing
SERVER_PORTS = [8080, 8081, 8082]  # Use multiple servers for comprehensive testing
SERVER_PROCESSES = []
SERVER_URLS = [f"http://localhost:{port}" for port in SERVER_PORTS]

# Detect if we're running from cross-language directory or project root
if os.path.basename(os.getcwd()) == "cross-language":
    # Running from tests/cross-language directory
    SDK_PYTHON_PATH = "../../sdk/python"
    SDK_JAVASCRIPT_PATH = "../../sdk/javascript"
    SDK_CPP_PATH = "../../sdk/cpp"
    SDK_RUST_PATH = "../../sdk/rust"
    BUILD_PATH = "../../build"
else:
    # Running from project root
    SDK_PYTHON_PATH = "sdk/python"
    SDK_JAVASCRIPT_PATH = "sdk/javascript"
    SDK_CPP_PATH = "sdk/cpp"
    SDK_RUST_PATH = "sdk/rust"
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
        
        # Start server process using built executable with Noise-NK encryption
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
        BUILD_PATH + "/openadp-encrypt",
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
        BUILD_PATH + "/openadp-decrypt",
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
        output_file = input_file.replace(".enc", "")
    
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
        "node", SDK_JAVASCRIPT_PATH + "/openadp-encrypt.js",
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
        "node", SDK_JAVASCRIPT_PATH + "/openadp-decrypt.js",
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
        SDK_RUST_PATH + "/target/release/openadp-encrypt",
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
        SDK_RUST_PATH + "/target/release/openadp-decrypt",
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

def verify_tools_exist():
    """Verify all required tools exist"""
    tools = {
        "C++ encrypt": SDK_CPP_PATH + "/build/openadp-encrypt",
        "C++ decrypt": SDK_CPP_PATH + "/build/openadp-decrypt", 
        "Go encrypt": BUILD_PATH + "/openadp-encrypt",
        "Go decrypt": BUILD_PATH + "/openadp-decrypt",
        "Python encrypt": SDK_PYTHON_PATH + "/openadp-encrypt.py",
        "Python decrypt": SDK_PYTHON_PATH + "/openadp-decrypt.py",
        "JavaScript encrypt": SDK_JAVASCRIPT_PATH + "/openadp-encrypt.js",
        "JavaScript decrypt": SDK_JAVASCRIPT_PATH + "/openadp-decrypt.js",
        "Rust encrypt": SDK_RUST_PATH + "/target/release/openadp-encrypt",
        "Rust decrypt": SDK_RUST_PATH + "/target/release/openadp-decrypt"
    }
    
    missing_tools = []
    available_tools = []
    
    for name, path in tools.items():
        if os.path.exists(path):
            log(f"✅ {name}: {path}")
            available_tools.append(name)
        else:
            log(f"❌ {name}: {path} (not found)")
            missing_tools.append(name)
    
    if missing_tools:
        log(f"⚠️  Missing tools: {', '.join(missing_tools)}")
        log("Some test combinations will be skipped.")
    
    return len(missing_tools) == 0, available_tools, missing_tools

def run_cpp_encrypt(input_file, output_file=None):
    """Run C++ encryption using the standardized interface"""
    if output_file is None:
        output_file = input_file + ".enc"
    
    cmd = [
        SDK_CPP_PATH + "/build/openadp-encrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running C++ encrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"C++ encrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr
    
    if not os.path.exists(output_file):
        log(f"C++ encrypt didn't create output file: {output_file}")
        return False, "Output file not created"
    
    log("C++ encrypt succeeded")
    return True, None

def run_cpp_decrypt(input_file, output_file=None):
    """Run C++ decryption using the standardized interface"""
    if output_file is None:
        # C++ decrypt tool strips .enc extension by default
        output_file = input_file.replace(".enc", "")
    
    cmd = [
        SDK_CPP_PATH + "/build/openadp-decrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS)
    ]
    
    log(f"Running C++ decrypt: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"C++ decrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr
    
    # Check if output file exists
    if os.path.exists(output_file):
        log("C++ decrypt succeeded")
        return True, None
    else:
        log(f"C++ decrypt didn't create output file: {output_file}")
        return False, "Output file not created"

def can_run_test_case(test_name, encrypt_func, decrypt_func, available_tools):
    """Check if a test case can run based on available tools"""
    tool_mapping = {
        run_cpp_encrypt: "C++ encrypt",
        run_cpp_decrypt: "C++ decrypt",
        run_go_encrypt: "Go encrypt", 
        run_go_decrypt: "Go decrypt",
        run_python_encrypt: "Python encrypt",
        run_python_decrypt: "Python decrypt",
        run_javascript_encrypt: "JavaScript encrypt",
        run_javascript_decrypt: "JavaScript decrypt",
        run_rust_encrypt: "Rust encrypt",
        run_rust_decrypt: "Rust decrypt"
    }
    
    encrypt_tool = tool_mapping.get(encrypt_func)
    decrypt_tool = tool_mapping.get(decrypt_func)
    
    missing = []
    if encrypt_tool and encrypt_tool not in available_tools:
        missing.append(encrypt_tool)
    if decrypt_tool and decrypt_tool not in available_tools:
        missing.append(decrypt_tool)
    
    return len(missing) == 0, missing

def main():
    """Main test function"""
    log("🚀 Starting Enhanced Cross-Language Test (5×5 Matrix)")
    log(f"Test content length: {len(TEST_CONTENT)} bytes")
    log(f"Test password: {TEST_PASSWORD}")
    log(f"Test user ID: {TEST_USER_ID}")
    
    # Verify tools exist
    all_tools_available, available_tools, missing_tools = verify_tools_exist()
    
    if not all_tools_available:
        log(f"⚠️  Some tools are missing. Tests will be skipped for missing tools.")
    
    # Start servers
    if not start_local_servers():
        log("❌ Failed to start servers")
        return False
    
    try:
        # Define 25 test combinations (5×5 matrix: C++, Go, Python, JavaScript, Rust)
        test_cases = [
            # C++ encrypt -> *
            ("1.  C++ -> C++", run_cpp_encrypt, run_cpp_decrypt),
            ("2.  C++ -> Go", run_cpp_encrypt, run_go_decrypt),
            ("3.  C++ -> Python", run_cpp_encrypt, run_python_decrypt),
            ("4.  C++ -> JavaScript", run_cpp_encrypt, run_javascript_decrypt),
            ("5.  C++ -> Rust", run_cpp_encrypt, run_rust_decrypt),
            
            # Go encrypt -> *
            ("6.  Go -> C++", run_go_encrypt, run_cpp_decrypt),
            ("7.  Go -> Go", run_go_encrypt, run_go_decrypt),
            ("8.  Go -> Python", run_go_encrypt, run_python_decrypt),
            ("9.  Go -> JavaScript", run_go_encrypt, run_javascript_decrypt),
            ("10. Go -> Rust", run_go_encrypt, run_rust_decrypt),
            
            # Python encrypt -> *
            ("11. Python -> C++", run_python_encrypt, run_cpp_decrypt),
            ("12. Python -> Go", run_python_encrypt, run_go_decrypt),
            ("13. Python -> Python", run_python_encrypt, run_python_decrypt),
            ("14. Python -> JavaScript", run_python_encrypt, run_javascript_decrypt),
            ("15. Python -> Rust", run_python_encrypt, run_rust_decrypt),
            
            # JavaScript encrypt -> *
            ("16. JavaScript -> C++", run_javascript_encrypt, run_cpp_decrypt),
            ("17. JavaScript -> Go", run_javascript_encrypt, run_go_decrypt),
            ("18. JavaScript -> Python", run_javascript_encrypt, run_python_decrypt),
            ("19. JavaScript -> JavaScript", run_javascript_encrypt, run_javascript_decrypt),
            ("20. JavaScript -> Rust", run_javascript_encrypt, run_rust_decrypt),
            
            # Rust encrypt -> *
            ("21. Rust -> C++", run_rust_encrypt, run_cpp_decrypt),
            ("22. Rust -> Go", run_rust_encrypt, run_go_decrypt),
            ("23. Rust -> Python", run_rust_encrypt, run_python_decrypt),
            ("24. Rust -> JavaScript", run_rust_encrypt, run_javascript_decrypt),
            ("25. Rust -> Rust", run_rust_encrypt, run_rust_decrypt),
        ]
        
        # Run all test cases
        results = []
        for test_name, encrypt_func, decrypt_func in test_cases:
            can_run, missing_tools = can_run_test_case(test_name, encrypt_func, decrypt_func, available_tools)
            if not can_run:
                log(f"⚠️  Test skipped: {test_name} (missing tools: {', '.join(missing_tools)})")
                results.append((test_name, None))
            else:
                success = run_test_case(test_name, encrypt_func, decrypt_func)
                results.append((test_name, success))
            
            # Brief pause between tests
            time.sleep(1)
        
        # Summary
        log(f"\n{'='*60}")
        log(f"📊 TEST SUMMARY")
        log(f"{'='*60}")
        
        passed_tests = []
        failed_tests = []
        skipped_tests = []
        
        for test_name, success in results:
            if success is None:  # Skipped
                skipped_tests.append(test_name)
            elif success:
                passed_tests.append(test_name)
                log(f"✅ PASS {test_name}")
            else:
                failed_tests.append(test_name)
                log(f"❌ FAIL {test_name}")
        
        log(f"\n📈 Results: {len(passed_tests)} passed, {len(failed_tests)} failed, {len(skipped_tests)} skipped out of {len(test_cases)} tests")
        
        if skipped_tests:
            log(f"⚠️  Skipped tests: {len(skipped_tests)}")
            for test_name in skipped_tests:
                log(f"   - {test_name}")
        
        if len(failed_tests) == 0 and len(skipped_tests) == 0:
            log("🎉 ALL TESTS PASSED! Complete cross-language compatibility confirmed across all 5 languages!")
            return True
        elif len(failed_tests) == 0:
            log("🎉 ALL AVAILABLE TESTS PASSED! Build missing tools to test remaining combinations.")
            return True
        else:
            log(f"💥 {len(failed_tests)} tests failed.")
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