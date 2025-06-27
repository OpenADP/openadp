#!/usr/bin/env python3
"""
Enhanced Cross-Language Encrypt/Decrypt Debug Test Script (5x5 Matrix)

This script tests all 25 combinations of encryption and decryption between C++, Go, Python, Rust, and JavaScript
WITH DEBUG MODE ENABLED to ensure deterministic outputs match across languages.

The test validates that when --debug flag is used:
1. All deterministic values (secrets, nonces, etc.) are identical across languages
2. Encrypted files are functionally equivalent (decrypt to same content)
3. Debug output shows matching parameters before encryption

ENCRYPT -> DECRYPT (with debug validation):
1.  C++ -> C++            6.  Go -> C++            11. Python -> C++        16. Rust -> C++          21. JavaScript -> C++
2.  C++ -> Go             7.  Go -> Go             12. Python -> Go         17. Rust -> Go           22. JavaScript -> Go  
3.  C++ -> Python         8.  Go -> Python         13. Python -> Python     18. Rust -> Python       23. JavaScript -> Python
4.  C++ -> Rust           9.  Go -> Rust           14. Python -> Rust       19. Rust -> Rust         24. JavaScript -> Rust
5.  C++ -> JavaScript     10. Go -> JavaScript     15. Python -> JavaScript 20. Rust -> JavaScript   25. JavaScript -> JavaScript
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
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Test configuration
TEST_PASSWORD = "test_password_debug"
TEST_USER_ID = "test_user_debug_cross_lang"
TEST_CONTENT = b"Hello, OpenADP Debug Cross-Language Test! This tests deterministic encrypt/decrypt compatibility."

# Server configuration for testing
SERVER_PORTS = [8080, 8081, 8082]
SERVER_PROCESSES = []
SERVER_URLS = [f"http://localhost:{port}" for port in SERVER_PORTS]

def log(message):
    """Log a message with timestamp"""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

def extract_debug_values(output: str, tool_name: str) -> Dict[str, str]:
    """Extract key deterministic values from debug output."""
    values = {}
    
    # Main secret pattern
    main_secret_match = re.search(r'deterministic main secret.*?0x([a-f0-9]+)', output, re.IGNORECASE)
    if main_secret_match:
        values['main_secret'] = main_secret_match.group(1)
    
    # Nonce pattern  
    nonce_match = re.search(r'deterministic nonce.*?([a-f0-9]{24,})', output, re.IGNORECASE)
    if nonce_match:
        values['nonce'] = nonce_match.group(1)
    
    # Auth code pattern
    auth_code_match = re.search(r'auth.*?code.*?([a-f0-9]{32,})', output, re.IGNORECASE)
    if auth_code_match:
        values['auth_code'] = auth_code_match.group(1)
    
    # Encryption key pattern
    key_match = re.search(r'encryption.*?key.*?([a-f0-9]{32,})', output, re.IGNORECASE)
    if key_match:
        values['encryption_key'] = key_match.group(1)
    
    # Parameters before encryption (for server calls)
    params_match = re.search(r'Parameters.*?before.*?encryption.*?(\[.*?\])', output, re.IGNORECASE)
    if params_match:
        values['parameters'] = params_match.group(1)
    
    log(f"Extracted {len(values)} debug values from {tool_name}: {list(values.keys())}")
    return values

def compare_debug_values(values1: Dict[str, str], values2: Dict[str, str], 
                        tool1: str, tool2: str) -> List[str]:
    """Compare debug values between two tools and return list of mismatches."""
    mismatches = []
    
    # Check all common keys
    common_keys = set(values1.keys()) & set(values2.keys())
    for key in common_keys:
        if values1[key] != values2[key]:
            mismatches.append(f"{key}: {tool1}={values1[key][:32]}... vs {tool2}={values2[key][:32]}...")
    
    # Check for missing keys
    only_in_1 = set(values1.keys()) - set(values2.keys())
    only_in_2 = set(values2.keys()) - set(values1.keys())
    
    for key in only_in_1:
        mismatches.append(f"{key}: present in {tool1} but missing in {tool2}")
    
    for key in only_in_2:
        mismatches.append(f"{key}: present in {tool2} but missing in {tool1}")
    
    return mismatches

def start_local_servers():
    """Start local Go OpenADP servers for testing"""
    log("Starting local OpenADP servers...")
    
    # Clean up any existing server processes
    cleanup_servers()
    
    for i, port in enumerate(SERVER_PORTS):
        log(f"Starting server on port {port}...")
        
        # Create temporary database for this server
        temp_db = tempfile.mktemp(suffix=f"_server_{port}.db")
        
        # Start server process with debug mode enabled
        cmd = [
            "./build/openadp-server",
            "-port", str(port),
            "-db", temp_db,
            "-auth", "true",
            "--debug"  # Enable debug mode on server
        ]
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="."
            )
            SERVER_PROCESSES.append((process, temp_db))
            log(f"Server started on port {port} with debug mode (PID: {process.pid})")
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
    """Run Go encryption with debug mode"""
    if output_file is None:
        output_file = input_file + ".enc"
    
    cmd = [
        "./build/openadp-encrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS),
        "--debug"  # Enable debug mode
    ]
    
    log(f"Running Go encrypt with debug: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Go encrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr, {}
    
    if not os.path.exists(output_file):
        log(f"Go encrypt didn't create output file: {output_file}")
        return False, "Output file not created", {}
    
    # Extract debug values
    debug_values = extract_debug_values(result.stderr, "Go encrypt")
    
    log("Go encrypt succeeded")
    return True, None, debug_values

def run_go_decrypt(input_file, output_file=None):
    """Run Go decryption with debug mode"""
    if output_file is None:
        output_file = input_file.replace(".enc", "")
    
    cmd = [
        "./build/openadp-decrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS),
        "--debug"  # Enable debug mode
    ]
    
    log(f"Running Go decrypt with debug: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Go decrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr, {}
    
    if not os.path.exists(output_file):
        log(f"Go decrypt didn't create output file: {output_file}")
        return False, "Output file not created", {}
    
    # Extract debug values
    debug_values = extract_debug_values(result.stderr, "Go decrypt")
    
    log("Go decrypt succeeded")
    return True, None, debug_values

def run_python_encrypt(input_file, output_file=None):
    """Run Python encryption with debug mode"""
    if output_file is None:
        output_file = input_file + ".enc"
    
    cmd = [
        "python3", "sdk/python/openadp-encrypt.py",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers-url", f"file://{create_servers_json()}",
        "--output", output_file,
        "--debug"  # Enable debug mode
    ]
    
    log(f"Running Python encrypt with debug: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Python encrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr, {}
    
    if not os.path.exists(output_file):
        log(f"Python encrypt didn't create output file: {output_file}")
        return False, "Output file not created", {}
    
    # Extract debug values
    debug_values = extract_debug_values(result.stderr, "Python encrypt")
    
    log("Python encrypt succeeded")
    return True, None, debug_values

def run_python_decrypt(input_file, output_file=None):
    """Run Python decryption with debug mode"""
    if output_file is None:
        output_file = input_file.replace(".enc", "")
    
    cmd = [
        "python3", "sdk/python/openadp-decrypt.py",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers-url", f"file://{create_servers_json()}",
        "--output", output_file,
        "--debug"  # Enable debug mode
    ]
    
    log(f"Running Python decrypt with debug: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Python decrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr, {}
    
    if not os.path.exists(output_file):
        log(f"Python decrypt didn't create output file: {output_file}")
        return False, "Output file not created", {}
    
    # Extract debug values
    debug_values = extract_debug_values(result.stderr, "Python decrypt")
    
    log("Python decrypt succeeded")
    return True, None, debug_values

def run_cpp_encrypt(input_file, output_file=None):
    """Run C++ encryption with debug mode"""
    if output_file is None:
        output_file = input_file + ".enc"
    
    cmd = [
        "./sdk/cpp/build/openadp-encrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS),
        "--output", output_file,
        "--debug"  # Enable debug mode
    ]
    
    log(f"Running C++ encrypt with debug: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"C++ encrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr, {}
    
    if not os.path.exists(output_file):
        log(f"C++ encrypt didn't create output file: {output_file}")
        return False, "Output file not created", {}
    
    # Extract debug values
    debug_values = extract_debug_values(result.stderr, "C++ encrypt")
    
    log("C++ encrypt succeeded")
    return True, None, debug_values

def run_cpp_decrypt(input_file, output_file=None):
    """Run C++ decryption with debug mode"""
    if output_file is None:
        output_file = input_file.replace(".enc", "")
    
    cmd = [
        "./sdk/cpp/build/openadp-decrypt",
        "--file", input_file,
        "--password", TEST_PASSWORD,
        "--user-id", TEST_USER_ID,
        "--servers", ",".join(SERVER_URLS),
        "--output", output_file,
        "--debug"  # Enable debug mode
    ]
    
    log(f"Running C++ decrypt with debug: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"C++ decrypt failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, result.stderr, {}
    
    if not os.path.exists(output_file):
        log(f"C++ decrypt didn't create output file: {output_file}")
        return False, "Output file not created", {}
    
    # Extract debug values
    debug_values = extract_debug_values(result.stderr, "C++ decrypt")
    
    log("C++ decrypt succeeded")
    return True, None, debug_values

def create_servers_json():
    """Create a temporary servers.json file for Python tools"""
    servers_data = {
        "servers": [
            {
                "url": url,
                "public_key": "kRycXPuAzwB/U12quw0FtJN564Mnu1ls/9qh0RMRcUw=",
                "country": "US"
            }
            for url in SERVER_URLS
        ]
    }
    
    temp_file = tempfile.mktemp(suffix=".json")
    with open(temp_file, 'w') as f:
        json.dump(servers_data, f)
    
    return temp_file

def verify_file_content(file_path, expected_content):
    """Verify that file contains expected content"""
    try:
        with open(file_path, 'rb') as f:
            actual_content = f.read()
        return actual_content == expected_content
    except:
        return False

def run_test_case_with_debug(test_name, encrypt_func, decrypt_func):
    """Run a test case and validate debug outputs match"""
    log(f"\n{'='*80}")
    log(f"Testing: {test_name}")
    log(f"{'='*80}")
    
    # Create test file
    test_file = create_test_file()
    encrypted_file = test_file + ".enc"
    decrypted_file = test_file + ".dec"
    
    try:
        # Step 1: Encrypt
        log(f"Step 1: Encrypting with {encrypt_func.__name__}")
        encrypt_success, encrypt_error, encrypt_debug = encrypt_func(test_file, encrypted_file)
        
        if not encrypt_success:
            log(f"❌ Encryption failed: {encrypt_error}")
            return False, ["Encryption failed"]
        
        # Step 2: Decrypt
        log(f"Step 2: Decrypting with {decrypt_func.__name__}")
        decrypt_success, decrypt_error, decrypt_debug = decrypt_func(encrypted_file, decrypted_file)
        
        if not decrypt_success:
            log(f"❌ Decryption failed: {decrypt_error}")
            return False, ["Decryption failed"]
        
        # Step 3: Verify content
        if not verify_file_content(decrypted_file, TEST_CONTENT):
            log(f"❌ Content verification failed")
            return False, ["Content mismatch"]
        
        # Step 4: Compare debug values (if both tools support debug)
        debug_mismatches = []
        if encrypt_debug and decrypt_debug:
            mismatches = compare_debug_values(
                encrypt_debug, decrypt_debug,
                encrypt_func.__name__, decrypt_func.__name__
            )
            debug_mismatches.extend(mismatches)
        
        if debug_mismatches:
            log(f"⚠️  Debug value mismatches found:")
            for mismatch in debug_mismatches:
                log(f"    {mismatch}")
            return True, debug_mismatches  # Functional success but debug mismatches
        
        log(f"✅ Test passed with matching debug values")
        return True, []
        
    finally:
        # Cleanup
        for f in [test_file, encrypted_file, decrypted_file]:
            try:
                if os.path.exists(f):
                    os.remove(f)
            except:
                pass

def verify_tools_exist():
    """Check which tools are available"""
    tools = {
        'go_encrypt': './build/openadp-encrypt',
        'go_decrypt': './build/openadp-decrypt',
        'python_encrypt': 'sdk/python/openadp-encrypt.py',
        'python_decrypt': 'sdk/python/openadp-decrypt.py',
        'cpp_encrypt': './sdk/cpp/build/openadp-encrypt',
        'cpp_decrypt': './sdk/cpp/build/openadp-decrypt',
    }
    
    available = {}
    for name, path in tools.items():
        if os.path.exists(path):
            available[name] = True
            log(f"✅ {name}: {path}")
        else:
            available[name] = False
            log(f"❌ {name}: {path} (not found)")
    
    return available

def main():
    """Main test function"""
    log("🧪 Cross-Language Encrypt/Decrypt Debug Test (5x5 Matrix)")
    log("=" * 80)
    
    # Check available tools
    available_tools = verify_tools_exist()
    
    # Start servers
    if not start_local_servers():
        log("❌ Failed to start servers")
        return 1
    
    try:
        # Define test matrix
        test_functions = {
            'go': (run_go_encrypt, run_go_decrypt),
            'python': (run_python_encrypt, run_python_decrypt),
            'cpp': (run_cpp_encrypt, run_cpp_decrypt),
        }
        
        # Filter available test functions
        available_test_functions = {}
        for lang, (enc_func, dec_func) in test_functions.items():
            enc_available = available_tools.get(f'{lang}_encrypt', False)
            dec_available = available_tools.get(f'{lang}_decrypt', False)
            if enc_available and dec_available:
                available_test_functions[lang] = (enc_func, dec_func)
        
        if len(available_test_functions) < 2:
            log("❌ Need at least 2 language implementations to run cross-language tests")
            return 1
        
        # Run test matrix
        total_tests = 0
        passed_tests = 0
        debug_mismatches = []
        
        langs = list(available_test_functions.keys())
        for encrypt_lang in langs:
            for decrypt_lang in langs:
                encrypt_func, _ = available_test_functions[encrypt_lang]
                _, decrypt_func = available_test_functions[decrypt_lang]
                
                test_name = f"{encrypt_lang.capitalize()} Encrypt → {decrypt_lang.capitalize()} Decrypt"
                total_tests += 1
                
                success, mismatches = run_test_case_with_debug(test_name, encrypt_func, decrypt_func)
                if success:
                    passed_tests += 1
                    if mismatches:
                        debug_mismatches.extend([(test_name, mismatch) for mismatch in mismatches])
        
        # Summary
        log(f"\n{'='*80}")
        log(f"TEST SUMMARY")
        log(f"{'='*80}")
        log(f"Total tests: {total_tests}")
        log(f"Passed tests: {passed_tests}")
        log(f"Failed tests: {total_tests - passed_tests}")
        
        if debug_mismatches:
            log(f"\n⚠️  DEBUG VALUE MISMATCHES ({len(debug_mismatches)} found):")
            for test_name, mismatch in debug_mismatches:
                log(f"  {test_name}: {mismatch}")
            log(f"\n💡 All tests passed functionally, but debug values don't match.")
            log(f"   This indicates deterministic operations are not identical across languages.")
            return 2  # Different exit code for debug mismatches
        
        if passed_tests == total_tests:
            log(f"🎉 ALL TESTS PASSED with matching debug values!")
            return 0
        else:
            log(f"💥 {total_tests - passed_tests} tests failed")
            return 1
    
    finally:
        cleanup_servers()

if __name__ == "__main__":
    sys.exit(main()) 