#!/usr/bin/env python3
"""
Enhanced Cross-Language Ocrypt Register/Recover Test Script (5x5 Matrix)

This script tests all 25 combinations of secret registration and recovery between C++, Go, Python, Rust, and JavaScript:

REGISTER -> RECOVER:
1.  C++ -> C++            6.  Go -> C++            11. Python -> C++        16. Rust -> C++          21. JavaScript -> C++
2.  C++ -> Go             7.  Go -> Go             12. Python -> Go         17. Rust -> Go           22. JavaScript -> Go
3.  C++ -> Python         8.  Go -> Python         13. Python -> Python     18. Rust -> Python       23. JavaScript -> Python
4.  C++ -> Rust           9.  Go -> Rust           14. Python -> Rust       19. Rust -> Rust         24. JavaScript -> Rust
5.  C++ -> JavaScript     10. Go -> JavaScript     15. Python -> JavaScript 20. Rust -> JavaScript   25. JavaScript -> JavaScript

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

# Add the project root to the path to import manage_test_servers
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from manage_test_servers import TestServerManager

# Test configuration
TEST_PASSWORD = "test_password_ocrypt_5x5"
TEST_USER_ID = "test_user_ocrypt_5x5"
TEST_APP_ID = "cross_lang_test_app"
TEST_SECRET = "Hello, OpenADP Ocrypt 5x5 Cross-Language Test! This tests all combinations of Go/Python/JavaScript/Rust/C++ register/recover compatibility for comprehensive interoperability validation."

# Server configuration for testing
SERVER_PORTS = [8080, 8081, 8082]  # Use multiple servers for comprehensive testing
SERVER_MANAGER = None
SERVERS_JSON_FILE = None

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
    """Start local Go OpenADP servers and generate servers.json for testing"""
    global SERVER_MANAGER, SERVERS_JSON_FILE
    
    log("Starting local OpenADP servers with TestServerManager...")
    
    # Clean up any existing servers
    cleanup_servers()
    
    # Create server manager
    SERVER_MANAGER = TestServerManager()
    
    # Launch servers
    num_servers = len(SERVER_PORTS)
    start_port = SERVER_PORTS[0]
    
    success = SERVER_MANAGER.launch_servers(num_servers, start_port, auth_enabled=True)
    if not success:
        log("❌ Failed to start servers")
        return False
    
    log("✅ Servers started successfully")
    
    # Generate servers.json with public keys
    log("📝 Generating servers.json with public keys...")
    try:
        SERVERS_JSON_FILE = SERVER_MANAGER.generate_servers_json()
        if SERVERS_JSON_FILE and os.path.exists(SERVERS_JSON_FILE):
            log(f"✅ Generated servers.json at {SERVERS_JSON_FILE}")
            
            # Log the contents for debugging
            with open(SERVERS_JSON_FILE, 'r') as f:
                servers_data = json.load(f)
                log(f"📋 Generated {len(servers_data.get('servers', []))} server entries")
                for i, server in enumerate(servers_data.get('servers', [])):
                    pub_key = server.get('public_key', '')
                    log(f"   Server {i+1}: {server['url']} (key: {pub_key[:16]}...)")
            
            return True
        else:
            log("❌ Failed to generate servers.json")
            return False
    except Exception as e:
        log(f"❌ Error generating servers.json: {e}")
        return False

def cleanup_servers():
    """Clean up server processes and temporary files"""
    global SERVER_MANAGER, SERVERS_JSON_FILE
    
    if SERVER_MANAGER:
        SERVER_MANAGER.teardown()
        SERVER_MANAGER = None
    
    # Clean up servers.json file
    if SERVERS_JSON_FILE and os.path.exists(SERVERS_JSON_FILE):
        try:
            os.remove(SERVERS_JSON_FILE)
            log(f"🧹 Cleaned up {SERVERS_JSON_FILE}")
        except:
            pass
    SERVERS_JSON_FILE = None

# Ocrypt doesn't need test files, it works with secrets directly

def run_go_register(secret=None):
    """Run Go ocrypt registration"""
    if secret is None:
        secret = TEST_SECRET
    
    if not SERVERS_JSON_FILE:
        return False, None, "No servers.json file available"
    
    cmd = [
        BUILD_PATH + "/ocrypt-register",
        "--user-id", TEST_USER_ID,
        "--app-id", TEST_APP_ID,
        "--long-term-secret", secret,
        "--password", TEST_PASSWORD,
        "--servers-url", f"file://{os.path.abspath(SERVERS_JSON_FILE)}"
    ]
    
    log(f"Running Go register with local servers.json")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Go register failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, None, result.stderr
    
    # Extract JSON from the output (it's at the end after all the user-friendly messages)
    try:
        lines = result.stdout.strip().split('\n')
        # Look for the JSON line (starts with '{' and ends with '}')
        json_line = None
        for line in lines:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                json_line = line
                break
        
        if json_line:
            metadata = json.loads(json_line)
            log("Go register succeeded")
            return True, metadata, None
        else:
            log("Go register succeeded but no JSON metadata found")
            log(f"Output: {result.stdout}")
            return False, None, "No JSON metadata found"
    except json.JSONDecodeError as e:
        log(f"Go register succeeded but metadata is invalid JSON: {e}")
        log(f"JSON line: {json_line}")
        return False, None, "Invalid JSON metadata"

def run_go_recover(metadata):
    """Run Go ocrypt recovery"""
    if not SERVERS_JSON_FILE:
        return False, None, "No servers.json file available"
    
    cmd = [
        BUILD_PATH + "/ocrypt-recover",
        "--metadata", json.dumps(metadata),
        "--password", TEST_PASSWORD,
        "--servers-url", f"file://{os.path.abspath(SERVERS_JSON_FILE)}"
    ]
    
    log(f"Running Go recover with local servers.json")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Go recover failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, None, result.stderr
    
    # Extract JSON from the output (it's at the end after all the user-friendly messages)
    try:
        lines = result.stdout.strip().split('\n')
        # Look for the JSON line (starts with '{' and ends with '}')
        json_line = None
        for line in lines:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                json_line = line
                break
        
        if json_line:
            recovery_result = json.loads(json_line)
            recovered_secret = recovery_result.get("secret", "")
            log("Go recover succeeded")
            return True, recovered_secret, None
        else:
            log("Go recover succeeded but no JSON result found")
            log(f"Output: {result.stdout}")
            return False, None, "No JSON result found"
    except json.JSONDecodeError as e:
        log(f"Go recover succeeded but result is invalid JSON: {e}")
        log(f"JSON line: {json_line}")
        return False, None, "Invalid JSON result"

def run_python_register(secret=None):
    """Run Python ocrypt registration"""
    if secret is None:
        secret = TEST_SECRET
    
    if not SERVERS_JSON_FILE:
        return False, None, "No servers.json file available"
    
    cmd = [
        "python3", SDK_PYTHON_PATH + "/ocrypt-register.py",
        "--user-id", TEST_USER_ID,
        "--app-id", TEST_APP_ID,
        "--long-term-secret", secret,
        "--password", TEST_PASSWORD,
        "--servers-url", f"file://{os.path.abspath(SERVERS_JSON_FILE)}"
    ]
    
    log(f"Running Python register with local servers.json")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Python register failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, None, result.stderr
    
    # Extract JSON from the output (it's at the end after all the user-friendly messages)
    try:
        lines = result.stdout.strip().split('\n')
        # Look for the JSON line (starts with '{' and ends with '}')
        json_line = None
        for line in lines:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                json_line = line
                break
        
        if json_line:
            metadata = json.loads(json_line)
            log("Python register succeeded")
            return True, metadata, None
        else:
            log("Python register succeeded but no JSON metadata found")
            log(f"Output: {result.stdout}")
            return False, None, "No JSON metadata found"
    except json.JSONDecodeError as e:
        log(f"Python register succeeded but metadata is invalid JSON: {e}")
        log(f"JSON line: {json_line}")
        return False, None, "Invalid JSON metadata"

def run_python_recover(metadata):
    """Run Python ocrypt recovery"""
    if not SERVERS_JSON_FILE:
        return False, None, "No servers.json file available"
    
    cmd = [
        "python3", SDK_PYTHON_PATH + "/ocrypt-recover.py",
        "--metadata", json.dumps(metadata),
        "--password", TEST_PASSWORD,
        "--servers-url", f"file://{os.path.abspath(SERVERS_JSON_FILE)}"
    ]
    
    log(f"Running Python recover with local servers.json")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Python recover failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, None, result.stderr
    
    # Extract JSON from the output (it's at the end after all the user-friendly messages)
    try:
        lines = result.stdout.strip().split('\n')
        # Look for the JSON line (starts with '{' and ends with '}')
        json_line = None
        for line in lines:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                json_line = line
                break
        
        if json_line:
            recovery_result = json.loads(json_line)
            recovered_secret = recovery_result.get("secret", "")
            log("Python recover succeeded")
            return True, recovered_secret, None
        else:
            log("Python recover succeeded but no JSON result found")
            log(f"Output: {result.stdout}")
            return False, None, "No JSON result found"
    except json.JSONDecodeError as e:
        log(f"Python recover succeeded but result is invalid JSON: {e}")
        log(f"JSON line: {json_line}")
        return False, None, "Invalid JSON result"

def run_javascript_register(secret=None):
    """Run JavaScript ocrypt registration"""
    if secret is None:
        secret = TEST_SECRET
    
    if not SERVERS_JSON_FILE:
        return False, None, "No servers.json file available"
    
    cmd = [
        "node", SDK_JAVASCRIPT_PATH + "/ocrypt-register.js",
        "--user-id", TEST_USER_ID,
        "--app-id", TEST_APP_ID,
        "--long-term-secret", secret,
        "--password", TEST_PASSWORD,
        "--servers-url", f"file://{os.path.abspath(SERVERS_JSON_FILE)}"
    ]
    
    log(f"Running JavaScript register with local servers.json")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"JavaScript register failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, None, result.stderr
    
    # Extract JSON from the output (it's at the end after all the user-friendly messages)
    try:
        lines = result.stdout.strip().split('\n')
        # Look for the JSON line (starts with '{' and ends with '}')
        json_line = None
        for line in lines:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                json_line = line
                break
        
        if json_line:
            metadata = json.loads(json_line)
            log("JavaScript register succeeded")
            return True, metadata, None
        else:
            log("JavaScript register succeeded but no JSON metadata found")
            log(f"Output: {result.stdout}")
            return False, None, "No JSON metadata found"
    except json.JSONDecodeError as e:
        log(f"JavaScript register succeeded but metadata is invalid JSON: {e}")
        log(f"JSON line: {json_line}")
        return False, None, "Invalid JSON metadata"

def run_javascript_recover(metadata):
    """Run JavaScript ocrypt recovery"""
    if not SERVERS_JSON_FILE:
        return False, None, "No servers.json file available"
    
    cmd = [
        "node", SDK_JAVASCRIPT_PATH + "/ocrypt-recover.js",
        "--metadata", json.dumps(metadata),
        "--password", TEST_PASSWORD,
        "--servers-url", f"file://{os.path.abspath(SERVERS_JSON_FILE)}"
    ]
    
    log(f"Running JavaScript recover with local servers.json")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"JavaScript recover failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, None, result.stderr
    
    # Extract JSON from the output (it's at the end after all the user-friendly messages)
    try:
        lines = result.stdout.strip().split('\n')
        # Look for the JSON line (starts with '{' and ends with '}')
        json_line = None
        for line in lines:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                json_line = line
                break
        
        if json_line:
            recovery_result = json.loads(json_line)
            recovered_secret = recovery_result.get("secret", "")
            log("JavaScript recover succeeded")
            return True, recovered_secret, None
        else:
            log("JavaScript recover succeeded but no JSON result found")
            log(f"Output: {result.stdout}")
            return False, None, "No JSON result found"
    except json.JSONDecodeError as e:
        log(f"JavaScript recover succeeded but result is invalid JSON: {e}")
        log(f"JSON line: {json_line}")
        return False, None, "Invalid JSON result"

def run_rust_register(secret=None):
    """Run Rust ocrypt registration"""
    if secret is None:
        secret = TEST_SECRET
    
    if not SERVERS_JSON_FILE:
        return False, None, "No servers.json file available"
    
    cmd = [
        SDK_RUST_PATH + "/target/release/ocrypt-register",  # Assuming Rust ocrypt tools follow similar naming
        "--user-id", TEST_USER_ID,
        "--app-id", TEST_APP_ID,
        "--long-term-secret", secret,
        "--password", TEST_PASSWORD,
        "--servers-url", f"file://{os.path.abspath(SERVERS_JSON_FILE)}"
    ]
    
    log(f"Running Rust register with local servers.json")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Rust register failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, None, result.stderr
    
    try:
        metadata = json.loads(result.stdout)
        log("Rust register succeeded")
        return True, metadata, None
    except json.JSONDecodeError as e:
        log(f"Rust register succeeded but metadata is invalid JSON: {e}")
        log(f"Output: {result.stdout}")
        return False, None, "Invalid JSON metadata"

def run_rust_recover(metadata):
    """Run Rust ocrypt recovery"""
    if not SERVERS_JSON_FILE:
        return False, None, "No servers.json file available"
    
    cmd = [
        SDK_RUST_PATH + "/target/release/ocrypt-recover",  # Assuming Rust ocrypt tools follow similar naming
        "--metadata", json.dumps(metadata),
        "--password", TEST_PASSWORD,
        "--servers-url", f"file://{os.path.abspath(SERVERS_JSON_FILE)}"
    ]
    
    log(f"Running Rust recover with local servers.json")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"Rust recover failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, None, result.stderr
    
    try:
        recovery_result = json.loads(result.stdout)
        recovered_secret = recovery_result.get("secret", "")
        log("Rust recover succeeded")
        return True, recovered_secret, None
    except json.JSONDecodeError as e:
        log(f"Rust recover succeeded but result is invalid JSON: {e}")
        log(f"Output: {result.stdout}")
        return False, None, "Invalid JSON result"

def verify_secret_content(recovered_secret, expected_secret):
    """Verify that recovered secret matches expected secret"""
    if recovered_secret == expected_secret:
        log(f"✅ Secret verification: MATCH")
        return True
    else:
        log(f"❌ Secret verification: MISMATCH")
        log(f"   Expected: {expected_secret[:50]}{'...' if len(expected_secret) > 50 else ''}")
        log(f"   Recovered: {recovered_secret[:50]}{'...' if len(recovered_secret) > 50 else ''}")
        return False

def run_test_case(test_name, register_func, recover_func):
    """Run a single test case: register with one tool, recover with another"""
    log(f"\n🧪 Running test case: {test_name}")
    
    # Step 1: Register secret
    log("1️⃣ Registering secret...")
    success, metadata, error = register_func(TEST_SECRET)
    
    if not success:
        log(f"❌ Registration failed: {error}")
        return False
    
    if not metadata:
        log("❌ Registration succeeded but no metadata returned")
        return False
    
    log(f"✅ Registration successful, metadata size: {len(json.dumps(metadata))} characters")
    
    # Step 2: Recover secret
    log("2️⃣ Recovering secret...")
    success, recovered_secret, error = recover_func(metadata)
    
    if not success:
        log(f"❌ Recovery failed: {error}")
        return False
    
    # Step 3: Verify content
    log("3️⃣ Verifying recovered secret...")
    if verify_secret_content(recovered_secret, TEST_SECRET):
        log(f"✅ Test case {test_name}: PASS")
        return True
    else:
        log(f"❌ Test case {test_name}: FAIL")
        return False

def verify_tools_exist():
    """Check which tools are available"""
    tools = {
        "Go register": BUILD_PATH + "/ocrypt-register",
        "Go recover": BUILD_PATH + "/ocrypt-recover",
        "Python register": SDK_PYTHON_PATH + "/ocrypt-register.py",
        "Python recover": SDK_PYTHON_PATH + "/ocrypt-recover.py",
        "JavaScript register": SDK_JAVASCRIPT_PATH + "/ocrypt-register.js",
        "JavaScript recover": SDK_JAVASCRIPT_PATH + "/ocrypt-recover.js",
        "Rust register": SDK_RUST_PATH + "/target/release/ocrypt-register",
        "Rust recover": SDK_RUST_PATH + "/target/release/ocrypt-recover",
        "C++ register": BUILD_PATH + "/ocrypt-register-cpp",  # Placeholder
        "C++ recover": BUILD_PATH + "/ocrypt-recover-cpp",  # Placeholder
    }
    
    available = set()
    
    for tool_name, tool_path in tools.items():
        if os.path.exists(tool_path):
            available.add(tool_name)
            log(f"✅ {tool_name}: Available at {tool_path}")
        else:
            log(f"❌ {tool_name}: Not found at {tool_path}")
    
    return available

def run_cpp_register(secret=None):
    """Run C++ ocrypt registration"""
    if secret is None:
        secret = TEST_SECRET
    
    if not SERVERS_JSON_FILE:
        return False, None, "No servers.json file available"
    
    cmd = [
        BUILD_PATH + "/ocrypt-register-cpp",  # Placeholder
        "--user-id", TEST_USER_ID,
        "--app-id", TEST_APP_ID,
        "--long-term-secret", secret,
        "--password", TEST_PASSWORD,
        "--servers-url", f"file://{os.path.abspath(SERVERS_JSON_FILE)}"
    ]
    
    log(f"Running C++ register with local servers.json")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"C++ register failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, None, result.stderr
    
    try:
        metadata = json.loads(result.stdout)
        log("C++ register succeeded")
        return True, metadata, None
    except json.JSONDecodeError as e:
        log(f"C++ register succeeded but metadata is invalid JSON: {e}")
        log(f"Output: {result.stdout}")
        return False, None, "Invalid JSON metadata"

def run_cpp_recover(metadata):
    """Run C++ ocrypt recovery"""
    if not SERVERS_JSON_FILE:
        return False, None, "No servers.json file available"
    
    cmd = [
        BUILD_PATH + "/ocrypt-recover-cpp",  # Placeholder
        "--metadata", json.dumps(metadata),
        "--password", TEST_PASSWORD,
        "--servers-url", f"file://{os.path.abspath(SERVERS_JSON_FILE)}"
    ]
    
    log(f"Running C++ recover with local servers.json")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        log(f"C++ recover failed:")
        log(f"STDOUT: {result.stdout}")
        log(f"STDERR: {result.stderr}")
        return False, None, result.stderr
    
    try:
        recovery_result = json.loads(result.stdout)
        recovered_secret = recovery_result.get("secret", "")
        log("C++ recover succeeded")
        return True, recovered_secret, None
    except json.JSONDecodeError as e:
        log(f"C++ recover succeeded but result is invalid JSON: {e}")
        log(f"Output: {result.stdout}")
        return False, None, "Invalid JSON result"

def can_run_test_case(test_name, register_func, recover_func, available_tools):
    """Check if a test case can be run based on available tools"""
    # Extract the language names from the test case name
    register_lang = test_name.split(" -> ")[0]
    recover_lang = test_name.split(" -> ")[1]
    
    register_tool = f"{register_lang} register"
    recover_tool = f"{recover_lang} recover"
    
    return register_tool in available_tools and recover_tool in available_tools

def main():
    """Main test function"""
    log("🚀 Starting Enhanced Cross-Language Ocrypt Test (5x5 Matrix)")
    log("=" * 70)
    
    # Verify available tools first
    log("🔍 Checking available tools...")
    available_tools = verify_tools_exist()
    
    if not available_tools:
        log("❌ No ocrypt tools available. Cannot run tests.")
        return False
    
    # Start local servers
    if not start_local_servers():
        log("❌ Failed to start test servers")
        return False
    
    # Define all test cases (5x5 matrix)
    test_functions = {
        "Go": (run_go_register, run_go_recover),
        "Python": (run_python_register, run_python_recover),
        "JavaScript": (run_javascript_register, run_javascript_recover),
        "Rust": (run_rust_register, run_rust_recover),
        "C++": (run_cpp_register, run_cpp_recover),
    }
    
    test_cases = []
    for register_lang, (register_func, _) in test_functions.items():
        for recover_lang, (_, recover_func) in test_functions.items():
            test_name = f"{register_lang} -> {recover_lang}"
            if can_run_test_case(test_name, register_func, recover_func, available_tools):
                test_cases.append((test_name, register_func, recover_func))
            else:
                log(f"⏭️  Skipping {test_name}: Missing tools")
    
    if not test_cases:
        log("❌ No test cases can be run. Missing required tools.")
        cleanup_servers()
        return False
    
    log(f"\n📋 Running {len(test_cases)} test cases...")
    
    # Run all test cases
    results = {}
    passed = 0
    failed = 0
    
    try:
        for test_name, register_func, recover_func in test_cases:
            if run_test_case(test_name, register_func, recover_func):
                results[test_name] = "PASS"
                passed += 1
            else:
                results[test_name] = "FAIL"
                failed += 1
    
    finally:
        # Always cleanup servers
        cleanup_servers()
    
    # Print summary
    log("\n" + "=" * 70)
    log("📊 TEST RESULTS SUMMARY")
    log("=" * 70)
    
    for test_name, result in results.items():
        status_icon = "✅" if result == "PASS" else "❌"
        log(f"{status_icon} {test_name}: {result}")
    
    log("=" * 70)
    log(f"📈 Total: {len(test_cases)} tests")
    log(f"✅ Passed: {passed}")
    log(f"❌ Failed: {failed}")
    
    if failed == 0:
        log("🎉 All cross-language ocrypt tests: PASS")
        return True
    else:
        log(f"💥 Cross-language ocrypt tests: {failed} FAILED")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 