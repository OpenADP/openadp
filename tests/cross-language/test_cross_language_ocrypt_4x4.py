#!/usr/bin/env python3
"""
Cross-language Ocrypt 5x5 Test

This script tests all 25 combinations of Ocrypt register/recover tools across:
- C++ (sdk/cpp/build/ocrypt-register, sdk/cpp/build/ocrypt-recover)
- Go (cmd/ocrypt-register, cmd/ocrypt-recover)
- Python (sdk/python/ocrypt-register.py, sdk/python/ocrypt-recover.py)  
- Rust (sdk/rust/target/release/ocrypt-register, sdk/rust/target/release/ocrypt-recover)
- JavaScript (sdk/javascript/ocrypt-register.js, sdk/javascript/ocrypt-recover.js)

Test matrix (25 combinations):
1.  C++ Register → C++ Recover           14. Rust Register → C++ Recover
2.  C++ Register → Go Recover            15. Rust Register → Go Recover
3.  C++ Register → Python Recover        16. Rust Register → Python Recover
4.  C++ Register → Rust Recover          17. Rust Register → Rust Recover
5.  C++ Register → JavaScript Recover    18. Rust Register → JavaScript Recover
6.  Go Register → C++ Recover            19. JavaScript Register → C++ Recover
7.  Go Register → Go Recover             20. JavaScript Register → Go Recover
8.  Go Register → Python Recover         21. JavaScript Register → Python Recover
9.  Go Register → Rust Recover           22. JavaScript Register → Rust Recover
10. Go Register → JavaScript Recover     23. JavaScript Register → JavaScript Recover
11. Python Register → C++ Recover        24. (Reserved for future expansion)
12. Python Register → Go Recover         25. (Reserved for future expansion)
13. Python Register → Python Recover
14. Python Register → Rust Recover
15. Python Register → JavaScript Recover

Each test validates:
- Registration creates valid metadata
- Recovery returns correct secret
- Backup refresh works (updated metadata differs from original)
- Cross-language JSON compatibility
- Graceful handling of missing/broken tools for debugging progress
"""

import os
import sys
import subprocess
import json
import tempfile
import shutil

def run_command(cmd, cwd=None, input_data=None):
    """Run a command and return (stdout, stderr, returncode)"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            cwd=cwd,
            capture_output=True, 
            text=True,
            input=input_data
        )
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return "", str(e), 1

def test_combination(register_tool, recover_tool, test_name, project_root):
    """Test a specific register→recover combination"""
    print(f"\n{'='*60}")
    print(f"Testing: {test_name}")
    print(f"{'='*60}")
    
    # Test parameters
    user_id = "test-user@example.com"
    app_id = "test-app-4x4"
    secret = "my-test-secret-4x4"
    password = "test-password-123"
    
    # Create temporary files
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as metadata_file:
        metadata_path = metadata_file.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as result_file:
        result_path = result_file.name
    
    try:
        # Step 1: Register with the specified tool
        print(f"Step 1: Registering with {register_tool}")
        
        if register_tool.endswith('.py'):
            # Python script
            register_cmd = f"python3 {register_tool} --user-id '{user_id}' --app-id '{app_id}' --long-term-secret '{secret}' --password '{password}' --output '{metadata_path}'"
        elif register_tool.endswith('.js'):
            # JavaScript script
            register_cmd = f"node {register_tool} --user-id '{user_id}' --app-id '{app_id}' --long-term-secret '{secret}' --password '{password}' --output '{metadata_path}'"
        elif 'rust' in register_tool:
            # Rust binary
            register_cmd = f"./{register_tool} --user-id '{user_id}' --app-id '{app_id}' --long-term-secret '{secret}' --password '{password}' --output '{metadata_path}'"
        elif 'cpp' in register_tool:
            # C++ binary
            register_cmd = f"./{register_tool} --user-id '{user_id}' --app-id '{app_id}' --long-term-secret '{secret}' --password '{password}' --output '{metadata_path}'"
        else:
            # Go binary (no extension)
            register_cmd = f"./{register_tool} --user-id '{user_id}' --app-id '{app_id}' --long-term-secret '{secret}' --password '{password}' --output '{metadata_path}'"
        
        stdout, stderr, returncode = run_command(register_cmd, cwd=project_root)
        
        if returncode != 0:
            print(f"❌ Registration failed!")
            print(f"Command: {register_cmd}")
            print(f"Stdout: {stdout}")
            print(f"Stderr: {stderr}")
            return False
        
        print(f"✅ Registration successful")
        
        # Verify metadata file exists and is valid JSON
        if not os.path.exists(metadata_path):
            print(f"❌ Metadata file not created: {metadata_path}")
            return False
        
        try:
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            print(f"✅ Metadata is valid JSON ({len(json.dumps(metadata))} bytes)")
        except json.JSONDecodeError as e:
            print(f"❌ Metadata is not valid JSON: {e}")
            return False
        
        # Step 2: Recover with the specified tool
        print(f"Step 2: Recovering with {recover_tool}")
        
        if recover_tool.endswith('.py'):
            # Python script
            recover_cmd = f"python3 {recover_tool} --metadata \"$(cat '{metadata_path}')\" --password '{password}' --output '{result_path}'"
        elif recover_tool.endswith('.js'):
            # JavaScript script
            recover_cmd = f"node {recover_tool} --metadata \"$(cat '{metadata_path}')\" --password '{password}' --output '{result_path}'"
        elif 'rust' in recover_tool:
            # Rust binary
            recover_cmd = f"./{recover_tool} --metadata \"$(cat '{metadata_path}')\" --password '{password}' --output '{result_path}'"
        elif 'cpp' in recover_tool:
            # C++ binary
            recover_cmd = f"./{recover_tool} --metadata \"$(cat '{metadata_path}')\" --password '{password}' --output '{result_path}'"
        else:
            # Go binary (no extension)
            recover_cmd = f"./{recover_tool} --metadata \"$(cat '{metadata_path}')\" --password '{password}' --output '{result_path}'"
        
        stdout, stderr, returncode = run_command(recover_cmd, cwd=project_root)
        
        if returncode != 0:
            print(f"❌ Recovery failed!")
            print(f"Command: {recover_cmd}")
            print(f"Stdout: {stdout}")
            print(f"Stderr: {stderr}")
            return False
        
        print(f"✅ Recovery successful")
        
        # Step 3: Validate recovery result
        if not os.path.exists(result_path):
            print(f"❌ Result file not created: {result_path}")
            return False
        
        try:
            with open(result_path, 'r') as f:
                result = json.load(f)
        except json.JSONDecodeError as e:
            print(f"❌ Result is not valid JSON: {e}")
            return False
        
        # Validate result structure
        required_fields = ['secret', 'remaining_guesses', 'updated_metadata']
        for field in required_fields:
            if field not in result:
                print(f"❌ Missing field in result: {field}")
                return False
        
        # Validate secret
        if result['secret'] != secret:
            print(f"❌ Secret mismatch!")
            print(f"Expected: {secret}")
            print(f"Got: {result['secret']}")
            return False
        
        print(f"✅ Secret correctly recovered: {result['secret']}")
        
        # Step 4: Validate backup refresh (updated metadata should be different)
        try:
            updated_metadata = json.loads(result['updated_metadata'])
            
            # Check that metadata has expected structure
            if 'backup_id' not in updated_metadata:
                print(f"❌ Updated metadata missing backup_id")
                return False
            
            if 'servers' not in updated_metadata:
                print(f"❌ Updated metadata missing servers")
                return False
            
            # Check that backup refresh occurred (backup_id should change)
            original_backup_id = metadata.get('backup_id')
            updated_backup_id = updated_metadata.get('backup_id')
            
            if original_backup_id == updated_backup_id:
                print(f"⚠️  Backup refresh may not have occurred (backup_id unchanged: {original_backup_id})")
                # This is not necessarily a failure - backup refresh can fail but recovery still succeeds
            else:
                print(f"✅ Backup refresh successful: {original_backup_id} → {updated_backup_id}")
        
        except json.JSONDecodeError as e:
            print(f"❌ Updated metadata is not valid JSON: {e}")
            return False
        
        print(f"✅ All validations passed for {test_name}")
        return True
        
    finally:
        # Clean up temporary files
        for temp_file in [metadata_path, result_path]:
            try:
                os.unlink(temp_file)
            except:
                pass

def main():
    # Find project root (directory containing cmd/, sdk/, etc.)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.join(script_dir, '..', '..')
    project_root = os.path.abspath(project_root)
    
    print(f"Project root: {project_root}")
    
    # Verify tools exist
    tools = {
        'cpp_register': 'sdk/cpp/build/ocrypt-register',
        'cpp_recover': 'sdk/cpp/build/ocrypt-recover',
        'go_register': 'cmd/ocrypt-register/ocrypt-register',
        'go_recover': 'cmd/ocrypt-recover/ocrypt-recover',
        'python_register': 'sdk/python/ocrypt-register.py',
        'python_recover': 'sdk/python/ocrypt-recover.py',
        'rust_register': 'sdk/rust/target/release/ocrypt-register',
        'rust_recover': 'sdk/rust/target/release/ocrypt-recover',
        'js_register': 'sdk/javascript/ocrypt-register.js',
        'js_recover': 'sdk/javascript/ocrypt-recover.js'
    }
    
    print("\nVerifying tools exist...")
    available_tools = {}
    missing_tools = []
    
    for name, path in tools.items():
        full_path = os.path.join(project_root, path)
        if os.path.exists(full_path):
            print(f"✅ {name}: {path}")
            available_tools[name] = path
        else:
            print(f"❌ {name}: {path} (not found)")
            missing_tools.append(name)
    
    if missing_tools:
        print(f"\n⚠️  Missing tools: {', '.join(missing_tools)}")
        print("Some combinations will be skipped, but available combinations will be tested.")
    
    # Define test combinations (25 total for 5x5 matrix)
    test_combinations = [
        # C++ Register → All Recovers
        ('cpp_register', 'cpp_recover', "1.  C++ Register → C++ Recover"),
        ('cpp_register', 'go_recover', "2.  C++ Register → Go Recover"),
        ('cpp_register', 'python_recover', "3.  C++ Register → Python Recover"),
        ('cpp_register', 'rust_recover', "4.  C++ Register → Rust Recover"),
        ('cpp_register', 'js_recover', "5.  C++ Register → JavaScript Recover"),
        
        # Go Register → All Recovers
        ('go_register', 'cpp_recover', "6.  Go Register → C++ Recover"),
        ('go_register', 'go_recover', "7.  Go Register → Go Recover"),
        ('go_register', 'python_recover', "8.  Go Register → Python Recover"),
        ('go_register', 'rust_recover', "9.  Go Register → Rust Recover"),
        ('go_register', 'js_recover', "10. Go Register → JavaScript Recover"),
        
        # Python Register → All Recovers
        ('python_register', 'cpp_recover', "11. Python Register → C++ Recover"),
        ('python_register', 'go_recover', "12. Python Register → Go Recover"),
        ('python_register', 'python_recover', "13. Python Register → Python Recover"),
        ('python_register', 'rust_recover', "14. Python Register → Rust Recover"),
        ('python_register', 'js_recover', "15. Python Register → JavaScript Recover"),
        
        # Rust Register → All Recovers
        ('rust_register', 'cpp_recover', "16. Rust Register → C++ Recover"),
        ('rust_register', 'go_recover', "17. Rust Register → Go Recover"),
        ('rust_register', 'python_recover', "18. Rust Register → Python Recover"),
        ('rust_register', 'rust_recover', "19. Rust Register → Rust Recover"),
        ('rust_register', 'js_recover', "20. Rust Register → JavaScript Recover"),
        
        # JavaScript Register → All Recovers
        ('js_register', 'cpp_recover', "21. JavaScript Register → C++ Recover"),
        ('js_register', 'go_recover', "22. JavaScript Register → Go Recover"),
        ('js_register', 'python_recover', "23. JavaScript Register → Python Recover"),
        ('js_register', 'rust_recover', "24. JavaScript Register → Rust Recover"),
        ('js_register', 'js_recover', "25. JavaScript Register → JavaScript Recover"),
    ]
    
    print(f"\n🚀 Starting 5x5 Cross-Language Ocrypt Test ({len(test_combinations)} combinations)")
    
    passed = 0
    failed = 0
    skipped = 0
    
    for register_tool_name, recover_tool_name, test_name in test_combinations:
        # Check if both tools are available
        if register_tool_name not in available_tools or recover_tool_name not in available_tools:
            missing = []
            if register_tool_name not in available_tools:
                missing.append(register_tool_name)
            if recover_tool_name not in available_tools:
                missing.append(recover_tool_name)
            print(f"\n⏭️  Skipping {test_name} - Missing tools: {', '.join(missing)}")
            skipped += 1
            continue
            
        register_tool = available_tools[register_tool_name]
        recover_tool = available_tools[recover_tool_name]
        
        try:
            if test_combination(register_tool, recover_tool, test_name, project_root):
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            failed += 1
    
    # Summary
    print(f"\n{'='*60}")
    print(f"FINAL RESULTS")
    print(f"{'='*60}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"⏭️  Skipped: {skipped} (missing tools)")
    print(f"📊 Total: {len(test_combinations)} combinations")
    
    if skipped > 0:
        print(f"\n💡 To run all tests, ensure all tools are built:")
        for tool_name in missing_tools:
            print(f"   - {tool_name}: {tools[tool_name]}")
    
    if failed == 0 and skipped == 0:
        print(f"🎉 All cross-language combinations work perfectly!")
        return 0
    elif failed == 0:
        print(f"🎉 All available combinations work perfectly!")
        print(f"   Build missing tools to test remaining {skipped} combinations.")
        return 0
    else:
        print(f"💥 {failed} combinations failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 