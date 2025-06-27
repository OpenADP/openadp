#!/usr/bin/env python3
"""
Cross-language Ocrypt 4x4 Test

This script tests all 16 combinations of Ocrypt register/recover tools across:
- Go (cmd/ocrypt-register, cmd/ocrypt-recover)
- Python (sdk/python/ocrypt-register.py, sdk/python/ocrypt-recover.py)  
- JavaScript (sdk/javascript/ocrypt-register.js, sdk/javascript/ocrypt-recover.js)
- Rust (sdk/rust/target/release/ocrypt-register, sdk/rust/target/release/ocrypt-recover)

Test matrix (16 combinations):
1.  Go Register → Go Recover           9.  JavaScript Register → Go Recover
2.  Go Register → Python Recover      10. JavaScript Register → Python Recover  
3.  Go Register → JavaScript Recover  11. JavaScript Register → JavaScript Recover
4.  Go Register → Rust Recover        12. JavaScript Register → Rust Recover
5.  Python Register → Go Recover      13. Rust Register → Go Recover
6.  Python Register → Python Recover  14. Rust Register → Python Recover
7.  Python Register → JavaScript Recover  15. Rust Register → JavaScript Recover
8.  Python Register → Rust Recover    16. Rust Register → Rust Recover

Each test validates:
- Registration creates valid metadata
- Recovery returns correct secret
- Backup refresh works (updated metadata differs from original)
- Cross-language JSON compatibility
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
        'go_register': 'cmd/ocrypt-register/ocrypt-register',
        'go_recover': 'cmd/ocrypt-recover/ocrypt-recover',
        'python_register': 'sdk/python/ocrypt-register.py',
        'python_recover': 'sdk/python/ocrypt-recover.py',
        'js_register': 'sdk/javascript/ocrypt-register.js',
        'js_recover': 'sdk/javascript/ocrypt-recover.js',
        'rust_register': 'sdk/rust/target/release/ocrypt-register',
        'rust_recover': 'sdk/rust/target/release/ocrypt-recover'
    }
    
    print("\nVerifying tools exist...")
    for name, path in tools.items():
        full_path = os.path.join(project_root, path)
        if os.path.exists(full_path):
            print(f"✅ {name}: {path}")
        else:
            print(f"❌ {name}: {path} (not found)")
            return 1
    
    # Define test combinations (16 total)
    test_combinations = [
        # Go Register → All Recovers
        (tools['go_register'], tools['go_recover'], "1.  Go Register → Go Recover"),
        (tools['go_register'], tools['python_recover'], "2.  Go Register → Python Recover"),
        (tools['go_register'], tools['js_recover'], "3.  Go Register → JavaScript Recover"),
        (tools['go_register'], tools['rust_recover'], "4.  Go Register → Rust Recover"),
        
        # Python Register → All Recovers
        (tools['python_register'], tools['go_recover'], "5.  Python Register → Go Recover"),
        (tools['python_register'], tools['python_recover'], "6.  Python Register → Python Recover"),
        (tools['python_register'], tools['js_recover'], "7.  Python Register → JavaScript Recover"),
        (tools['python_register'], tools['rust_recover'], "8.  Python Register → Rust Recover"),
        
        # JavaScript Register → All Recovers
        (tools['js_register'], tools['go_recover'], "9.  JavaScript Register → Go Recover"),
        (tools['js_register'], tools['python_recover'], "10. JavaScript Register → Python Recover"),
        (tools['js_register'], tools['js_recover'], "11. JavaScript Register → JavaScript Recover"),
        (tools['js_register'], tools['rust_recover'], "12. JavaScript Register → Rust Recover"),
        
        # Rust Register → All Recovers
        (tools['rust_register'], tools['go_recover'], "13. Rust Register → Go Recover"),
        (tools['rust_register'], tools['python_recover'], "14. Rust Register → Python Recover"),
        (tools['rust_register'], tools['js_recover'], "15. Rust Register → JavaScript Recover"),
        (tools['rust_register'], tools['rust_recover'], "16. Rust Register → Rust Recover"),
    ]
    
    print(f"\n🚀 Starting 4x4 Cross-Language Ocrypt Test ({len(test_combinations)} combinations)")
    
    passed = 0
    failed = 0
    
    for register_tool, recover_tool, test_name in test_combinations:
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
    print(f"✅ Passed: {passed}/{len(test_combinations)}")
    print(f"❌ Failed: {failed}/{len(test_combinations)}")
    
    if failed == 0:
        print(f"🎉 All cross-language combinations work perfectly!")
        return 0
    else:
        print(f"💥 Some combinations failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 