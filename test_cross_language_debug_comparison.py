#!/usr/bin/env python3
"""
Cross-Language Debug Output Comparison Test

This test runs encryption/decryption operations with Python, Go, and C++ implementations
in debug mode and compares their debug output to ensure they perform identical 
cryptographic operations.

Enhanced to support:
- Dynamic server management with proper public keys
- file://, http://, and https:// server URL formats
- Consistent server URL handling across all SDKs
"""

import os
import sys
import subprocess
import tempfile
import time
import re
import argparse
from manage_test_servers import TestServerManager

def log(message):
    print(f"[CROSS_TEST] {message}")

class CrossLanguageDebugTest:
    def __init__(self, num_servers=2, start_port=8080, servers_url_format="http"):
        self.num_servers = num_servers
        self.start_port = start_port
        self.servers_url_format = servers_url_format
        self.server_manager = TestServerManager()
        self.servers_url = None
        self.test_files = []
        
    def setup(self):
        """Setup test servers and get servers URL"""
        log(f"🔧 Setting up {self.num_servers} test servers...")
        
        # Launch test servers
        success = self.server_manager.launch_servers(self.num_servers, self.start_port)
        if not success:
            log("❌ Failed to launch test servers")
            return False
        
        # Get servers URL in the requested format
        try:
            self.servers_url = self.server_manager.get_servers_url(self.servers_url_format)
            log(f"✅ Servers URL: {self.servers_url}")
            return True
        except Exception as e:
            log(f"❌ Failed to get servers URL: {e}")
            return False
    
    def cleanup(self):
        """Cleanup test infrastructure"""
        log("🧹 Cleaning up test infrastructure...")
        
        # Cleanup server manager
        self.server_manager.teardown()
        
        # Clean up test files
        for test_file in self.test_files:
            try:
                if os.path.exists(test_file):
                    os.remove(test_file)
            except:
                pass
        
        log("✅ Cleanup complete")
    
    def create_test_input(self):
        """Create test input file"""
        test_content = b"Cross-language debug test: identical crypto operations verification"
        test_file = "cross_lang_debug_input.txt"
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        self.test_files.append(test_file)
        return test_file
    
    def extract_debug_operations(self, debug_output):
        """Extract debug operations from stderr output"""
        operations = []
        
        # Split by lines and look for debug patterns
        lines = debug_output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Look for various debug patterns
            if any(pattern in line for pattern in [
                "Using deterministic",
                "Computed U point",
                "Computed S =",
                "Auth code for server",
                "Generated deterministic"
            ]):
                # Clean up the line
                if line.startswith('[DEBUG]'):
                    line = line[7:].strip()
                elif 'DEBUG]' in line:
                    # Handle Go format: "2025/06/28 12:30:09 [DEBUG] message"
                    debug_pos = line.find('[DEBUG]')
                    if debug_pos >= 0:
                        line = line[debug_pos + 7:].strip()
                
                if line:
                    operations.append(line)
        
        return operations
    
    def extract_debug_operations_combined(self, stdout, stderr):
        """Extract debug operations from both stdout and stderr"""
        # Combine outputs and extract from both
        combined_output = stderr + "\n" + stdout
        return self.extract_debug_operations(combined_output)
    
    def run_python_encrypt(self, test_file):
        """Run Python encryption with debug output"""
        log("🐍 Running Python encryption with debug...")
        
        # Try different Python entry points
        python_scripts = [
            "sdk/python/openadp-encrypt.py",
            "sdk/python/openadp/openadp-encrypt.py",
        ]
        
        python_script = None
        for script in python_scripts:
            if os.path.exists(script):
                python_script = script
                break
        
        if not python_script:
            log("❌ Python encrypt script not found")
            return None, None, "Python encrypt script not found"
        
        cmd = [
            "python3", python_script,
            "--file", test_file,
            "--password", "cross_lang_debug_pass",
            "--user-id", "cross_lang_debug_user",
            "--servers-url", self.servers_url,  # Use --servers-url instead of --servers
            "--debug"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            log(f"Python exit code: {result.returncode}")
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            log(f"❌ Python encryption failed: {e}")
            return -1, "", str(e)
    
    def run_go_encrypt(self, test_file):
        """Run Go encryption with debug output"""
        log("🐹 Running Go encryption with debug...")
        
        # Check for Go binary
        go_binaries = [
            "build/openadp-encrypt",
            "cmd/openadp-encrypt/openadp-encrypt",
        ]
        
        go_binary = None
        for binary in go_binaries:
            if os.path.exists(binary):
                go_binary = binary
                break
        
        if not go_binary:
            log("❌ Go encrypt binary not found")
            return None, None, "Go encrypt binary not found"
        
        cmd = [
            go_binary,
            "--file", test_file,
            "--password", "cross_lang_debug_pass",
            "--user-id", "cross_lang_debug_user",
            "--servers-url", self.servers_url,  # Use --servers-url
            "--debug"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            log(f"Go exit code: {result.returncode}")
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            log(f"❌ Go encryption failed: {e}")
            return -1, "", str(e)
    
    def run_cpp_encrypt(self, test_file):
        """Run C++ encryption with debug output"""
        log("⚙️ Running C++ encryption with debug...")
        
        # Check for C++ binary
        cpp_binaries = [
            "sdk/cpp/build/openadp-encrypt",
            "build/cpp/openadp-encrypt",
        ]
        
        cpp_binary = None
        for binary in cpp_binaries:
            if os.path.exists(binary):
                cpp_binary = binary
                break
        
        if not cpp_binary:
            log("❌ C++ encrypt binary not found")
            return None, None, "C++ encrypt binary not found"
        
        # C++ uses different parameter names
        output_file = test_file + "_cpp.enc"
        metadata_file = test_file + "_cpp.meta"
        self.test_files.extend([output_file, metadata_file])
        
        cmd = [
            cpp_binary,
            "--input", test_file,
            "--output", output_file,
            "--metadata", metadata_file,
            "--password", "cross_lang_debug_pass",
            "--user-id", "cross_lang_debug_user",
            "--servers-url", self.servers_url,  # C++ should support this format
            "--debug"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            log(f"C++ exit code: {result.returncode}")
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            log(f"❌ C++ encryption failed: {e}")
            return -1, "", str(e)
    
    def run_javascript_encrypt(self, test_file):
        """Run JavaScript encryption with debug output"""
        log("🟨 Running JavaScript encryption with debug...")
        
        # Check for JavaScript encrypt script
        js_scripts = [
            "sdk/javascript/openadp-encrypt.js",
        ]
        
        js_script = None
        for script in js_scripts:
            if os.path.exists(script):
                js_script = script
                break
        
        if not js_script:
            log("❌ JavaScript encrypt script not found")
            return None, None, "JavaScript encrypt script not found"
        
        cmd = [
            "node", js_script,
            "--file", test_file,
            "--password", "cross_lang_debug_pass",
            "--user-id", "cross_lang_debug_user",
            "--servers-url", self.servers_url,
            "--debug"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            log(f"JavaScript exit code: {result.returncode}")
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            log(f"❌ JavaScript encryption failed: {e}")
            return -1, "", str(e)
    
    def compare_implementations(self):
        """Run and compare all implementations"""
        log("🔍 Running cross-language debug comparison...")
        
        # Create test input
        test_file = self.create_test_input()
        
        # Run all implementations
        implementations = {
            "Python": self.run_python_encrypt(test_file),
            "Go": self.run_go_encrypt(test_file), 
            "C++": self.run_cpp_encrypt(test_file),
            "JavaScript": self.run_javascript_encrypt(test_file)
        }
        
        # Check for failures
        failed_implementations = []
        for name, (code, stdout, stderr) in implementations.items():
            if code is None or code != 0:
                failed_implementations.append(name)
                log(f"❌ {name} failed with exit code {code}")
                if stderr:
                    log(f"   stderr: {stderr[:200]}...")
        
        # Show detailed output for ALL implementations to compare transport keys
        for name, (code, stdout, stderr) in implementations.items():
            log(f"\n{'='*60}")
            log(f"{name} DETAILED OUTPUT:")
            log("="*60)
            log(f"Exit code: {code}")
            log(f"stdout: {stdout}")
            log(f"stderr: {stderr}")
        
        if failed_implementations:
            log(f"❌ Failed implementations: {failed_implementations}")
            return False
        
        # Extract debug operations
        debug_operations = {}
        for name, (code, stdout, stderr) in implementations.items():
            operations = self.extract_debug_operations_combined(stdout, stderr)
            debug_operations[name] = operations
            log(f"✅ {name}: {len(operations)} debug operations extracted")
        
        # Display raw debug output
        log("\n" + "="*80)
        log("RAW DEBUG OUTPUT COMPARISON")
        log("="*80)
        
        for name, (code, stdout, stderr) in implementations.items():
            log(f"\n{'-'*60}")
            log(f"{name} DEBUG OUTPUT:")
            log("-"*60)
            log(stderr)
        
        # Display extracted operations
        log("\n" + "="*80)
        log("EXTRACTED DEBUG OPERATIONS COMPARISON")
        log("="*80)
        
        for name, operations in debug_operations.items():
            log(f"\n{'-'*60}")
            log(f"{name} OPERATIONS ({len(operations)}):")
            log("-"*60)
            for i, op in enumerate(operations, 1):
                log(f" {i:2}. {op}")
        
        # Compare operations
        log("\n" + "="*80)
        log("COMPARISON ANALYSIS")
        log("="*80)
        
        # Get operation counts
        op_counts = {name: len(ops) for name, ops in debug_operations.items()}
        log(f"Operation counts: {op_counts}")
        
        # Check if counts match
        if len(set(op_counts.values())) == 1:
            log("✅ All implementations have the same number of debug operations")
        else:
            log("⚠️ Different number of debug operations between implementations")
        
        # Compare operations pairwise
        implementation_names = list(debug_operations.keys())
        comparison_results = {}
        
        for i in range(len(implementation_names)):
            for j in range(i + 1, len(implementation_names)):
                name1, name2 = implementation_names[i], implementation_names[j]
                ops1, ops2 = debug_operations[name1], debug_operations[name2]
                
                matches = 0
                total = max(len(ops1), len(ops2))
                
                for k in range(min(len(ops1), len(ops2))):
                    if ops1[k] == ops2[k]:
                        matches += 1
                
                match_percentage = (matches / total * 100) if total > 0 else 0
                comparison_results[f"{name1} vs {name2}"] = (matches, total, match_percentage)
                
                log(f"{name1} vs {name2}: {matches}/{total} operations match ({match_percentage:.1f}%)")
        
        # Determine overall result
        all_perfect = all(matches == total for matches, total, _ in comparison_results.values())
        
        if all_perfect:
            log("\n🎉 PERFECT MATCH: All implementations produce identical debug operations!")
            return True
        else:
            log("\n⚠️ PARTIAL MATCH: Some differences found between implementations")
            return False
    
    def run(self):
        """Run the complete cross-language debug comparison test"""
        log("🚀 Starting Cross-Language Debug Comparison Test")
        log(f"Testing {self.num_servers} servers with {self.servers_url_format} URL format")
        
        try:
            # Setup
            if not self.setup():
                return False
            
            # Run comparison
            result = self.compare_implementations()
            
            return result
            
        finally:
            # Always cleanup
            self.cleanup()

def main():
    parser = argparse.ArgumentParser(description="Cross-language debug output comparison test")
    parser.add_argument("--num-servers", type=int, default=2, 
                       help="Number of test servers to launch (default: 2)")
    parser.add_argument("--start-port", type=int, default=8080,
                       help="Starting port for test servers (default: 8080)")  
    parser.add_argument("--servers-url-format", choices=["file", "http"], default="http",
                       help="Format for servers URL (default: http)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Check required tools
    required_tools = [
        ("build/openadp-server", "Go server"),
        ("build/openadp-serverinfo", "Server info tool"),
    ]
    
    missing_tools = []
    for tool_path, tool_name in required_tools:
        if not os.path.exists(tool_path):
            # Try alternative location
            alt_path = tool_path.replace("build/", "cmd/").replace("/", "/") + "/" + os.path.basename(tool_path)
            if not os.path.exists(alt_path):
                missing_tools.append(f"{tool_name} ({tool_path})")
    
    if missing_tools:
        log("❌ Missing required tools:")
        for tool in missing_tools:
            log(f"   - {tool}")
        log("Please build the required tools first.")
        return 1
    
    # Run the test
    test = CrossLanguageDebugTest(
        num_servers=args.num_servers,
        start_port=args.start_port,
        servers_url_format=args.servers_url_format
    )
    
    try:
        if test.run():
            log("🎉 Cross-language debug comparison PASSED!")
            log("All implementations produce identical cryptographic operations.")
            return 0
        else:
            log("💥 Cross-language debug comparison FAILED!")
            log("Implementations have differences in cryptographic operations.")
            return 1
    except KeyboardInterrupt:
        log("Test interrupted by user")
        return 130
    except Exception as e:
        log(f"❌ Test failed with error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 