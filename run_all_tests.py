#!/usr/bin/env python3
"""
OpenADP Comprehensive Test Runner

This script runs all tests across all languages and components:
- Go unit tests
- Go integration tests  
- Python SDK tests
- Cross-language compatibility tests
- Build verification tests

Color Scheme:
- Uses protanopia-friendly colors with high contrast
- SUCCESS: Blue (instead of green) for passed tests
- FAILURE: Magenta (instead of red) for failed tests
- These colors are easily distinguishable for people with red-green color blindness

Usage:
    ./run_all_tests.py              # Run all tests
    ./run_all_tests.py --fast       # Skip slow integration tests
    ./run_all_tests.py --verbose    # Verbose output
    ./run_all_tests.py --go-only    # Only Go tests
    ./run_all_tests.py --python-only # Only Python tests
    ./run_all_tests.py --no-color   # Disable colored output
"""

import os
import sys
import subprocess
import time
import argparse
import json
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import shutil

@dataclass
class TestResult:
    name: str
    success: bool
    duration: float
    output: str
    error: Optional[str] = None

class Colors:
    # Protanopia-friendly colors with high contrast and bold text
    # Using bold variants to ensure visibility across different terminal themes
    _colors_enabled = True
    
    @classmethod
    def disable_colors(cls):
        """Disable all colors for terminals that don't support them or when requested"""
        cls._colors_enabled = False
    
    @classmethod
    def _get_color(cls, code):
        """Return color code if colors are enabled, empty string otherwise"""
        return code if cls._colors_enabled else ''
    
    @property
    def SUCCESS(self):
        return self._get_color('\033[1;34m')    # Bold blue for success
    
    @property  
    def FAILURE(self):
        return self._get_color('\033[1;35m')    # Bold magenta for failure
    
    @property
    def WARNING(self):
        return self._get_color('\033[1;33m')    # Bold yellow for warnings
    
    @property
    def INFO(self):
        return self._get_color('\033[1;36m')    # Bold cyan for info
    
    @property
    def EMPHASIS(self):
        return self._get_color('\033[1;37m')    # Bold white for emphasis
    
    @property
    def BOLD(self):
        return self._get_color('\033[1m')       # Bold text
    
    @property
    def RESET(self):
        return self._get_color('\033[0m')       # Reset to default
    
    # Legacy aliases for backward compatibility
    @property
    def GREEN(self):
        return self._get_color('\033[1;34m')    # Map to bold blue
    
    @property
    def RED(self):
        return self._get_color('\033[1;35m')    # Map to bold magenta
    
    @property
    def YELLOW(self):
        return self._get_color('\033[1;33m')    # Bold yellow
    
    @property
    def BLUE(self):
        return self._get_color('\033[1;34m')    # Bold blue
    
    @property
    def MAGENTA(self):
        return self._get_color('\033[1;35m')    # Bold magenta
    
    @property
    def CYAN(self):
        return self._get_color('\033[1;36m')    # Bold cyan
    
    @property
    def WHITE(self):
        return self._get_color('\033[1;37m')    # Bold white

# Create a global instance
Colors = Colors()

class OpenADPTestRunner:
    def __init__(self, args):
        self.args = args
        self.root_dir = Path.cwd()
        self.results: List[TestResult] = []
        self.start_time = time.time()
        
        # Disable colors if requested or if not in a terminal
        if args.no_color or not sys.stdout.isatty():
            Colors.disable_colors()
        
    def log(self, message: str, color: str = Colors.INFO):
        if self.args.verbose or "FAIL" in message or "PASS" in message:
            print(f"{color}{message}{Colors.RESET}")
    
    def run_command(self, cmd: List[str], cwd: Optional[Path] = None, timeout: int = 300) -> Tuple[bool, str, str]:
        """Run a command and return (success, stdout, stderr)"""
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd or self.root_dir,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, "", f"Exception running command: {str(e)}"
    
    def test_go_build(self) -> TestResult:
        """Test that all Go components build successfully"""
        start_time = time.time()
        self.log("🔨 Building Go components...", Colors.INFO)
        
        # First clean, then build all components including tools needed for tests
        success, stdout, stderr = self.run_command([
            "make", "clean", "build", "build-go"
        ])
        duration = time.time() - start_time
        
        if success:
            self.log("✅ Go build: PASS", Colors.SUCCESS)
            return TestResult("Go Build", True, duration, stdout)
        else:
            self.log("❌ Go build: FAIL", Colors.FAILURE)
            return TestResult("Go Build", False, duration, stdout, stderr)
    
    def test_go_unit_tests(self) -> TestResult:
        """Run Go unit tests for all modules (ocrypt, server)"""
        start_time = time.time()
        self.log("🧪 Running Go unit tests...", Colors.INFO)
        
        # Run tests for each module separately
        modules = ["server"]
        all_output = []
        all_errors = []
        overall_success = True
        
        for module in modules:
            self.log(f"  📦 Testing {module} module...", Colors.INFO)
            success, stdout, stderr = self.run_command(["go", "test", "./...", "-v"], cwd=self.root_dir / module)
            all_output.append(f"=== {module.upper()} MODULE TESTS ===\n{stdout}")
            if stderr:
                all_errors.append(f"=== {module.upper()} MODULE ERRORS ===\n{stderr}")
            if not success:
                overall_success = False
                self.log(f"  ❌ {module} module tests: FAIL", Colors.FAILURE)
            else:
                self.log(f"  ✅ {module} module tests: PASS", Colors.SUCCESS)
        
        duration = time.time() - start_time
        combined_output = "\n\n".join(all_output)
        combined_errors = "\n\n".join(all_errors) if all_errors else None
        
        if overall_success:
            self.log("✅ Go unit tests: PASS", Colors.SUCCESS)
            return TestResult("Go Unit Tests", True, duration, combined_output)
        else:
            self.log("❌ Go unit tests: FAIL", Colors.FAILURE)
            return TestResult("Go Unit Tests", False, duration, combined_output, combined_errors)
    
    def test_go_integration_tests(self) -> TestResult:
        """Run Go integration tests"""
        start_time = time.time()
        self.log("🔗 Running Go integration tests...", Colors.INFO)
        
        success, stdout, stderr = self.run_command(["go", "test", "./tests/...", "-v"], timeout=600)
        duration = time.time() - start_time
        
        if success:
            self.log("✅ Go integration tests: PASS", Colors.SUCCESS)
            return TestResult("Go Integration Tests", True, duration, stdout)
        else:
            self.log("❌ Go integration tests: FAIL", Colors.FAILURE)
            return TestResult("Go Integration Tests", False, duration, stdout, stderr)
    
    def test_python_sdk_setup(self) -> TestResult:
        """Test Python SDK setup and dependencies"""
        start_time = time.time()
        self.log("🐍 Testing Python SDK setup...", Colors.INFO)
        
        # Check if venv exists
        venv_path = self.root_dir / "venv"
        if not venv_path.exists():
            duration = time.time() - start_time
            return TestResult("Python SDK Setup", False, duration, "", 
                            "Virtual environment not found. Please run 'scripts/setup_env.sh' first.")
        
        # Test import of openadp module
        success, stdout, stderr = self.run_command([
            "bash", "-c", "source venv/bin/activate && python -c 'import openadp; print(\"OpenADP Python SDK imported successfully\")'"
        ])
        
        duration = time.time() - start_time
        
        if success:
            self.log("✅ Python SDK setup: PASS", Colors.SUCCESS)
            return TestResult("Python SDK Setup", True, duration, stdout)
        else:
            self.log("❌ Python SDK setup: FAIL", Colors.FAILURE)
            return TestResult("Python SDK Setup", False, duration, stdout, stderr)
    
    def test_python_unit_tests(self) -> TestResult:
        """Run Python unit tests"""
        start_time = time.time()
        self.log("🧪 Running Python unit tests...", Colors.INFO)
        
        python_test_dir = self.root_dir / "sdk" / "python" / "tests"
        success, stdout, stderr = self.run_command([
            "bash", "-c", "source ../../../venv/bin/activate && python -m pytest . -v --tb=short"
        ], cwd=python_test_dir)
        
        duration = time.time() - start_time
        
        if success:
            self.log("✅ Python unit tests: PASS", Colors.SUCCESS)
            return TestResult("Python Unit Tests", True, duration, stdout)
        else:
            self.log("❌ Python unit tests: FAIL", Colors.FAILURE)
            return TestResult("Python Unit Tests", False, duration, stdout, stderr)
    
    def test_python_tools(self) -> TestResult:
        """Test Python encrypt/decrypt tools"""
        start_time = time.time()
        self.log("🔧 Testing Python tools...", Colors.INFO)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test_file.txt"
            test_content = "Test content for Python tools"
            test_file.write_text(test_content)
            
            # Test version flags using virtual environment
            success1, _, _ = self.run_command([
                "bash", "-c", "source venv/bin/activate && python sdk/python/openadp-encrypt.py --version"
            ])
            success2, _, _ = self.run_command([
                "bash", "-c", "source venv/bin/activate && python sdk/python/openadp-decrypt.py --version"
            ])
            
            duration = time.time() - start_time
            
            if success1 and success2:
                self.log("✅ Python tools: PASS", Colors.SUCCESS)
                return TestResult("Python Tools", True, duration, "Version checks passed")
            else:
                self.log("❌ Python tools: FAIL", Colors.FAILURE)
                return TestResult("Python Tools", False, duration, "", "Version checks failed")
    
    def test_javascript_unit_tests(self) -> TestResult:
        """Run JavaScript unit tests including Ocrypt tests"""
        start_time = time.time()
        self.log("🟨 Running JavaScript unit tests...", Colors.INFO)
        
        # Check JavaScript dependencies first
        if not self.check_javascript_dependencies():
            duration = time.time() - start_time
            return TestResult("JavaScript Unit Tests", False, duration, 
                            "", "JavaScript dependencies not available")
        
        js_sdk_path = self.root_dir / "sdk" / "javascript"
        success, stdout, stderr = self.run_command(["npm", "test"], cwd=js_sdk_path)
        
        duration = time.time() - start_time
        
        if success:
            self.log("✅ JavaScript unit tests: PASS", Colors.SUCCESS)
            return TestResult("JavaScript Unit Tests", True, duration, stdout)
        else:
            self.log("❌ JavaScript unit tests: FAIL", Colors.FAILURE)
            return TestResult("JavaScript Unit Tests", False, duration, stdout, stderr)
    
    def test_cross_language_compatibility(self) -> TestResult:
        """Run cross-language compatibility tests"""
        start_time = time.time()
        self.log("🔄 Running cross-language compatibility tests...", Colors.INFO)
        
        # Use our existing cross-language test
        success, stdout, stderr = self.run_command([
            "python", "tests/cross-language/test_cross_language_encrypt_decrypt.py"
        ], timeout=300)
        
        duration = time.time() - start_time
        
        if success:
            self.log("✅ Cross-language compatibility: PASS", Colors.SUCCESS)
            return TestResult("Cross-Language Compatibility", True, duration, stdout)
        else:
            self.log("❌ Cross-language compatibility: FAIL", Colors.FAILURE)
            return TestResult("Cross-Language Compatibility", False, duration, stdout, stderr)

    def test_cross_language_16x16_matrix(self) -> TestResult:
        """Run comprehensive 16x16 cross-language matrix test (Go/Python/JavaScript/Rust)"""
        start_time = time.time()
        self.log("🔄 Running comprehensive 16x16 cross-language matrix test...", Colors.INFO)
        
        # Check JavaScript dependencies first
        if not self.check_javascript_dependencies():
            duration = time.time() - start_time
            return TestResult("16x16 Cross-Language Matrix", False, duration, 
                            "", "JavaScript dependencies not available")
        
        # Ensure Go tools are built
        if not self.ensure_go_tools_built():
            duration = time.time() - start_time
            return TestResult("16x16 Cross-Language Matrix", False, duration, 
                            "", "Go tools not available")
        
        # Ensure Rust tools are built
        if not self.ensure_rust_tools_built():
            duration = time.time() - start_time
            return TestResult("16x16 Cross-Language Matrix", False, duration, 
                            "", "Rust tools not available")
        
        # Use the enhanced 16x16 test
        success, stdout, stderr = self.run_command([
            "python", "tests/cross-language/test_cross_language_encrypt_decrypt_16x16.py"
        ], timeout=600)  # Longer timeout for comprehensive test
        
        duration = time.time() - start_time
        
        if success:
            self.log("✅ 16x16 Cross-language matrix: PASS", Colors.SUCCESS)
            return TestResult("16x16 Cross-Language Matrix", True, duration, stdout)
        else:
            self.log("❌ 16x16 Cross-language matrix: FAIL", Colors.FAILURE)
            return TestResult("16x16 Cross-Language Matrix", False, duration, stdout, stderr)
    
    def test_noise_nk_compatibility(self) -> TestResult:
        """Test Noise-NK cross-platform compatibility between Python server and JavaScript client"""
        start_time = time.time()
        self.log("🔒 Testing Noise-NK cross-platform compatibility...", Colors.INFO)
        
        # Check JavaScript dependencies first
        if not self.check_javascript_dependencies():
            duration = time.time() - start_time
            return TestResult("Noise-NK Compatibility", False, duration, 
                            "", "JavaScript dependencies not available")
        
        server_process = None
        try:
            # Start Python Noise server in background
            self.log("🚀 Starting Python Noise-NK server...", Colors.INFO)
            server_process = subprocess.Popen(
                ["python", "noise_server.py"],
                cwd=self.root_dir / "sdk" / "python",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for server to start and create server_info.json
            server_info_path = self.root_dir / "sdk" / "python" / "server_info.json"
            max_wait = 10  # Wait up to 10 seconds for server to start
            wait_time = 0
            
            while wait_time < max_wait:
                if server_info_path.exists():
                    # Give it another second to fully initialize
                    time.sleep(1)
                    break
                time.sleep(0.5)
                wait_time += 0.5
            
            if not server_info_path.exists():
                if server_process.poll() is not None:
                    # Server process died
                    _, stderr = server_process.communicate()
                    return TestResult("Noise-NK Compatibility", False, time.time() - start_time, 
                                    "", f"Server failed to start: {stderr}")
                else:
                    return TestResult("Noise-NK Compatibility", False, time.time() - start_time,
                                    "", "Server didn't create server_info.json in time")
            
            self.log("📡 Server started, running JavaScript client test...", Colors.INFO)
            
            # Run JavaScript client test
            success, stdout, stderr = self.run_command([
                "node", "noise_client.js"
            ], cwd=self.root_dir / "sdk" / "javascript", timeout=60)
            
            duration = time.time() - start_time
            
            # Check for successful test completion
            if success and "All tests completed successfully!" in stdout:
                self.log("✅ Noise-NK compatibility: PASS", Colors.SUCCESS)
                return TestResult("Noise-NK Compatibility", True, duration, stdout)
            else:
                self.log("❌ Noise-NK compatibility: FAIL", Colors.FAILURE)
                error_msg = stderr if stderr else "JavaScript client test failed or didn't complete successfully"
                return TestResult("Noise-NK Compatibility", False, duration, stdout, error_msg)
                
        except Exception as e:
            duration = time.time() - start_time
            self.log(f"❌ Noise-NK compatibility: EXCEPTION - {str(e)}", Colors.FAILURE)
            return TestResult("Noise-NK Compatibility", False, duration, "", str(e))
            
        finally:
            # Clean up server process
            if server_process:
                try:
                    server_process.terminate()
                    server_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server_process.kill()
                    server_process.wait()
                except Exception:
                    pass  # Ignore cleanup errors
                
                # Clean up server_info.json
                try:
                    server_info_path = self.root_dir / "sdk" / "python" / "server_info.json"
                    if server_info_path.exists():
                        server_info_path.unlink()
                except Exception:
                    pass  # Ignore cleanup errors
    
    def test_makefile_targets(self) -> TestResult:
        """Test key Makefile targets"""
        start_time = time.time()
        self.log("📋 Testing Makefile targets...", Colors.INFO)
        
        targets_to_test = ["test", "fmt"]
        all_success = True
        combined_output = []
        
        for target in targets_to_test:
            success, stdout, stderr = self.run_command(["make", target])
            combined_output.append(f"=== make {target} ===\n{stdout}\n{stderr}")
            if not success:
                all_success = False
                self.log(f"❌ make {target}: FAIL", Colors.FAILURE)
            else:
                self.log(f"✅ make {target}: PASS", Colors.SUCCESS)
        
        duration = time.time() - start_time
        output = "\n".join(combined_output)
        
        if all_success:
            self.log("✅ Makefile targets: PASS", Colors.SUCCESS)
            return TestResult("Makefile Targets", True, duration, output)
        else:
            self.log("❌ Makefile targets: FAIL", Colors.FAILURE)
            return TestResult("Makefile Targets", False, duration, output, "Some targets failed")
    
    def ensure_go_tools_built(self) -> bool:
        """Ensure Go tools are built before running tests that need them"""
        self.log("🔧 Ensuring Go tools are built...", Colors.INFO)
        
        # Check if build directory exists and has executables
        build_dir = self.root_dir / "build"
        if not build_dir.exists():
            self.log("📁 Build directory doesn't exist, building all tools...", Colors.WARNING)
            success, _, _ = self.run_command(["make", "build-go"])
            return success
        
        # Check for key executables including ocrypt tools
        key_executables = ["openadp-server", "openadp-encrypt", "openadp-decrypt", 
                          "openadp-serverinfo", "ocrypt-register", "ocrypt-recover"]
        missing_tools = []
        
        for exe in key_executables:
            exe_path = build_dir / exe
            if not exe_path.exists():
                missing_tools.append(exe)
        
        if missing_tools:
            self.log(f"🔨 Missing tools: {missing_tools}, building all tools...", Colors.WARNING)
            success, _, _ = self.run_command(["make", "build-go"])
            return success
        
        self.log("✅ Go tools are already built", Colors.SUCCESS)
        return True
    
    def ensure_rust_tools_built(self) -> bool:
        """Ensure Rust tools are built before running tests that need them"""
        self.log("🦀 Ensuring Rust tools are built...", Colors.INFO)
        
        # Check if Rust tools exist in the expected location
        rust_dir = self.root_dir / "sdk" / "rust" / "target" / "release"
        if not rust_dir.exists():
            self.log("📁 Rust release directory doesn't exist, building Rust tools...", Colors.WARNING)
            success, _, _ = self.run_command(["make", "build-rust"])
            return success
        
        # Check for key Rust executables
        rust_executables = ["openadp-encrypt", "openadp-decrypt"]
        missing_tools = []
        
        for exe in rust_executables:
            exe_path = rust_dir / exe
            if not exe_path.exists():
                missing_tools.append(exe)
        
        if missing_tools:
            self.log(f"🔨 Missing Rust tools: {missing_tools}, building Rust tools...", Colors.WARNING)
            success, _, _ = self.run_command(["make", "build-rust"])
            return success
        
        self.log("✅ Rust tools are already built", Colors.SUCCESS)
        return True
    
    def check_javascript_dependencies(self) -> bool:
        """Check if Node.js and JavaScript dependencies are available"""
        self.log("📦 Checking JavaScript dependencies...", Colors.INFO)
        
        # Check if Node.js is available
        success, stdout, stderr = self.run_command(["node", "--version"])
        if not success:
            self.log("❌ Node.js not found. Please install Node.js to run Noise-NK tests.", Colors.FAILURE)
            return False
        
        node_version = stdout.strip()
        self.log(f"✅ Node.js version: {node_version}", Colors.SUCCESS)
        
        # Check if package.json exists in JavaScript SDK
        js_sdk_path = self.root_dir / "sdk" / "javascript"
        package_json_path = js_sdk_path / "package.json"
        
        if not package_json_path.exists():
            self.log("❌ package.json not found in JavaScript SDK", Colors.FAILURE)
            return False
        
        # Check if node_modules exists, if not try to install
        node_modules_path = js_sdk_path / "node_modules"
        if not node_modules_path.exists():
            self.log("📦 Installing JavaScript dependencies...", Colors.INFO)
            success, stdout, stderr = self.run_command(["npm", "install"], cwd=js_sdk_path)
            if not success:
                self.log(f"❌ Failed to install JavaScript dependencies: {stderr}", Colors.FAILURE)
                return False
            self.log("✅ JavaScript dependencies installed", Colors.SUCCESS)
        
        return True
    
    def test_cpp_build(self) -> TestResult:
        """Test that C++ SDK builds successfully"""
        start_time = time.time()
        self.log("🔨 Building C++ SDK...", Colors.INFO)
        
        cpp_build_dir = self.root_dir / "sdk" / "cpp" / "build"
        
        # Create build directory if it doesn't exist
        if not cpp_build_dir.exists():
            cpp_build_dir.mkdir(parents=True, exist_ok=True)
        
        # Run cmake and make
        success1, stdout1, stderr1 = self.run_command(["cmake", ".."], cwd=cpp_build_dir)
        if not success1:
            duration = time.time() - start_time
            self.log("❌ C++ CMake configure: FAIL", Colors.FAILURE)
            return TestResult("C++ Build", False, duration, stdout1, stderr1)
        
        success2, stdout2, stderr2 = self.run_command(["make"], cwd=cpp_build_dir)
        duration = time.time() - start_time
        
        if success2:
            self.log("✅ C++ build: PASS", Colors.SUCCESS)
            return TestResult("C++ Build", True, duration, stdout1 + stdout2)
        else:
            self.log("❌ C++ build: FAIL", Colors.FAILURE)
            return TestResult("C++ Build", False, duration, stdout1 + stdout2, stderr1 + stderr2)
    
    def test_cpp_unit_tests(self) -> TestResult:
        """Run C++ unit tests"""
        start_time = time.time()
        self.log("🧪 Running C++ unit tests...", Colors.INFO)
        
        cpp_build_dir = self.root_dir / "sdk" / "cpp" / "build"
        test_vectors_file = cpp_build_dir / "test_vectors.json"
        
        # Generate test vectors if they don't exist (needed for crypto vector tests)
        if not test_vectors_file.exists():
            self.log("📝 Generating test vectors...", Colors.INFO)
            gen_success, gen_stdout, gen_stderr = self.run_command(["./generate_test_vectors"], cwd=cpp_build_dir)
            if not gen_success:
                # Don't fail the entire test suite if test vector generation fails,
                # just log a warning since not all tests depend on it
                self.log("⚠️  Test vector generation failed, some crypto vector tests may fail", Colors.WARNING)
            else:
                self.log("✅ Test vectors generated successfully", Colors.SUCCESS)
        
        # Run the C++ tests
        success, stdout, stderr = self.run_command(["./openadp_tests"], cwd=cpp_build_dir, timeout=600)
        duration = time.time() - start_time
        
        if success:
            self.log("✅ C++ unit tests: PASS", Colors.SUCCESS)
            return TestResult("C++ Unit Tests", True, duration, stdout)
        else:
            self.log("❌ C++ unit tests: FAIL", Colors.FAILURE)
            return TestResult("C++ Unit Tests", False, duration, stdout, stderr)
    
    def test_cpp_crypto_vectors(self) -> TestResult:
        """Run C++ crypto test vectors"""
        start_time = time.time()
        self.log("🔐 Running C++ crypto test vectors...", Colors.INFO)
        
        cpp_build_dir = self.root_dir / "sdk" / "cpp" / "build"
        test_vectors_file = cpp_build_dir / "test_vectors.json"
        
        # Generate test vectors if they don't exist
        if not test_vectors_file.exists():
            self.log("📝 Generating test vectors...", Colors.INFO)
            gen_success, gen_stdout, gen_stderr = self.run_command(["./generate_test_vectors"], cwd=cpp_build_dir)
            if not gen_success:
                duration = time.time() - start_time
                self.log("❌ Test vector generation: FAIL", Colors.FAILURE)
                return TestResult("C++ Crypto Vectors", False, duration, gen_stdout, gen_stderr)
            self.log("✅ Test vectors generated successfully", Colors.SUCCESS)
        
        # Run only the crypto vector tests
        success, stdout, stderr = self.run_command([
            "./openadp_tests", "--gtest_filter=CryptoVectorTest.*"
        ], cwd=cpp_build_dir)
        duration = time.time() - start_time
        
        if success:
            self.log("✅ C++ crypto vectors: PASS", Colors.SUCCESS)
            return TestResult("C++ Crypto Vectors", True, duration, stdout)
        else:
            self.log("❌ C++ crypto vectors: FAIL", Colors.FAILURE)
            return TestResult("C++ Crypto Vectors", False, duration, stdout, stderr)

    def test_cross_language_4x4_matrix(self) -> TestResult:
        """Run 4x4 cross-language compatibility tests"""
        start_time = time.time()
        self.log("🌐 Running 4x4 cross-language compatibility tests...", Colors.INFO)
        
        # Ensure all necessary tools are built
        if not self.ensure_go_tools_built():
            return TestResult("4x4 Cross-Language", False, time.time() - start_time, "", "Go tools not available")
        
        if not self.ensure_rust_tools_built():
            return TestResult("4x4 Cross-Language", False, time.time() - start_time, "", "Rust tools not available")
        
        # Ensure C++ tools are built
        cpp_build_dir = self.root_dir / "sdk" / "cpp" / "build"
        if not (cpp_build_dir / "openadp-encrypt").exists() or not (cpp_build_dir / "openadp-decrypt").exists():
            self.log("🔨 Building C++ tools for cross-language tests...", Colors.INFO)
            success, _, _ = self.run_command(["make"], cwd=cpp_build_dir)
            if not success:
                return TestResult("4x4 Cross-Language", False, time.time() - start_time, "", "C++ tools build failed")
        
        # Check if the 4x4 test exists
        test_4x4_path = self.root_dir / "tests" / "cross-language" / "test_cross_language_encrypt_decrypt_4x4.py"
        if not test_4x4_path.exists():
            # Fallback to ocrypt 4x4 test
            test_4x4_path = self.root_dir / "tests" / "cross-language" / "test_cross_language_ocrypt_4x4.py"
        
        if not test_4x4_path.exists():
            self.log("⚠️  4x4 test not found, skipping", Colors.WARNING)
            return TestResult("4x4 Cross-Language", True, time.time() - start_time, "Test not found - skipped")
        
        # Run the 4x4 cross-language test
        success, stdout, stderr = self.run_command(["python3", str(test_4x4_path)], timeout=900)
        duration = time.time() - start_time
        
        if success:
            self.log("✅ 4x4 cross-language: PASS", Colors.SUCCESS)
            return TestResult("4x4 Cross-Language", True, duration, stdout)
        else:
            self.log("❌ 4x4 cross-language: FAIL", Colors.FAILURE)
            return TestResult("4x4 Cross-Language", False, duration, stdout, stderr)

    def ensure_cpp_tools_built(self) -> bool:
        """Ensure C++ tools are built before running tests that need them"""
        self.log("⚙️  Ensuring C++ tools are built...", Colors.INFO)
        
        cpp_build_dir = self.root_dir / "sdk" / "cpp" / "build"
        if not cpp_build_dir.exists():
            self.log("📁 C++ build directory doesn't exist, building C++ tools...", Colors.WARNING)
            cpp_build_dir.mkdir(parents=True, exist_ok=True)
            success1, _, _ = self.run_command(["cmake", ".."], cwd=cpp_build_dir)
            if not success1:
                return False
            success2, _, _ = self.run_command(["make"], cwd=cpp_build_dir)
            return success2
        
        # Check for key C++ executables
        cpp_executables = ["openadp_tests", "openadp-encrypt", "openadp-decrypt", "generate_test_vectors"]
        missing_tools = []
        
        for exe in cpp_executables:
            exe_path = cpp_build_dir / exe
            if not exe_path.exists():
                missing_tools.append(exe)
        
        if missing_tools:
            self.log(f"🔨 Missing C++ tools: {missing_tools}, building C++ tools...", Colors.WARNING)
            success, _, _ = self.run_command(["make"], cwd=cpp_build_dir)
            return success
        
        self.log("✅ C++ tools are already built", Colors.SUCCESS)
        return True
    
    def test_all_cross_language_tests(self) -> TestResult:
        """Automatically discover and run all cross-language tests"""
        start_time = time.time()
        self.log("🌐 Running all cross-language tests...", Colors.INFO)
        
        # Ensure all necessary tools are built
        if not self.ensure_go_tools_built():
            return TestResult("All Cross-Language", False, time.time() - start_time, "", "Go tools not available")
        
        if not self.ensure_rust_tools_built():
            return TestResult("All Cross-Language", False, time.time() - start_time, "", "Rust tools not available")
        
        if not self.ensure_cpp_tools_built():
            return TestResult("All Cross-Language", False, time.time() - start_time, "", "C++ tools not available")
        
        # Find all test files in cross-language directory
        cross_lang_dir = self.root_dir / "tests" / "cross-language"
        if not cross_lang_dir.exists():
            return TestResult("All Cross-Language", False, time.time() - start_time, "", "Cross-language test directory not found")
        
        # Find all Python test files (excluding __pycache__ and other non-test files)
        test_files = []
        for file_path in cross_lang_dir.glob("*.py"):
            if file_path.is_file() and not file_path.name.startswith("__"):
                # Include files that start with "test_" or contain "test" in the name
                if "test" in file_path.name.lower():
                    test_files.append(file_path)
        
        if not test_files:
            return TestResult("All Cross-Language", False, time.time() - start_time, "", "No cross-language test files found")
        
        # Sort test files for consistent execution order
        test_files.sort()
        
        self.log(f"📋 Found {len(test_files)} cross-language test files:", Colors.INFO)
        for test_file in test_files:
            self.log(f"  • {test_file.name}", Colors.INFO)
        
        # Run each test file
        all_outputs = []
        all_errors = []
        failed_tests = []
        passed_tests = []
        
        for test_file in test_files:
            self.log(f"🧪 Running {test_file.name}...", Colors.INFO)
            
            # Run the test with a generous timeout for cross-language tests
            success, stdout, stderr = self.run_command(["python3", str(test_file)], timeout=1200)
            
            test_name = test_file.stem.replace("test_", "").replace("_", " ").title()
            
            if success:
                self.log(f"  ✅ {test_name}: PASS", Colors.SUCCESS)
                passed_tests.append(test_name)
                all_outputs.append(f"=== {test_name} ===\n{stdout}")
            else:
                self.log(f"  ❌ {test_name}: FAIL", Colors.FAILURE)
                failed_tests.append(test_name)
                all_outputs.append(f"=== {test_name} FAILED ===\n{stdout}")
                if stderr:
                    all_errors.append(f"=== {test_name} ERRORS ===\n{stderr}")
        
        duration = time.time() - start_time
        combined_output = "\n\n".join(all_outputs)
        combined_errors = "\n\n".join(all_errors) if all_errors else None
        
        # Summary
        total_tests = len(test_files)
        passed_count = len(passed_tests)
        failed_count = len(failed_tests)
        
        self.log(f"📊 Cross-language test summary: {passed_count}/{total_tests} passed", Colors.INFO)
        
        if failed_count == 0:
            self.log("✅ All cross-language tests: PASS", Colors.SUCCESS)
            return TestResult("All Cross-Language", True, duration, combined_output)
        else:
            self.log(f"❌ Cross-language tests: {failed_count} FAILED", Colors.FAILURE)
            error_msg = f"Failed tests: {', '.join(failed_tests)}"
            if combined_errors:
                error_msg += f"\n\nErrors:\n{combined_errors}"
            return TestResult("All Cross-Language", False, duration, combined_output, error_msg)
    
    def run_all_tests(self):
        """Run all tests based on command line arguments"""
        self.log(f"🚀 OpenADP Comprehensive Test Suite", Colors.SUCCESS)
        self.log(f"📁 Root directory: {self.root_dir}", Colors.INFO)
        self.log("=" * 60, Colors.INFO)
        
        # Ensure Go tools are built if we're running any tests that need them
        need_go_tools = not self.args.python_only or not self.args.fast
        if need_go_tools:
            if not self.ensure_go_tools_built():
                self.log("❌ Failed to build Go tools, some tests may fail", Colors.FAILURE)
        
        # Ensure C++ tools are built if we're running any tests that need them
        need_cpp_tools = not self.args.python_only and not self.args.go_only
        if need_cpp_tools:
            if not self.ensure_cpp_tools_built():
                self.log("❌ Failed to build C++ tools, some tests may fail", Colors.FAILURE)
        
        # Determine which tests to run
        tests_to_run = []
        
        if not self.args.python_only:
            tests_to_run.extend([
                ("Build", self.test_go_build),
                ("Go Unit", self.test_go_unit_tests),
            ])
            
            if not self.args.fast:
                tests_to_run.append(("Go Integration", self.test_go_integration_tests))
                
            tests_to_run.append(("Makefile", self.test_makefile_targets))
        
        # Add C++ tests
        if not self.args.python_only and not self.args.go_only:
            tests_to_run.extend([
                ("C++ Build", self.test_cpp_build),
                ("C++ Unit", self.test_cpp_unit_tests),
                ("C++ Crypto Vectors", self.test_cpp_crypto_vectors),
            ])
        
        if not self.args.go_only:
            tests_to_run.extend([
                ("Python Setup", self.test_python_sdk_setup),
                ("Python Tools", self.test_python_tools),
                ("Python Unit", self.test_python_unit_tests),
                ("JavaScript Unit", self.test_javascript_unit_tests),
            ])
            
            if not self.args.fast or self.args.cross_language:
                tests_to_run.append(("All Cross-Language", self.test_all_cross_language_tests))
        
        # Run tests
        for test_name, test_func in tests_to_run:
            try:
                result = test_func()
                self.results.append(result)
            except Exception as e:
                self.log(f"❌ {test_name}: EXCEPTION - {str(e)}", Colors.FAILURE)
                self.results.append(TestResult(test_name, False, 0, "", str(e)))
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        total_time = time.time() - self.start_time
        passed = sum(1 for r in self.results if r.success)
        failed = len(self.results) - passed
        
        print("\n" + "=" * 60)
        print(f"{Colors.SUCCESS}📊 TEST SUMMARY{Colors.RESET}")
        print("=" * 60)
        
        for result in self.results:
            status_color = Colors.SUCCESS if result.success else Colors.FAILURE
            status = "PASS" if result.success else "FAIL"
            duration_str = f"{result.duration:.2f}s"
            print(f"{status_color}{status:<4}{Colors.RESET} {result.name:<30} ({duration_str})")
        
        print("=" * 60)
        print(f"📈 Total: {len(self.results)} tests")
        print(f"{Colors.SUCCESS}✅ Passed: {passed}{Colors.RESET}")
        if failed > 0:
            print(f"{Colors.FAILURE}❌ Failed: {failed}{Colors.RESET}")
        print(f"⏱️  Total time: {total_time:.2f}s")
        
        # Print failure details
        if failed > 0:
            print(f"\n{Colors.FAILURE}💥 FAILURE DETAILS:{Colors.RESET}")
            print("=" * 60)
            for result in self.results:
                if not result.success:
                    print(f"\n{Colors.FAILURE}❌ {result.name}:{Colors.RESET}")
                    if result.error:
                        print(f"Error: {result.error}")
                    if result.output and self.args.verbose:
                        print(f"Output:\n{result.output}")
        
        # Exit with appropriate code
        sys.exit(0 if failed == 0 else 1)

def main():
    parser = argparse.ArgumentParser(description="OpenADP Comprehensive Test Runner")
    parser.add_argument("--fast", action="store_true", help="Skip slow integration tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--go-only", action="store_true", help="Only run Go tests")
    parser.add_argument("--python-only", action="store_true", help="Only run Python tests")
    parser.add_argument("--cross-language", action="store_true", help="Run all cross-language tests (overrides --fast)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    
    args = parser.parse_args()
    
    if args.go_only and args.python_only:
        print("Error: Cannot specify both --go-only and --python-only")
        sys.exit(1)
    
    runner = OpenADPTestRunner(args)
    runner.run_all_tests()

if __name__ == "__main__":
    main() 