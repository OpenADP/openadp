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
            "make", "clean", "build", "build-server", "build-encrypt", "build-decrypt"
        ])
        duration = time.time() - start_time
        
        if success:
            self.log("✅ Go build: PASS", Colors.SUCCESS)
            return TestResult("Go Build", True, duration, stdout)
        else:
            self.log("❌ Go build: FAIL", Colors.FAILURE)
            return TestResult("Go Build", False, duration, stdout, stderr)
    
    def test_go_unit_tests(self) -> TestResult:
        """Run Go unit tests"""
        start_time = time.time()
        self.log("🧪 Running Go unit tests...", Colors.INFO)
        
        success, stdout, stderr = self.run_command(["go", "test", "./pkg/...", "-v"])
        duration = time.time() - start_time
        
        if success:
            self.log("✅ Go unit tests: PASS", Colors.SUCCESS)
            return TestResult("Go Unit Tests", True, duration, stdout)
        else:
            self.log("❌ Go unit tests: FAIL", Colors.FAILURE)
            return TestResult("Go Unit Tests", False, duration, stdout, stderr)
    
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
        
        # Check if venv exists and is activated
        venv_path = self.root_dir / "venv"
        if not venv_path.exists():
            return TestResult("Python SDK Setup", False, 0, "", "Virtual environment not found")
        
        # Test import of openadp module
        success, stdout, stderr = self.run_command([
            "python", "-c", 
            "import sys; sys.path.insert(0, 'sdk/python'); import openadp; print('OpenADP Python SDK imported successfully')"
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
        
        python_test_dir = self.root_dir / "tests" / "python"
        success, stdout, stderr = self.run_command([
            "python", "-m", "pytest", ".", "-v", "--tb=short"
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
            
            # Test version flags
            success1, _, _ = self.run_command(["python", "tools/openadp-encrypt.py", "-version"])
            success2, _, _ = self.run_command(["python", "tools/openadp-decrypt.py", "-version"])
            
            duration = time.time() - start_time
            
            if success1 and success2:
                self.log("✅ Python tools: PASS", Colors.SUCCESS)
                return TestResult("Python Tools", True, duration, "Version checks passed")
            else:
                self.log("❌ Python tools: FAIL", Colors.FAILURE)
                return TestResult("Python Tools", False, duration, "", "Version checks failed")
    
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
            success, _, _ = self.run_command(["make", "build-server", "build-encrypt", "build-decrypt"])
            return success
        
        # Check for key executables
        key_executables = ["openadp-server", "openadp-encrypt", "openadp-decrypt"]
        missing_tools = []
        
        for exe in key_executables:
            exe_path = build_dir / exe
            if not exe_path.exists():
                missing_tools.append(exe)
        
        if missing_tools:
            self.log(f"🔨 Missing tools: {missing_tools}, building all tools...", Colors.WARNING)
            success, _, _ = self.run_command(["make", "build-server", "build-encrypt", "build-decrypt"])
            return success
        
        self.log("✅ Go tools are already built", Colors.SUCCESS)
        return True
    
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
        
        if not self.args.go_only:
            tests_to_run.extend([
                ("Python Setup", self.test_python_sdk_setup),
                ("Python Tools", self.test_python_tools),
                ("Python Unit", self.test_python_unit_tests),
            ])
            
            if not self.args.fast:
                tests_to_run.append(("Cross-Language", self.test_cross_language_compatibility))
        
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
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    
    args = parser.parse_args()
    
    if args.go_only and args.python_only:
        print("Error: Cannot specify both --go-only and --python-only")
        sys.exit(1)
    
    runner = OpenADPTestRunner(args)
    runner.run_all_tests()

if __name__ == "__main__":
    main() 