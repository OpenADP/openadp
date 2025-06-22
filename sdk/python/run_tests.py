#!/usr/bin/env python3
"""
OpenADP Python SDK Test Runner
==============================

This script discovers and runs all Python tests in the sdk/python directory,
providing a clear status report with color-coded output.

Usage:
    python run_tests.py [options]

Options:
    -v, --verbose    Show detailed test output
    -q, --quiet      Show minimal output (only final status)
    -h, --help       Show this help message
"""

import os
import sys
import subprocess
import argparse
import time
from pathlib import Path
from typing import List, Tuple, Dict


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class TestRunner:
    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self.test_results: List[Tuple[str, bool, str]] = []
        self.start_time = time.time()
        
    def print_header(self):
        """Print the test runner header"""
        if not self.quiet:
            print(f"{Colors.BLUE}{Colors.BOLD}🧪 OpenADP Python SDK Test Runner{Colors.RESET}")
            print(f"{Colors.BLUE}{'=' * 40}{Colors.RESET}")
            print()
    
    def discover_tests(self) -> List[str]:
        """Discover all Python test files"""
        test_files = set()  # Use set to avoid duplicates
        sdk_python_dir = Path(__file__).parent
        
        # Look for test files in current directory
        for pattern in ['test_*.py', '*_test.py', 'integration_test.py']:
            test_files.update(sdk_python_dir.glob(pattern))
        
        # Look for test files in subdirectories
        for subdir in sdk_python_dir.iterdir():
            if subdir.is_dir() and not subdir.name.startswith('.') and subdir.name != '__pycache__':
                for pattern in ['test_*.py', '*_test.py']:
                    test_files.update(subdir.glob(pattern))
        
        return [str(f) for f in sorted(test_files)]
    
    def run_single_test(self, test_file: str) -> Tuple[bool, str]:
        """Run a single test file and return success status and output"""
        try:
            if not self.quiet:
                print(f"🔄 Running {os.path.basename(test_file)}...", end=" ", flush=True)
            
            # Run the test
            result = subprocess.run(
                [sys.executable, test_file],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout per test
            )
            
            success = result.returncode == 0
            output = result.stdout + result.stderr
            
            if not self.quiet:
                if success:
                    print(f"{Colors.GREEN}✅ PASS{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ FAIL{Colors.RESET}")
            
            return success, output
            
        except subprocess.TimeoutExpired:
            if not self.quiet:
                print(f"{Colors.RED}⏰ TIMEOUT{Colors.RESET}")
            return False, "Test timed out after 5 minutes"
        except Exception as e:
            if not self.quiet:
                print(f"{Colors.RED}💥 ERROR{Colors.RESET}")
            return False, f"Exception running test: {str(e)}"
    
    def run_unittest_discovery(self) -> Tuple[bool, str]:
        """Run unittest discovery for any unittest-based tests"""
        try:
            if not self.quiet:
                print(f"🔄 Running unittest discovery...", end=" ", flush=True)
            
            result = subprocess.run(
                [sys.executable, '-m', 'unittest', 'discover', '-s', '.', '-p', 'test*.py'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            success = result.returncode == 0
            output = result.stdout + result.stderr
            
            if not self.quiet:
                if success:
                    print(f"{Colors.GREEN}✅ PASS{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ FAIL{Colors.RESET}")
            
            return success, output
            
        except subprocess.TimeoutExpired:
            if not self.quiet:
                print(f"{Colors.RED}⏰ TIMEOUT{Colors.RESET}")
            return False, "Unittest discovery timed out after 5 minutes"
        except Exception as e:
            if not self.quiet:
                print(f"{Colors.RED}💥 ERROR{Colors.RESET}")
            return False, f"Exception running unittest discovery: {str(e)}"
    
    def run_pytest_if_available(self) -> Tuple[bool, str]:
        """Run pytest if it's available and there are test files"""
        try:
            # Check if pytest is available
            subprocess.run([sys.executable, '-m', 'pytest', '--version'], 
                         capture_output=True, check=True)
            
            if not self.quiet:
                print(f"🔄 Running pytest...", end=" ", flush=True)
            
            result = subprocess.run(
                [sys.executable, '-m', 'pytest', '.', '-v' if self.verbose else '-q'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            success = result.returncode == 0
            output = result.stdout + result.stderr
            
            if not self.quiet:
                if success:
                    print(f"{Colors.GREEN}✅ PASS{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ FAIL{Colors.RESET}")
            
            return success, output
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            # pytest not available
            return True, "pytest not available (skipped)"
        except subprocess.TimeoutExpired:
            if not self.quiet:
                print(f"{Colors.RED}⏰ TIMEOUT{Colors.RESET}")
            return False, "pytest timed out after 5 minutes"
        except Exception as e:
            if not self.quiet:
                print(f"{Colors.RED}💥 ERROR{Colors.RESET}")
            return False, f"Exception running pytest: {str(e)}"
    
    def run_all_tests(self):
        """Run all discovered tests"""
        # Discover test files
        test_files = self.discover_tests()
        
        if not self.quiet:
            print(f"📁 Discovered {len(test_files)} test files")
            print()
        
        # Run individual test files
        for test_file in test_files:
            success, output = self.run_single_test(test_file)
            self.test_results.append((os.path.basename(test_file), success, output))
            
            if self.verbose and output.strip():
                print(f"{Colors.YELLOW}--- Output from {os.path.basename(test_file)} ---{Colors.RESET}")
                print(output)
                print(f"{Colors.YELLOW}--- End output ---{Colors.RESET}")
                print()
        
        # Run unittest discovery (if no individual test files found or as additional coverage)
        if not test_files:
            success, output = self.run_unittest_discovery()
            self.test_results.append(("unittest discovery", success, output))
            
            if self.verbose and output.strip():
                print(f"{Colors.YELLOW}--- Unittest discovery output ---{Colors.RESET}")
                print(output)
                print(f"{Colors.YELLOW}--- End output ---{Colors.RESET}")
                print()
        
        # Only run pytest if we want comprehensive coverage or there are pytest-specific features
        # Skip pytest if we already ran the test files individually to avoid duplication
        if not test_files or self.verbose:
            success, output = self.run_pytest_if_available()
            if "pytest not available" not in output:
                self.test_results.append(("pytest", success, output))
                
                if self.verbose and output.strip():
                    print(f"{Colors.YELLOW}--- Pytest output ---{Colors.RESET}")
                    print(output)
                    print(f"{Colors.YELLOW}--- End output ---{Colors.RESET}")
                    print()
    
    def print_summary(self):
        """Print the final test summary"""
        if not self.quiet:
            print()
            print(f"{Colors.BLUE}{Colors.BOLD}📊 Test Summary{Colors.RESET}")
            print(f"{Colors.BLUE}{'=' * 20}{Colors.RESET}")
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for _, success, _ in self.test_results if success)
        failed_tests = total_tests - passed_tests
        
        if not self.quiet:
            for test_name, success, _ in self.test_results:
                status_icon = "✅" if success else "❌"
                status_color = Colors.GREEN if success else Colors.RED
                print(f"  {status_icon} {test_name}: {status_color}{'PASS' if success else 'FAIL'}{Colors.RESET}")
            print()
        
        # Calculate elapsed time
        elapsed_time = time.time() - self.start_time
        
        # Print final status
        if failed_tests == 0:
            print(f"{Colors.GREEN}{Colors.BOLD}🎉 ALL TESTS PASSED! 🎉{Colors.RESET}")
            print(f"{Colors.GREEN}Status: GREEN ✅{Colors.RESET}")
            if not self.quiet:
                print(f"{Colors.GREEN}Ran {total_tests} test(s) in {elapsed_time:.2f}s{Colors.RESET}")
        else:
            print(f"{Colors.RED}{Colors.BOLD}❌ SOME TESTS FAILED ❌{Colors.RESET}")
            print(f"{Colors.RED}Status: RED ❌{Colors.RESET}")
            if not self.quiet:
                print(f"{Colors.RED}Passed: {passed_tests}, Failed: {failed_tests} (Total: {total_tests}){Colors.RESET}")
                print(f"{Colors.RED}Ran {total_tests} test(s) in {elapsed_time:.2f}s{Colors.RESET}")
        
        # Show failed test details if not verbose
        if failed_tests > 0 and not self.verbose and not self.quiet:
            print()
            print(f"{Colors.YELLOW}💡 Run with -v/--verbose to see detailed output{Colors.RESET}")
        
        return failed_tests == 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="OpenADP Python SDK Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed test output')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Show minimal output (only final status)')
    
    args = parser.parse_args()
    
    # Change to the script directory
    os.chdir(Path(__file__).parent)
    
    # Create and run test runner
    runner = TestRunner(verbose=args.verbose, quiet=args.quiet)
    
    try:
        runner.print_header()
        runner.run_all_tests()
        success = runner.print_summary()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}🛑 Test run interrupted by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}💥 Unexpected error: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main() 