#!/usr/bin/env python3
"""
OpenADP Comprehensive Test Runner

This script discovers and runs all tests in the OpenADP project:
- Unit tests in tests/unit/
- Integration tests in tests/integration/
- E2E tests in tests/e2e/
- Auth tests in tests/auth/
- Co-located unit tests (e.g., openadp/auth/test_*.py)
- Standalone test functions in modules

Usage:
    python run_tests.py [options]
    
Options:
    --unit-only         Run only unit tests
    --integration-only  Run only integration tests
    --e2e-only         Run only E2E tests
    --auth-only        Run only authentication tests
    --co-located-only  Run only co-located tests
    --verbose          Verbose output
    --coverage         Run with coverage reporting
    --parallel         Run tests in parallel (where safe)
    --fast             Skip slow integration tests
    --help             Show this help message
"""

import sys
import os
import subprocess
import argparse
import time
from pathlib import Path
from typing import List, Dict, Optional

class TestRunner:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_results: Dict[str, bool] = {}
        self.start_time = time.time()
        
    def run_command(self, cmd: List[str], description: str, cwd: Optional[Path] = None) -> bool:
        """Run a command and return True if successful"""
        print(f"\n{'='*60}")
        print(f"🧪 {description}")
        print(f"{'='*60}")
        print(f"Command: {' '.join(cmd)}")
        print(f"Working directory: {cwd or self.project_root}")
        print()
        
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd or self.project_root,
                capture_output=False,
                text=True
            )
            
            # Handle pytest exit codes
            # 0: All tests passed
            # 5: No tests collected (this is OK for E2E tests when all are marked as manual)
            success = result.returncode == 0 or (result.returncode == 5 and "End-to-End" in description)
            
            self.test_results[description] = success
            
            if success:
                if result.returncode == 5 and "End-to-End" in description:
                    print(f"✅ {description} - PASSED (all tests deselected as manual)")
                else:
                    print(f"✅ {description} - PASSED")
            else:
                print(f"❌ {description} - FAILED (exit code: {result.returncode})")
                
            return success
            
        except Exception as e:
            print(f"❌ {description} - ERROR: {e}")
            self.test_results[description] = False
            return False
    
    def run_unit_tests(self, verbose: bool = False, coverage: bool = False) -> bool:
        """Run all unit tests"""
        cmd = ["python", "-m", "pytest"]
        
        if verbose:
            cmd.append("-v")
        if coverage:
            cmd.extend(["--cov=openadp", "--cov=server", "--cov=client"])
            
        cmd.append("tests/unit/")
        
        return self.run_command(cmd, "Unit Tests (tests/unit/)")
    
    def run_auth_tests(self, verbose: bool = False) -> bool:
        """Run authentication tests"""
        cmd = ["python", "-m", "pytest"]
        
        if verbose:
            cmd.append("-v")
            
        cmd.append("tests/auth/")
        
        return self.run_command(cmd, "Authentication Tests (tests/auth/)")
    
    def run_co_located_tests(self, verbose: bool = False) -> bool:
        """Run co-located unit tests"""
        cmd = ["python", "-m", "pytest"]
        
        if verbose:
            cmd.append("-v")
            
        # Use explicit file paths instead of glob pattern
        cmd.extend(["openadp/auth/test_dpop.py", "openadp/auth/test_keys.py"])
        
        return self.run_command(cmd, "Co-located Unit Tests (openadp/auth/)")
    
    def run_integration_tests(self, verbose: bool = False, fast: bool = False) -> bool:
        """Run integration tests"""
        cmd = ["python", "-m", "pytest"]
        
        if verbose:
            cmd.append("-v")
        if fast:
            cmd.extend(["-m", "not slow"])
            
        cmd.append("tests/integration/")
        
        return self.run_command(cmd, "Integration Tests (tests/integration/)")
    
    def run_e2e_tests(self, verbose: bool = False) -> bool:
        """Run end-to-end tests"""
        cmd = ["python", "-m", "pytest"]
        
        if verbose:
            cmd.append("-v")
            
        cmd.append("tests/e2e/")
        
        return self.run_command(cmd, "End-to-End Tests (tests/e2e/)")
    
    def run_standalone_tests(self, verbose: bool = False) -> bool:
        """Run standalone test functions in modules"""
        success = True
        
        try:
            print(f"\n{'='*60}")
            print(f"🧪 Standalone Tests (noise_nk module)")
            print(f"{'='*60}")
            
            sys.path.insert(0, str(self.project_root))
            from openadp.noise_nk import test_noise_nk
            
            print("Running test_noise_nk()...")
            test_noise_nk()
            print("✅ test_noise_nk() - PASSED")
            self.test_results["Standalone Tests (noise_nk)"] = True
            
        except Exception as e:
            print(f"❌ test_noise_nk() - FAILED: {e}")
            self.test_results["Standalone Tests (noise_nk)"] = False
            success = False
            
        return success
    
    def check_test_dependencies(self) -> bool:
        """Check if test dependencies are available"""
        print("🔍 Checking test dependencies...")
        
        try:
            import pytest
            print("✅ pytest available")
        except ImportError:
            print("❌ pytest not available - install with: pip install pytest")
            return False
            
        try:
            import pytest_cov
            print("✅ pytest-cov available")
        except ImportError:
            print("⚠️  pytest-cov not available - coverage reporting disabled")
            
        return True
    
    def print_summary(self):
        """Print test results summary"""
        elapsed = time.time() - self.start_time
        
        print(f"\n{'='*80}")
        print(f"🏁 TEST SUMMARY")
        print(f"{'='*80}")
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result)
        failed_tests = total_tests - passed_tests
        
        for test_name, result in self.test_results.items():
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"{status:12} {test_name}")
        
        print(f"\n{'='*80}")
        print(f"Total: {total_tests} test suites")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        print(f"Elapsed Time: {elapsed:.1f}s")
        
        if failed_tests == 0:
            print(f"\n🎉 ALL TESTS PASSED! Project status: GREEN ✅")
            return True
        else:
            print(f"\n💥 {failed_tests} test suite(s) failed. Project status: RED ❌")
            return False

def main():
    parser = argparse.ArgumentParser(
        description="OpenADP Comprehensive Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument("--unit-only", action="store_true", help="Run only unit tests")
    parser.add_argument("--integration-only", action="store_true", help="Run only integration tests")
    parser.add_argument("--e2e-only", action="store_true", help="Run only E2E tests")
    parser.add_argument("--auth-only", action="store_true", help="Run only authentication tests")
    parser.add_argument("--co-located-only", action="store_true", help="Run only co-located tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--coverage", action="store_true", help="Run with coverage reporting")
    parser.add_argument("--parallel", action="store_true", help="Run tests in parallel (where safe)")
    parser.add_argument("--fast", action="store_true", help="Skip slow integration tests")
    
    args = parser.parse_args()
    
    runner = TestRunner()
    
    print("🚀 OpenADP Comprehensive Test Runner")
    print(f"Project root: {runner.project_root}")
    
    # Check dependencies
    if not runner.check_test_dependencies():
        sys.exit(1)
    
    success = True
    
    # Determine which tests to run
    run_all = not any([
        args.unit_only, args.integration_only, args.e2e_only, 
        args.auth_only, args.co_located_only
    ])
    
    if run_all or args.unit_only:
        success &= runner.run_unit_tests(args.verbose, args.coverage)
    
    if run_all or args.auth_only:
        success &= runner.run_auth_tests(args.verbose)
    
    if run_all or args.co_located_only:
        success &= runner.run_co_located_tests(args.verbose)
    
    if run_all or args.integration_only:
        success &= runner.run_integration_tests(args.verbose, args.fast)
    
    if run_all or args.e2e_only:
        success &= runner.run_e2e_tests(args.verbose)
    
    if run_all:
        success &= runner.run_standalone_tests(args.verbose)
    
    # Print summary and exit
    overall_success = runner.print_summary()
    sys.exit(0 if overall_success else 1)

if __name__ == "__main__":
    main() 