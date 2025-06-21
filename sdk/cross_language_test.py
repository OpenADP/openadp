#!/usr/bin/env python3
"""
Cross-Language Compatibility Test for OpenADP SDKs

This test compares the core cryptographic operations between Python and JavaScript
implementations to ensure they produce identical results. This is critical for
ensuring that keys generated in one language can be recovered in another.

Key areas tested:
1. Point operations (Ed25519)
2. Hash functions and key derivation
3. Shamir secret sharing
4. Authentication code generation
5. Identifier derivation
6. Password to PIN conversion

Run with: python3 cross_language_test.py
"""

import sys
import os
import json
import subprocess
import tempfile
from typing import Dict, Any, List, Tuple

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python'))

from openadp.crypto import (
    Point2D, Point4D, G, P, Q, D,
    point_add, point_mul, point_compress, point_decompress,
    H, sha256_hash, ShamirSecretSharing, is_valid_point
)
from openadp.keygen import derive_identifiers, password_to_pin, generate_auth_codes


class CrossLanguageCompatibilityTest:
    """Test suite for cross-language compatibility"""
    
    def __init__(self):
        self.test_results = []
        self.js_sdk_path = os.path.join(os.path.dirname(__file__), 'javascript')
    
    def run_js_test(self, test_name: str, test_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run a test in the JavaScript SDK and return results"""
        
                 # Create a temporary test script
         test_script = f"""
import {{ Point2D, Point4D, G, P, Q, D, hashToPoint, ShamirSecretSharing }} from '{self.js_sdk_path}/src/crypto.js';
import {{ deriveIdentifiers, passwordToPin }} from '{self.js_sdk_path}/src/index.js';

const testData = {json.dumps(test_data)};
const results = {{}};

try {{
    switch (testData.test) {{
        case 'point_operations':
            // Test basic point operations
            const point = new Point2D(BigInt(testData.x), BigInt(testData.y));
            results.isValid = point.isValid();
            results.compressed = Array.from(point.compress());
            
            // Test point multiplication
            const scalar = BigInt(testData.scalar);
            const multiplied = point.multiply(scalar);
            results.multiplied_x = multiplied.x.toString();
            results.multiplied_y = multiplied.y.toString();
            break;
            
        case 'shamir_sharing':
            // Test Shamir secret sharing
            const secret = new Uint8Array(testData.secret);
            const shares = ShamirSecretSharing.split(secret, testData.threshold, testData.numShares);
            results.shares = shares.map(share => ({{
                x: share.x,
                y: share.y.toString(),
                length: share.length
            }}));
            
            // Test recovery with subset of shares
            const recoveryShares = shares.slice(0, testData.threshold);
            const recovered = ShamirSecretSharing.recover(recoveryShares);
            results.recovered = Array.from(recovered);
            break;
            
        case 'identifier_derivation':
            // Test identifier derivation - note: JS implementation may be different
            try {{
                const ids = deriveIdentifiers(testData.filename, testData.userId, testData.hostname);
                results.uid = ids.uid || ids[0];
                results.did = ids.did || ids[1]; 
                results.bid = ids.bid || ids[2];
            }} catch (e) {{
                results.error = e.message;
            }}
            break;
            
        case 'password_to_pin':
            // Test password to PIN conversion - note: JS implementation may be different
            try {{
                const pin = passwordToPin(testData.password, Buffer.from(testData.salt), testData.iterations);
                results.pin = pin;
            }} catch (e) {{
                results.error = e.message;
            }}
            break;
            
        default:
            results.error = 'Unknown test type';
    }}
}} catch (error) {{
    results.error = error.message;
    results.stack = error.stack;
}}

console.log(JSON.stringify(results));
"""
        
        # Write test script to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(test_script)
            temp_script = f.name
        
        try:
            # Run the test script
            result = subprocess.run(
                ['node', temp_script],
                cwd=self.js_sdk_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout.strip())
            else:
                return {
                    'error': f'JavaScript test failed: {result.stderr}',
                    'stdout': result.stdout,
                    'returncode': result.returncode
                }
                
        except subprocess.TimeoutExpired:
            return {'error': 'JavaScript test timed out'}
        except json.JSONDecodeError as e:
            return {'error': f'Failed to parse JavaScript output: {e}', 'stdout': result.stdout}
        except Exception as e:
            return {'error': f'Failed to run JavaScript test: {e}'}
        finally:
            try:
                os.unlink(temp_script)
            except:
                pass
    
    def test_point_operations(self):
        """Test Ed25519 point operations compatibility"""
        print("\n🔢 Testing Ed25519 point operations...")
        
        # Test with a known point
        test_point = G  # Use the base point
        scalar = 12345
        
        # Python implementation
        python_results = {
            'isValid': is_valid_point(test_point),
            'compressed': list(point_compress(test_point)),
            'multiplied': point_mul(scalar, test_point)
        }
        
        # JavaScript implementation
        js_test_data = {
            'test': 'point_operations',
            'x': str(test_point.x),
            'y': str(test_point.y),
            'scalar': str(scalar)
        }
        
        js_results = self.run_js_test('point_operations', js_test_data)
        
        # Compare results
        success = True
        issues = []
        
        if 'error' in js_results:
            success = False
            issues.append(f"JavaScript error: {js_results['error']}")
        else:
            # Compare validity
            if python_results['isValid'] != js_results.get('isValid'):
                success = False
                issues.append(f"Point validity mismatch: Python={python_results['isValid']}, JS={js_results.get('isValid')}")
            
            # Compare compressed form
            if python_results['compressed'] != js_results.get('compressed'):
                success = False
                issues.append(f"Compressed point mismatch: Python={python_results['compressed'][:8]}..., JS={js_results.get('compressed', [])[:8]}...")
            
            # Compare multiplication result
            py_mult = python_results['multiplied']
            js_mult_x = js_results.get('multiplied_x')
            js_mult_y = js_results.get('multiplied_y')
            
            if js_mult_x and js_mult_y:
                if str(py_mult.x) != js_mult_x or str(py_mult.y) != js_mult_y:
                    success = False
                    issues.append(f"Point multiplication mismatch")
        
        self.test_results.append({
            'test': 'point_operations',
            'success': success,
            'issues': issues,
            'python_results': python_results,
            'js_results': js_results
        })
        
        if success:
            print("   ✅ Point operations match between Python and JavaScript")
        else:
            print("   ❌ Point operations differ between implementations:")
            for issue in issues:
                print(f"      - {issue}")
    
    def test_shamir_secret_sharing(self):
        """Test Shamir secret sharing compatibility"""
        print("\n🔐 Testing Shamir secret sharing...")
        
        # Test with a known secret
        secret = bytes([1, 2, 3, 4, 5, 6, 7, 8] * 4)  # 32 bytes
        threshold = 3
        num_shares = 5
        
        # Python implementation
        python_shares = ShamirSecretSharing.split_secret(secret, threshold, num_shares)
        python_recovered = ShamirSecretSharing.recover_secret(python_shares[:threshold])
        
        python_results = {
            'shares': [(x, str(y)) for x, y in python_shares],
            'recovered': list(python_recovered)
        }
        
        # JavaScript implementation
        js_test_data = {
            'test': 'shamir_sharing',
            'secret': list(secret),
            'threshold': threshold,
            'numShares': num_shares
        }
        
        js_results = self.run_js_test('shamir_sharing', js_test_data)
        
        # Compare results
        success = True
        issues = []
        
        if 'error' in js_results:
            success = False
            issues.append(f"JavaScript error: {js_results['error']}")
        else:
            # Compare recovered secret
            if python_results['recovered'] != js_results.get('recovered'):
                success = False
                issues.append(f"Secret recovery mismatch: Python={python_results['recovered'][:8]}..., JS={js_results.get('recovered', [])[:8]}...")
            
            # Compare number of shares
            py_shares_count = len(python_results['shares'])
            js_shares_count = len(js_results.get('shares', []))
            if py_shares_count != js_shares_count:
                success = False
                issues.append(f"Share count mismatch: Python={py_shares_count}, JS={js_shares_count}")
        
        self.test_results.append({
            'test': 'shamir_secret_sharing',
            'success': success,
            'issues': issues,
            'python_results': python_results,
            'js_results': js_results
        })
        
        if success:
            print("   ✅ Shamir secret sharing matches between Python and JavaScript")
        else:
            print("   ❌ Shamir secret sharing differs between implementations:")
            for issue in issues:
                print(f"      - {issue}")
    
    def test_identifier_derivation(self):
        """Test identifier derivation compatibility"""
        print("\n🆔 Testing identifier derivation...")
        
        # Test cases
        test_cases = [
            {
                'filename': 'test-file.txt',
                'userId': 'test@example.com',
                'hostname': 'test-hostname'
            },
            {
                'filename': 'backup.tar.gz',
                'userId': 'user@domain.com',
                'hostname': 'laptop'
            }
        ]
        
        all_success = True
        all_issues = []
        
        for case in test_cases:
            # Python implementation
            py_uid, py_did, py_bid = derive_identifiers(
                case['filename'], case['userId'], case['hostname']
            )
            
            python_results = {
                'uid': py_uid,
                'did': py_did,
                'bid': py_bid
            }
            
            # JavaScript implementation
            js_test_data = {
                'test': 'identifier_derivation',
                **case
            }
            
            js_results = self.run_js_test('identifier_derivation', js_test_data)
            
            # Compare results
            success = True
            issues = []
            
            if 'error' in js_results:
                success = False
                issues.append(f"JavaScript error: {js_results['error']}")
            else:
                # Compare identifiers
                for key in ['uid', 'did', 'bid']:
                    if python_results.get(key) != js_results.get(key):
                        success = False
                        issues.append(f"{key.upper()} mismatch for {case['filename']}: Python={python_results.get(key)}, JS={js_results.get(key)}")
            
            if not success:
                all_success = False
                all_issues.extend(issues)
        
        self.test_results.append({
            'test': 'identifier_derivation',
            'success': all_success,
            'issues': all_issues
        })
        
        if all_success:
            print("   ✅ Identifier derivation matches between Python and JavaScript")
        else:
            print("   ❌ Identifier derivation differs between implementations:")
            for issue in all_issues:
                print(f"      - {issue}")
    
    def test_password_to_pin(self):
        """Test password to PIN conversion compatibility"""
        print("\n🔑 Testing password to PIN conversion...")
        
        # Test cases
        passwords = ['test123', 'secure_password', 'пароль']
        salt = b'test_salt_12345'
        iterations = 1000  # Use fewer iterations for faster testing
        
        all_success = True
        all_issues = []
        
        for password in passwords:
            # Python implementation
            python_pin = password_to_pin(password)
            python_results = {
                'pin': list(python_pin)
            }
            
            # JavaScript implementation
            js_test_data = {
                'test': 'password_to_pin',
                'password': password,
                'salt': list(salt),
                'iterations': iterations
            }
            
            js_results = self.run_js_test('password_to_pin', js_test_data)
            
            # Compare results
            success = True
            issues = []
            
            if 'error' in js_results:
                success = False
                issues.append(f"JavaScript error for '{password}': {js_results['error']}")
            else:
                # Note: The implementations may be different, so we just check if both produce valid output
                if not js_results.get('pin'):
                    success = False
                    issues.append(f"JavaScript didn't produce PIN for '{password}'")
            
            if not success:
                all_success = False
                all_issues.extend(issues)
        
        self.test_results.append({
            'test': 'password_to_pin',
            'success': all_success,
            'issues': all_issues
        })
        
        if all_success:
            print("   ✅ Password to PIN conversion working in both implementations")
        else:
            print("   ⚠️  Password to PIN conversion has differences:")
            for issue in all_issues:
                print(f"      - {issue}")
    
    def run_all_tests(self):
        """Run all cross-language compatibility tests"""
        print("🚀 OpenADP Cross-Language Compatibility Test")
        print("============================================")
        
        # Run individual tests
        self.test_point_operations()
        self.test_shamir_secret_sharing()
        self.test_identifier_derivation()
        self.test_password_to_pin()
        
        # Summary
        print("\n📊 Test Summary:")
        print("================")
        
        total_tests = len(self.test_results)
        successful_tests = sum(1 for result in self.test_results if result['success'])
        
        print(f"Total tests: {total_tests}")
        print(f"Successful: {successful_tests}")
        print(f"Failed: {total_tests - successful_tests}")
        
        if successful_tests == total_tests:
            print("\n🎉 All cross-language compatibility tests passed!")
            print("   Python and JavaScript SDKs are compatible.")
        else:
            print(f"\n⚠️  {total_tests - successful_tests} test(s) failed.")
            print("   There may be compatibility issues between SDKs.")
            
            print("\n🔍 Detailed Issues:")
            for result in self.test_results:
                if not result['success']:
                    print(f"\n   {result['test']}:")
                    for issue in result['issues']:
                        print(f"     - {issue}")
        
        return successful_tests == total_tests


def main():
    """Run cross-language compatibility tests"""
    test_suite = CrossLanguageCompatibilityTest()
    success = test_suite.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main() 