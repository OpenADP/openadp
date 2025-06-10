#!/usr/bin/env python3
"""Debug the integer to bytes conversion issue."""

import crypto
import sharing
import secrets

# Test with actual secret sharing
s = secrets.randbelow(crypto.q)
shares = sharing.make_random_shares(s, 2, 2)

print(f"crypto.q = {crypto.q}")
print(f"crypto.q bits: {crypto.q.bit_length()}")
print(f"Max value for 32 bytes: {2**256 - 1}")
print(f"crypto.q < 2^256: {crypto.q < 2**256}")
print()

for i, (x, y) in enumerate(shares):
    print(f"Share {i+1}: x={x}, y={y}")
    print(f"  Y bits: {y.bit_length()}")
    print(f"  Y < 2^256: {y < 2**256}")
    print(f"  Y < crypto.q: {y < crypto.q}")
    
    # Test conversion
    try:
        # Calculate minimum bytes needed
        bytes_needed = (y.bit_length() + 7) // 8
        print(f"  Minimum bytes needed: {bytes_needed}")
        
        # Try to convert to exactly 32 bytes
        y_bytes = int.to_bytes(y, 32, "little")
        print(f"  ✅ Conversion to 32 bytes successful: {len(y_bytes)} bytes")
        
        # Test if we can convert back
        y_recovered = int.from_bytes(y_bytes, "little")
        print(f"  ✅ Round-trip successful: {y == y_recovered}")
        
        # Test with different byte sizes
        for byte_size in [31, 32, 33]:
            try:
                test_bytes = int.to_bytes(y, byte_size, "little")
                print(f"  ✅ Conversion to {byte_size} bytes: OK")
            except OverflowError as e:
                print(f"  ❌ Conversion to {byte_size} bytes: {e}")
                
    except Exception as e:
        print(f"  ❌ Conversion failed: {e}")
    print()

# Test the specific validation logic
print("Testing server validation logic:")
for i, (x, y) in enumerate(shares):
    y_str = str(y)
    print(f"Share {i+1} as string: length={len(y_str)}")
    
    # Simulate the JSON-RPC server conversion
    try:
        y_int = int(y_str)
        y_bytes = int.to_bytes(y_int, 32, "little")
        validation_result = len(y_bytes) <= 32
        print(f"  JSON-RPC conversion successful: {len(y_bytes)} bytes, validation: {validation_result}")
    except Exception as e:
        print(f"  JSON-RPC conversion failed: {e}") 