#!/usr/bin/env python3
"""Debug script to see what y parameter looks like when converted."""

# Test what happens when we convert bytes to string
y_bytes = b"123456789012345678901234567890123456789012345678901234567890"
y_str = str(y_bytes)

print(f"Original bytes: {y_bytes}")
print(f"Length of bytes: {len(y_bytes)}")
print(f"str(y_bytes): {y_str}")
print(f"Length of str: {len(y_str)}")

# Try to convert back to int (this will fail)
try:
    y_int = int(y_str)
    print(f"Converted to int: {y_int}")
except ValueError as e:
    print(f"❌ ValueError: {e}")

# What we should do instead:
# Convert bytes to a big integer
y_int_correct = int.from_bytes(y_bytes, byteorder='big')
print(f"\nCorrect conversion:")
print(f"int.from_bytes(y_bytes, 'big'): {y_int_correct}")
print(f"Bit length: {y_int_correct.bit_length()}")

# Convert back to string for transmission
y_str_correct = str(y_int_correct)
print(f"str(y_int_correct): {y_str_correct[:50]}...")
print(f"Length of correct string: {len(y_str_correct)}")

# Test server conversion
try:
    y_int_from_server = int(y_str_correct)
    print(f"✅ Server can convert: {str(y_int_from_server)[:50]}...")
    
    # Convert back to bytes
    y_bytes_recovered = y_int_from_server.to_bytes(32, 'little')
    print(f"✅ Recovered bytes length: {len(y_bytes_recovered)}")
    
except Exception as e:
    print(f"❌ Server conversion failed: {e}") 