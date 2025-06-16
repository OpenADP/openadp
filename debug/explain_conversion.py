#!/usr/bin/env python3
"""Explain the byte-to-integer conversion issue."""

y = b'123456789012345678901234567890123456789012345678901234567890'
print(f'Bytes: {y}')
print(f'Length: {len(y)} bytes')
print()

# Each character as ASCII value
print('ASCII values of first few characters:')
for i in range(5):
    print(f'  y[{i}] = {y[i]} (ASCII for \'{chr(y[i])}\')')
print()

# Convert to integer
y_int = int.from_bytes(y, 'big')
print(f'As big integer: {y_int}')
print(f'Bit length: {y_int.bit_length()} bits')
print(f'Byte length needed: {(y_int.bit_length() + 7) // 8} bytes')
print()

# Show why this is huge
print("Why this creates a huge number:")
print("Each ASCII '1' = 49, '2' = 50, '3' = 51, etc.")
print("When interpreted as big-endian bytes, this becomes:")
print("49 * 256^59 + 50 * 256^58 + 51 * 256^57 + ... = HUGE number")
print()

# What we probably should do instead for testing
print("Better approach for testing:")
test_secret = b'A' * 32  # 32 bytes of 'A'
test_int = int.from_bytes(test_secret, 'big')
print(f'32 bytes of "A": {test_secret}')
print(f'As integer: {test_int}')
print(f'Bit length: {test_int.bit_length()} bits')
print(f'Fits in 32 bytes: {test_int.bit_length() <= 256}') 