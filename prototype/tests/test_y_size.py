#!/usr/bin/env python3
import sys
import os
import secrets

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import crypto
from openadp import sharing

s = secrets.randbelow(crypto.q)
shares = sharing.make_random_shares(s, 2, 2)
y = shares[0][1]

print(f'Y value: {y}')
print(f'Y bytes needed: {y.bit_length()} bits, {(y.bit_length() + 7) // 8} bytes')
print(f'Max value that fits in 32 bytes: {2**256 - 1}')
print(f'Y < 2^256: {y < 2**256}')

try:
    y_bytes = int.to_bytes(y, 32, 'little')
    print(f'✅ Conversion successful: {len(y_bytes)} bytes')
except Exception as e:
    print(f'❌ Conversion failed: {e}') 