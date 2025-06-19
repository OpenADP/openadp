#!/usr/bin/env python3
import sys
import os
import secrets

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from server import server
from openadp import database, crypto

# Test database lookup format
db = database.Database('test_recover.db')

uid = b'test'
did = b'device'  
bid = b'backup'
version = 1
x = 1
y = b'\x01' * 32

print("Inserting test data...")
db.insert(uid, did, bid, "test_auth_code", version, x, y, 0, 10, 0)

print("Looking up data...")
result = db.lookup(uid, did, bid)
print(f'Lookup result: {result}')
print(f'Result type: {type(result)}')
print(f'Result length: {len(result)}')

if result and len(result) == 6:
    version, x, y, num_guesses, max_guesses, expiration = result
    print(f'Unpacked: version={version}, x={x}, y type={type(y)}, num_guesses={num_guesses}')
    print(f'Y length: {len(y)}')

db.close() 