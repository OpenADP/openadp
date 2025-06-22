#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'openadp'))

from openadp.client import generate_keypair

# Generate a keypair and check the format
private_key, public_key = generate_keypair()

print(f"Private key type: {type(private_key)}")
print(f"Private key length: {len(private_key)}")
print(f"Private key hex: {private_key.hex()}")

print(f"Public key type: {type(public_key)}")
print(f"Public key length: {len(public_key)}")
print(f"Public key hex: {public_key.hex()}")

# Check if they are bytes
print(f"Private key is bytes: {isinstance(private_key, bytes)}")
print(f"Public key is bytes: {isinstance(public_key, bytes)}") 