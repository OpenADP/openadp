#!/usr/bin/env python3
"""
Generates a static X25519 keypair for the OpenADP server.

The private key is saved to 'server_sk.key' and the public key
is printed to standard output in Base64 format.
"""

import os
import sys
import base64

# Add the project's 'src' directory to the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(os.path.dirname(script_dir), "src")
sys.path.insert(0, src_dir)

from openadp import crypto

def generate_and_save_key():
    """Generates and saves the server keypair."""
    private_key, public_key = crypto.x25519_generate_keypair()

    key_filename = "server_sk.key"
    with open(key_filename, "wb") as f:
        f.write(private_key)

    print(f"Private key saved to {key_filename}")
    print("Add the following public key to your servers.json file:")
    print(base64.b64encode(public_key).decode('utf-8'))

if __name__ == "__main__":
    generate_and_save_key() 