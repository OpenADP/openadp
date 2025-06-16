#!/usr/bin/env python3

import sys
sys.path.insert(0, '.')
from openadp.auth.dpop import make_dpop_header
from cryptography.hazmat.primitives.asymmetric import ec
from unittest.mock import patch

private_key = ec.generate_private_key(ec.SECP256R1())
malformed_der = b'\x31\x44\x02\x20' + b'\x00' * 32 + b'\x02\x20' + b'\x00' * 32

try:
    with patch.object(private_key, 'sign', return_value=malformed_der):
        result = make_dpop_header('POST', 'https://example.com/token', private_key)
        print('No exception raised')
except Exception as e:
    print('Exception raised:', type(e).__name__, str(e)) 