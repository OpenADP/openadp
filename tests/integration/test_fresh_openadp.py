#!/usr/bin/env python3
"""Test OpenADP with a fresh BID to avoid old registration conflicts."""

import sys
import os
import pytest
import uuid

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import keygen

def test_fresh_openadp(tmp_path):
    """Integration: Test OpenADP key generation and recovery with a fresh backup ID."""
    # Create a temporary file to simulate a new backup
    test_file = tmp_path / "fresh_test_file.txt"
    test_file.write_text("OpenADP integration test data.")
    test_password = "my_secure_password123"
    # Simulate a fresh user_id (UUID)
    user_id = str(uuid.uuid4())

    # Generate encryption key
    enc_key, error, server_urls, threshold = keygen.generate_encryption_key(
        str(test_file), test_password, user_id
    )
    assert error is None, f"Key generation failed: {error}"
    assert enc_key is not None, "Encryption key should not be None"
    assert server_urls is not None and len(server_urls) >= threshold, "Not enough servers used"

    # Recover encryption key
    recovered_key, error = keygen.recover_encryption_key(
        str(test_file), test_password, user_id, server_urls, threshold=threshold
    )
    assert error is None, f"Key recovery failed: {error}"
    assert recovered_key is not None, "Recovered key should not be None"
    assert enc_key == recovered_key, (
        f"Keys don't match!\nGenerated:  {enc_key.hex()}\nRecovered:  {recovered_key.hex()}"
    ) 