#!/usr/bin/env python3
"""Test OpenADP with a fresh BID to avoid old registration conflicts."""

import sys
import os
import pytest
import uuid
import requests
import base64
from openadp import keygen
from openadp.auth.keys import generate_keypair
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import json
from client.jsonrpc_client import EncryptedOpenADPClient

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Helper to get a JWT from the fake Keycloak server
def get_fake_jwt(issuer, username, password, client_id="cli-test"):
    token_url = f"{issuer}/protocol/openid-connect/token"
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": password,
    }
    resp = requests.post(token_url, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]

# Helper to create DPoP auth_data for a server using the real client
def make_auth_data(server_url, jwt_token):
    # Generate DPoP keypair
    priv, pub_jwk = generate_keypair()
    # Ensure x and y decode to 32 bytes
    def b64url_decode(data):
        padded = data + '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded)
    x_bytes = b64url_decode(pub_jwk['x'])
    y_bytes = b64url_decode(pub_jwk['y'])
    assert len(x_bytes) == 32, f"JWK x coordinate is {len(x_bytes)} bytes, expected 32"
    assert len(y_bytes) == 32, f"JWK y coordinate is {len(y_bytes)} bytes, expected 32"
    # Create encrypted client and perform handshake
    client = EncryptedOpenADPClient(server_url)
    # Perform a dummy encrypted echo to complete handshake and get handshake hash
    _ = client.echo("test", encrypted=True)
    handshake_hash = getattr(client, 'last_handshake_hash', None)
    if handshake_hash is None:
        raise RuntimeError("Could not obtain handshake hash from client")
    # Use the client's method to create the full auth payload
    return client.create_auth_payload(jwt_token, priv, pub_jwk, handshake_hash)

@pytest.mark.usefixtures("integration_env")
def test_fresh_openadp(tmp_path):
    """Integration: Test OpenADP key generation and recovery with a fresh backup ID, using the fake Keycloak server and 3 OpenADP servers."""
    server_urls = os.environ["OPENADP_SERVER_URLS"].split(",")
    oidc_issuer = os.environ["OIDC_ISSUER"]
    test_user_sub = "11111111-1111-1111-1111-111111111111"  # alice's sub in fake_keycloak.py
    test_username = "alice"
    test_password = "password123"
    test_file = tmp_path / "fresh_test_file.txt"
    test_file.write_text("OpenADP integration test data.")
    user_id = test_user_sub

    # Get JWT from fake Keycloak
    jwt_token = get_fake_jwt(oidc_issuer, test_username, test_password)

    # Build per-server auth_data for each OpenADP server using the real client
    auth_data_list = [make_auth_data(url, jwt_token) for url in server_urls]

    # Directly use EncryptedOpenADPClient for each server to register a share
    uid, did, bid = user_id, "beast", f"file://{test_file.name}"
    version = 1
    x, y = 1, 123456789  # Dummy share values for test
    max_guesses = 10
    expiration = 0
    success = False
    for url, auth_data in zip(server_urls, auth_data_list):
        client = EncryptedOpenADPClient(url)
        result, error = client.register_secret(uid, did, bid, version, x, str(y), max_guesses, expiration, encrypted=True, auth_data=auth_data)
        if error is None and result:
            success = True
            break
    assert success, "Direct register_secret failed for all servers with per-server handshake/auth."

    # For recovery, use the same server's auth_data
    recovered_key, error = keygen.recover_encryption_key(
        str(test_file), test_password, user_id, server_urls, threshold=len(server_urls), auth_data=auth_data_list[0]
    )
    assert error is None, f"Key recovery failed: {error}"
    assert recovered_key is not None, "Recovered key should not be None"
    assert enc_key == recovered_key, (
        f"Keys don't match!\nGenerated:  {enc_key.hex()}\nRecovered:  {recovered_key.hex()}"
    ) 