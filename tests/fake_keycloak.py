import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import base64
import uuid
from typing import Dict, Any
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Configurable test users and clients ---
TEST_USERS = [
    {"username": "alice", "password": "password123", "sub": "11111111-1111-1111-1111-111111111111"},
    {"username": "bob", "password": "password456", "sub": "22222222-2222-2222-2222-222222222222"},
]
TEST_CLIENTS = [
    {"client_id": "cli-test", "client_secret": "secret", "allowed_grant_types": ["password"]},
]
ISSUER = "http://localhost:9000/realms/openadp"

# --- Generate static EC key for signing ---
EC_KEY = ec.generate_private_key(ec.SECP256R1(), default_backend())
EC_PUB = EC_KEY.public_key()
EC_JWK = json.loads(
    jwt.algorithms.ECAlgorithm.to_jwk(EC_PUB)
)
KID = "test-key"

# --- JWKS endpoint ---
JWKS = {
    "keys": [{
        **EC_JWK,
        "kid": KID,
        "use": "sig",
        "alg": "ES256",
        "kty": "EC"
    }]
}

# --- HTTP Handler ---
class FakeKeycloakHandler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode("utf-8"))

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            self._send_json({
                "issuer": ISSUER,
                "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
                "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
                "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
                "userinfo_endpoint": f"{ISSUER}/protocol/openid-connect/userinfo",
                "grant_types_supported": ["password", "client_credentials"],
                "response_types_supported": ["token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["ES256"],
            })
        elif self.path == "/protocol/openid-connect/certs":
            self._send_json(JWKS)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/protocol/openid-connect/token":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode("utf-8")
            params = dict(x.split('=') for x in body.split('&'))
            grant_type = params.get("grant_type")
            client_id = params.get("client_id")
            username = params.get("username")
            password = params.get("password")
            # Only support password grant for now
            if grant_type != "password":
                self._send_json({"error": "unsupported_grant_type"}, code=400)
                return
            # Validate client
            client = next((c for c in TEST_CLIENTS if c["client_id"] == client_id), None)
            if not client or "password" not in client["allowed_grant_types"]:
                self._send_json({"error": "invalid_client"}, code=401)
                return
            # Validate user
            user = next((u for u in TEST_USERS if u["username"] == username and u["password"] == password), None)
            if not user:
                self._send_json({"error": "invalid_grant"}, code=401)
                return
            # Issue JWT
            now = int(time.time())
            payload = {
                "iss": ISSUER,
                "sub": user["sub"],
                "aud": client_id,
                "iat": now,
                "exp": now + 300,
                "jti": str(uuid.uuid4()),
            }
            # DPoP/PoP: Accept cnf from request (not implemented yet)
            token = jwt.encode(payload, EC_KEY, algorithm="ES256", headers={"kid": KID})
            self._send_json({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "openid profile email",
            })
        else:
            self.send_response(404)
            self.end_headers()

# --- Server class for test setup/teardown ---
class FakeKeycloakServer:
    def __init__(self, host="localhost", port=9000):
        self.host = host
        self.port = port
        self.httpd = HTTPServer((host, port), FakeKeycloakHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever)
        self.thread.daemon = True
        self.issuer = f"http://{host}:{port}/realms/openadp"
    def start(self):
        self.thread.start()
        time.sleep(0.1)  # Give server time to start
    def stop(self):
        self.httpd.shutdown()
        self.thread.join()

if __name__ == "__main__":
    server = FakeKeycloakServer()
    print(f"Fake Keycloak running at {server.issuer}")
    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping fake Keycloak...")
        server.stop() 