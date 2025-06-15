import pytest
import sys
import os
import subprocess
import time
sys.path.insert(0, os.path.dirname(__file__))
from fake_keycloak import FakeKeycloakServer

@pytest.fixture(scope="session")
def fake_keycloak_server():
    server = FakeKeycloakServer()
    server.start()
    yield server
    server.stop()

@pytest.fixture(scope="session")
def openadp_servers(tmp_path_factory, fake_keycloak_server):
    base_port = 9100
    procs = []
    server_urls = []
    for i in range(3):
        port = base_port + i
        data_dir = tmp_path_factory.mktemp(f"openadp_server_{i}")
        env = os.environ.copy()
        env["OPENADP_PORT"] = str(port)
        env["OPENADP_AUTH_ISSUER"] = fake_keycloak_server.issuer
        env["OPENADP_AUTH_JWKS_URL"] = f"{fake_keycloak_server.issuer}/protocol/openid-connect/certs"
        # Add any other env vars your server needs here
        proc = subprocess.Popen(
            ["python", "prototype/run_server.py"],
            env=env,
            cwd=os.path.abspath("."),
        )
        procs.append(proc)
        server_urls.append(f"http://localhost:{port}")
    time.sleep(2)
    yield server_urls
    for proc in procs:
        proc.terminate()
        proc.wait()

@pytest.fixture(scope="session")
def integration_env(fake_keycloak_server, openadp_servers):
    # Set environment variables for the test
    os.environ["OPENADP_SERVER_URLS"] = ",".join(openadp_servers)
    os.environ["OIDC_ISSUER"] = fake_keycloak_server.issuer
    yield
    # Cleanup if needed 