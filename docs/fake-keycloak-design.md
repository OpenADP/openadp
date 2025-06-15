# Fake Keycloak (OIDC) Provider Design for OpenADP Integration Testing

## 1. Goals
- Provide a lightweight, Python-based fake OIDC provider for automated and CI integration tests.
- Allow OpenADP clients and servers to authenticate and obtain tokens without a real Keycloak or browser.
- Support the minimal set of OIDC endpoints and flows required for OpenADP (including DPoP/PoP if needed).
- Be easy to configure with test users, clients, and signing keys.
- Be fast, stateless, and suitable for parallel test runs.

---

## 2. Supported Endpoints
- `/.well-known/openid-configuration` — OIDC discovery
- `/protocol/openid-connect/token` — Token endpoint (supports grant types below)
- `/protocol/openid-connect/certs` — JWKS endpoint for public keys
- `/protocol/openid-connect/userinfo` — (Optional) User info endpoint
- `/protocol/openid-connect/auth` — (Optional) Authorization endpoint (for Device Code/PKCE, if needed)

---

## 3. Supported Grant Types
- **Client Credentials Grant** — For service-to-service and CI automation
- **Resource Owner Password Credentials (ROPC) Grant** — For test users (no browser required)
- **Device Code Grant** — (Optional, for full client simulation)
- **Refresh Token Grant** — (Optional, for token renewal)

---

## 4. JWT and JWKS Handling
- **Signing Keys**: Generate a static RSA or EC keypair at startup (or allow config for reproducibility)
- **JWKS Endpoint**: Serve the public key in JWKS format
- **Token Issuance**: Issue JWTs with configurable claims (sub, iss, exp, iat, aud, cnf, etc.)
- **DPoP/PoP Support**: Accept a DPoP public key (JWK) in the request and include a `cnf` claim in the JWT
- **Token Lifetime**: Configurable (default: short, e.g., 5 minutes)
- **Refresh Tokens**: Issue refresh tokens if needed

---

## 5. DPoP/PoP Support
- Accept a DPoP public key (JWK) in the token request (as a parameter or header)
- Include the `cnf` claim in the issued JWT
- (Optional) Validate DPoP proof-of-possession headers for advanced tests

---

## 6. User and Client Configuration
- Allow test users and clients to be configured via a static JSON or YAML file, or via Python dicts
- Each user: username, password, subject (sub claim)
- Each client: client_id, client_secret, allowed grant types
- Optionally, allow dynamic creation of users/clients for parallel tests

---

## 7. Security and Test Isolation
- Not for production use! Only for local/CI testing
- All secrets/keys are ephemeral or test-only
- Should not bind to public interfaces by default
- Should be stateless or easy to reset between tests

---

## 8. Extensibility
- Easy to add new endpoints or claims as OpenADP evolves
- Pluggable signing algorithms (RS256, ES256, etc.)
- Support for additional OIDC features as needed

---

## 9. Usage in CI and Local Testing
- Start the fake Keycloak as a background process or fixture before running integration tests
- Point OpenADP clients/servers at the fake OIDC endpoints (issuer, JWKS, token)
- Use test users/clients to obtain tokens programmatically (no browser required)
- Optionally, provide a Python API for direct token issuance in tests

---

## 10. Example Configuration
```yaml
users:
  - username: alice
    password: password123
    sub: 11111111-1111-1111-1111-111111111111
  - username: bob
    password: password456
    sub: 22222222-2222-2222-2222-222222222222
clients:
  - client_id: cli-test
    client_secret: secret
    allowed_grant_types: [client_credentials, password]
```

---

## 11. Example Usage in Test
```python
# Start fake Keycloak (in test setup)
from fake_keycloak import FakeKeycloakServer
server = FakeKeycloakServer(config_path="test_oidc_config.yaml")
server.start()

# In test: obtain token
import requests
resp = requests.post(f"{server.issuer}/protocol/openid-connect/token", data={
    "grant_type": "password",
    "client_id": "cli-test",
    "username": "alice",
    "password": "password123"
})
token = resp.json()["access_token"]

# Use token in OpenADP client/server
...

# Stop server (in test teardown)
server.stop()
```

---

## 12. Implementation Notes
- Use Flask or FastAPI for the HTTP server (simple, async, easy to test)
- Use PyJWT for JWT creation and signing
- Use cryptography for key generation
- Serve JWKS as a static endpoint
- Minimal dependencies for fast startup and CI use

---

*This design doc is a living document. Update as requirements evolve or new OIDC features are needed for OpenADP testing.* 