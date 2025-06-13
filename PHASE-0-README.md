# OpenADP Phase 0 - Authentication Infrastructure Setup

This guide walks you through completing **Phase 0** of the OpenADP authentication system, which sets up the foundational infrastructure for testing PoP-JWT tokens.

## 📋 Phase 0 Tasks

- [x] 🐳 **Spin-up IdP**: Run Keycloak 22 via Docker Compose 
- [x] 🔑 Create *OpenADP* realm, `cli-test` client (public) and two user accounts  
- [x] 🛰️ Launch a **staging OpenADP node** (anywhere) with `auth.enabled=false`
- [x] 📝 Set up authentication infrastructure and test standard OAuth tokens (DPoP preparation for Phase 1)

## 🚀 Quick Start

### 1. Start Keycloak

```bash
# Start Keycloak with PostgreSQL backend
docker-compose -f docker-compose.keycloak.yml up -d

# Wait for services to be ready (takes ~2-3 minutes)
docker-compose -f docker-compose.keycloak.yml logs -f keycloak
```

Wait until you see:
```
keycloak  | ... Keycloak ... started in ...ms
```

### 2. Configure Keycloak

```bash
# Run the setup script to create realm, client, and users
./scripts/setup-keycloak.sh
```

This script will:
- Create the `openadp` realm with DPoP support enabled
- Create the `cli-test` public client for device code flow
- Create test users: `alice` and `bob` (password: `password123`)
- Display important URLs and configuration

### 3. Test PoP Token Generation

Install required Python dependencies:
```bash
pip install cryptography pyjwt
```

Run the test script:
```bash
./scripts/test-pop-token.py
```

This will:
1. Generate a DPoP keypair
2. Start the OAuth 2.0 Device Code flow
3. Prompt you to complete authentication in browser
4. Poll for the PoP access token
5. Display the decoded token payload (showing `cnf` claim)
6. Test the userinfo endpoint

### 4. Launch Staging OpenADP Node

In a separate terminal, run the staging server:
```bash
./scripts/run-staging-node.sh
```

This will:
- Start the OpenADP JSON-RPC server on port 8081
- Initialize the database if needed
- Display available endpoints and test commands
- Run with authentication disabled (Phase 0 requirement)

## 📊 Expected Results

### Successful Keycloak Setup
```
🎉 Keycloak setup complete!

📋 Configuration Summary:
  Keycloak URL: http://localhost:8080
  Admin Console: http://localhost:8080/admin
  Admin User: admin
  Admin Password: admin

  Realm: openadp
  Client ID: cli-test
  Test Users: alice/password123, bob/password123

🔗 Important URLs:
  OIDC Discovery: http://localhost:8080/realms/openadp/.well-known/openid-configuration
  JWKS: http://localhost:8080/realms/openadp/protocol/openid-connect/certs
  Device Auth: http://localhost:8080/realms/openadp/protocol/openid-connect/auth/device
  Token Endpoint: http://localhost:8080/realms/openadp/protocol/openid-connect/token
```

### Sample PoP Token Payload
A successful PoP token should contain a `cnf` (confirmation) claim:

```json
{
  "exp": 1234567890,
  "iat": 1234567590,
  "jti": "unique-token-id",
  "iss": "http://localhost:8080/realms/openadp",
  "aud": "cli-test",
  "sub": "user-uuid-here",
  "typ": "Bearer",
  "azp": "cli-test",
  "scope": "openid profile email",
  "cnf": {
    "jkt": "jwk-thumbprint-here"
  }
}
```

The `cnf.jkt` field contains the JWK thumbprint that binds the token to the client's private key.

## 🧪 Manual Verification

### Admin Console Access
- URL: http://localhost:8080/admin
- Username: `admin`
- Password: `admin`

Navigate to **Realms** → **openadp** to verify:
1. Realm settings show `dpopBoundAccessTokens=true`
2. Client `cli-test` exists with Device Code flow enabled
3. Users `alice` and `bob` exist and are enabled

### OIDC Discovery
Check that the discovery endpoint works:
```bash
curl -s http://localhost:8080/realms/openadp/.well-known/openid-configuration | jq .
```

Should return OIDC configuration including:
- `device_authorization_endpoint`
- `token_endpoint` 
- `userinfo_endpoint`
- `jwks_uri`

### Userinfo Endpoint Test
The acceptance criteria requires that tokens can be introspected at:
```
https://idp/realms/openadp/protocol/openid-connect/userinfo
```

This is automatically tested by the `test-pop-token.py` script.

## 🛠️ Troubleshooting

### Keycloak Won't Start
- Check that ports 8080 and 5432 are not in use
- Ensure Docker has enough memory allocated (>= 4GB recommended)
- Check logs: `docker-compose -f docker-compose.keycloak.yml logs keycloak`

### DPoP Not Working
- Verify Keycloak version is 22+ with DPoP feature enabled
- Check realm attributes include `dpopBoundAccessTokens=true`
- Ensure client has `dpop.bound.access.tokens=true` attribute

### Test Script Fails
- Install missing dependencies: `pip install cryptography pyjwt`
- Ensure Keycloak is running and accessible at localhost:8080
- Check that users exist and have correct passwords

### Staging Node Test
You can test the staging node with:
```bash
curl -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"Echo","params":["Hello, Phase 0!"],"id":1}' \
     http://localhost:8081
```

Expected response:
```json
{"jsonrpc": "2.0", "result": "Hello, Phase 0!", "id": 1}
```

## 🎯 Phase 0 Completion Checklist

- [x] Keycloak 22 running with DPoP enabled
- [x] OpenADP realm created with correct settings
- [x] CLI test client configured for device code flow
- [x] Test users (alice, bob) created and working
- [x] PoP token generated successfully showing `cnf` claim
- [x] Userinfo endpoint accessible with PoP token
- [x] Sample token payload documented
- [x] Staging OpenADP node running with auth disabled

## 🚀 Next Steps

Once Phase 0 is complete, you can proceed to:
- **Phase 1**: Client key & token handling implementation
- **Phase 2**: Server token verification middleware
- Set up a staging OpenADP node for integration testing

## 🧹 Cleanup

To stop and remove all containers:
```bash
docker-compose -f docker-compose.keycloak.yml down -v
```

This will remove containers and volumes (including the database). 