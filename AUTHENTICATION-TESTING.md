# OpenADP Authentication Testing Guide

## Overview

The OpenADP encrypt/decrypt tools use Phase 3.5 encrypted authentication using DPoP tokens over Noise-NK channels. This provides nation-state resistant encryption with secure token exchange.

**Phase 5 Status**: Authentication is **mandatory** for all operations. The global authentication server at `https://auth.openadp.org` is used by default. The `--auth` flag has been removed as authentication is always enabled.

## Authentication Architecture

- **Phase 3.5 Encrypted Authentication**: DPoP tokens transmitted within Noise-NK encrypted channels
- **Session-bound authentication**: Tokens bound to Noise-NK handshake hash to prevent replay
- **OAuth 2.0 Device Flow**: User authentication via Keycloak
- **Server-side validation**: JWT tokens validated with JWKS caching

## Testing Requirements

### Prerequisites

1. **OpenADP Server** running with Phase 3.5 authentication support
2. **Keycloak** configured for OAuth 2.0 Device Flow
3. **Different ports** for OpenADP and Keycloak (to avoid conflicts)

### Quick Setup for Testing

#### 1. Start OpenADP Server (Port 8080)
```bash
cd prototype/src
python -m server.jsonrpc_server --port 8080
```

#### 2. Start Keycloak (Port 8081) 
```bash
# Using Docker Compose
docker-compose -f docker-compose.keycloak.yml up -d

# Or modify to use port 8081 if needed
```

#### 3. Test Encryption with Authentication
```bash
cd prototype/tools

# Test encryption (authentication is always enabled in Phase 5)
python encrypt.py test_file.txt --servers http://localhost:8080

# Or explicitly specify the global server (usually not needed - it's the default)
python encrypt.py test_file.txt --servers http://localhost:8080 --issuer https://auth.openadp.org/realms/openadp

# Test decryption (authentication is always enabled in Phase 5)
python decrypt.py test_file.txt.enc
```

## Authentication Flow

1. **Device Code Flow**: User authenticates via browser with Keycloak
2. **DPoP Key Generation**: Client generates ECDSA key pair for token binding
3. **Token Acquisition**: Client receives access token and DPoP key binding
4. **Encrypted Request**: Token + handshake signature sent within Noise-NK channel
5. **Server Validation**: Server validates JWT + DPoP binding + handshake signature
6. **Secure Operation**: Authenticated RPC call executed

## Server Configuration

### Phase 5 Configuration
Authentication is **enabled by default** as of Phase 5:
```bash
# Standard server startup (authentication enabled by default)
python -m server.jsonrpc_server --port 8080
```

### Development/Testing Only
To disable authentication for development (not recommended for production):
```bash
OPENADP_AUTH_ENABLED=0 python -m server.jsonrpc_server --port 8080
```

## Testing Status

### ✅ Completed Tests
- **Phase 3.5 Authentication Implementation**: Full test in `test_phase35_auth.py`
- **Encrypt/Decrypt without Auth**: Local server testing successful
- **Threshold Management**: Metadata-based threshold storage working
- **Noise-NK Encryption**: All RPC calls properly encrypted

### 🔧 Pending Tests
- **Full Authentication Flow**: Requires Keycloak setup
- **Cross-server Authentication**: Multiple authenticated servers
- **Token Refresh**: Long-running authentication sessions

## Command-Line Options

### Encrypt Tool
```bash
python encrypt.py <file> [options]

Authentication Options (Phase 5 - authentication always enabled):
  --issuer ISSUER          OAuth issuer URL (default: https://auth.openadp.org/realms/openadp)
  --client-id CLIENT_ID    OAuth client ID (default: cli-test)

Server Options:
  --servers URL [URL ...]   Custom server URLs (bypasses scraping)
  --servers-url URL        URL to scrape for server list
```

### Decrypt Tool  
```bash
python decrypt.py <file.enc> [options]

Authentication Options (Phase 5 - authentication always enabled):
  --issuer ISSUER          OAuth issuer URL (default: https://auth.openadp.org/realms/openadp)
  --client-id CLIENT_ID    OAuth client ID (default: cli-test)

Server Options:
  --servers URL [URL ...]  Override metadata servers (testing only)
```

## Security Benefits

- **End-to-end Token Encryption**: Tokens invisible to network intermediaries
- **Session Binding**: Prevents token replay across different sessions  
- **Handshake Verification**: Proves DPoP key possession
- **JWKS Validation**: Cryptographic token verification
- **Nation-state Resistant**: Multi-layer encryption protection

## Troubleshooting

### Authentication Failed
- Verify Keycloak is running and accessible
- Check issuer URL matches Keycloak configuration
- Ensure oauth client `cli-test` exists in Keycloak

### Port Conflicts
- Use different ports for OpenADP server and Keycloak
- Update `--issuer` flag to match Keycloak port

### Token Issues
- Clear cached tokens: `rm -rf ~/.openadp/tokens.json`
- Regenerate DPoP keys: `rm -rf ~/.openadp/dpop_key.pem` 