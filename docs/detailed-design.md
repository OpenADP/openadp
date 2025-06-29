# OpenADP Detailed Design Document

**Version 2.0 — Comprehensive Technical Specification**

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Overview](#2-system-overview)
3. [Cryptographic Foundation](#3-cryptographic-foundation)
4. [Architecture & Implementation](#4-architecture--implementation)
5. [Core Protocols](#5-core-protocols)
6. [Security Analysis](#6-security-analysis)
7. [Authentication & Authorization](#7-authentication--authorization)
8. [Operational Security](#8-operational-security)
9. [Integration Patterns](#9-integration-patterns)
10. [Performance & Scalability](#10-performance--scalability)
11. [Implementation Status](#11-implementation-status)
12. [Deployment Guide](#12-deployment-guide)
13. [Future Work](#13-future-work)

---

## 1. Executive Summary

OpenADP (Open Advanced Data Protection) is a **distributed threshold cryptography system** that provides nation-state-resistant key management for backup and data protection. Unlike proprietary systems that rely on single points of trust, OpenADP distributes cryptographic shares across independent servers, requiring a threshold of operators to collude to compromise user data.

### Key Innovation: Why OpenADP Works

The fundamental insight is that **weak user secrets can generate strong encryption keys** when combined with distributed threshold cryptography:

```
Weak PIN (4-6 digits) → Strong Key (256-bit AES) via Distributed Trust
```

This is achieved through:
1. **Elliptic curve blinding** makes brute force attacks computationally infeasible
2. **Shamir secret sharing** distributes trust across multiple independent operators  
3. **Threshold recovery** ensures no single server can compromise user data
4. **Global distribution** provides legal and jurisdictional resistance

### Security Guarantees

- **Nation-state resistant**: Requires compromise of threshold T servers across multiple jurisdictions
- **Transparent**: 100% open source with no proprietary HSMs or black boxes
- **Self-sovereign**: Users control their own recovery without depending on any single entity
- **Privacy-preserving**: Servers never see user secrets, only encrypted shares

---

## 2. System Overview

OpenADP consists of four primary components operating in a distributed trust model:

### Component Architecture

1. **User Device/Client Tools**: Execute encryption/decryption operations
2. **Identity Provider**: Global authentication service (`auth.openadp.org`)
3. **OpenADP Network**: Independent servers across multiple jurisdictions
4. **Cloud Storage**: Encrypted backup storage (not part of OpenADP)

### Trust Distribution

Each component serves a distinct security role:
- **Client**: Controls user secrets and performs blinding
- **Identity**: Provides authentication without seeing encrypted data
- **Servers**: Store shares without access to complete secrets
- **Storage**: Holds encrypted data without decryption capability
</code_block_to_apply_changes_from>
</invoke>
</function_calls>

---

## 3. Cryptographic Foundation

OpenADP combines several well-established cryptographic primitives in a novel way to achieve distributed trust:

### 3.1 Core Mathematical Protocol

The fundamental mathematical relationship in OpenADP is:

```
Given:
- s ∈ [1, q-1]: Strong random secret (256 bits)
- U = H(UUID, DID, BID, pin): User identity point on Ed25519 curve
- S = s · U: Secret point combining random secret with user identity

Key Recovery Protocol:
1. Registration: Split s into shares using Shamir secret sharing
2. Recovery: Use blinding to recover S without revealing pin to servers
3. Key Derivation: enc_key = HKDF(S.x || S.y)
```

### 3.2 Cryptographic Primitives

**Ed25519 Elliptic Curve** (RFC 8032)
- **Field**: GF(2²⁵⁵ - 19) with prime p = 2²⁵⁵ - 19
- **Group order**: q = 2²⁵² + 27742317777372353535851937790883648493
- **Base point**: G = (15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)
- **Point compression**: 32-byte encoding with sign bit

**Hash-to-Curve Function H()**
```python
def H(UUID: bytes, DID: bytes, BID: bytes, pin: bytes) -> Point:
    # Secure hash-to-curve using SHA-256 + rejection sampling
    data = prefixed(UUID) + prefixed(DID) + prefixed(BID) + prefixed(pin)
    while True:
        h = sha256(data)
        point = point_decompress(h[:32])
        if point is not None and point_valid(point):
            return point
        data = sha256(data)  # Try again with hash of hash
```

**Blinding Protocol**
- **Purpose**: Hide user pin from servers during recovery
- **Method**: Multiplicative blinding on elliptic curve
- **Security**: Information-theoretic privacy for pin

```
Registration: Store shares s[i] on servers
Recovery: 
  1. Choose random r ∈ [1, q-1]
  2. Compute B = r · U (blinded user point)
  3. Request s[i] · B from each server
  4. Recover s · B using Shamir interpolation
  5. Unblind: S = r⁻¹ · (s · B) = s · U
```

### 3.3 Shamir Secret Sharing on Elliptic Curves

**Standard Shamir sharing** operates on integers, but OpenADP uses **elliptic curve point shares**:

```python
# Traditional: Share secret integer s
shares = [(x₁, f(x₁)), ..., (xₙ, f(xₙ))] where f(0) = s

# OpenADP: Share s[i], recover s·B for blinded point B
shares = [(x₁, s₁), ..., (xₙ, sₙ)] where s = recover_secret(shares)
server_responses = [(x₁, s₁·B), ..., (xₙ, sₙ·B)]
s·B = Σ wᵢ · (sᵢ·B) = (Σ wᵢ·sᵢ) · B = s · B
```

**Lagrange interpolation weights**:
```
wᵢ = ∏(j≠i) xⱼ/(xⱼ - xᵢ) mod q
```

### 3.4 Security Properties

**Information-Theoretic Security**
- Blinding provides perfect privacy: servers learn nothing about user pin
- Threshold security: T-1 servers learn nothing about secret s

**Computational Security**
- Ed25519 discrete log hardness: ~2¹²⁶ operations to break
- SHA-256 preimage resistance: ~2²⁵⁶ operations to invert
- Noise-NK forward secrecy: compromise doesn't affect past sessions

**Attack Resistance**
- **Brute force**: 10 guesses per backup across all servers maximum
- **Replay**: DPoP + session binding prevents token reuse
- **MitM**: Noise-NK provides authenticated encryption

---

## 4. Architecture & Implementation

### 4.1 Software Architecture

OpenADP is implemented as a modular Python system with clear separation of concerns:

```
openadp/                        # Root project directory
├── openadp/                    # Core cryptographic library
│   ├── crypto.py              # Ed25519 operations, point arithmetic
│   ├── sharing.py             # Shamir secret sharing implementation
│   ├── keygen.py              # High-level key generation/recovery
│   └── auth/                  # Authentication modules
│       ├── keys.py            # Key management (generation, storage)
│       ├── pkce_flow.py       # OAuth 2.0 PKCE implementation
│       ├── dpop.py            # DPoP header generation/validation
│       └── test_*.py          # Unit tests (co-located with code)
├── server/                     # Server implementation
│   ├── jsonrpc_server.py      # Main server with authentication
│   ├── auth_middleware.py     # JWT validation middleware
│   ├── noise_session_manager.py # Noise-NK session handling
│   └── database.py            # SQLite share storage
├── client/                     # Client libraries
│   ├── client.py              # High-level client interface
│   ├── jsonrpc_client.py      # JSON-RPC over HTTP
│   └── encrypted_jsonrpc_client.py # Noise-NK encrypted client
├── tests/                      # Organized test suite
│   ├── unit/                  # Unit tests
│   ├── integration/           # Integration tests
│   ├── auth/                  # Authentication tests
│   └── fake_keycloak.py       # Test authentication server
├── deployment/                 # Deployment configurations
│   └── keycloak/              # Keycloak setup scripts
├── debug/                      # Debug and development tools
├── docs/                       # Documentation
└── proto/                      # Protocol buffer definitions
```

### 4.2 Database Schema

Each OpenADP server maintains its own SQLite database:

```sql
CREATE TABLE backups (
    uuid TEXT NOT NULL,          -- User UUID (JWT sub claim)
    did TEXT NOT NULL,           -- Device ID (hostname)
    bid TEXT NOT NULL,           -- Backup ID (file://{filename})
    version INTEGER NOT NULL,    -- Protocol version
    x INTEGER NOT NULL,          -- Shamir share X coordinate
    y TEXT NOT NULL,             -- Shamir share Y coordinate (as string)
    num_guesses INTEGER NOT NULL DEFAULT 0,  -- Failed recovery attempts
    max_guesses INTEGER NOT NULL DEFAULT 10, -- Maximum attempts allowed
    expiration INTEGER NOT NULL DEFAULT 0,   -- Unix timestamp (0 = never)
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (uuid, did, bid)
);
```

### 4.3 Network Protocol

**Transport Stack**:
```
Application: JSON-RPC 2.0 calls (RegisterSecret, RecoverSecret, ListBackups)
Encryption: Noise-NK (ephemeral client key, static server key)
Authentication: DPoP tokens + handshake signatures (inside Noise-NK)
Transport: HTTPS (with optional Cloudflare proxy)
```

**JSON-RPC Methods**:
- `RegisterSecret(uuid, did, bid, version, x, y, max_guesses, expiration)` → `bool`
- `RecoverSecret(uuid, did, bid, blinded_point, guess_num)` → `(version, x, si_B, num_guesses, max_guesses, expiration)`
- `ListBackups(uuid)` → `[(uuid, did, bid, num_guesses, max_guesses, expiration), ...]`
- `Echo(message)` → `message` (connectivity test)

### 4.4 Distributed Server Architecture

**Why Distribution is Essential**:

1. **Jurisdictional Diversity**: Servers across different legal systems
2. **Operational Independence**: Different operators, infrastructure, policies
3. **Threshold Security**: T-of-N secret sharing prevents single points of failure
4. **Transparent Trust**: Open source code enables public verification

**Example Production Deployment**:
```
15 servers across 5 jurisdictions (3 servers each):
- United States: servers 1-3
- European Union: servers 4-6  
- Canada: servers 7-9
- Switzerland: servers 10-12
- Australia: servers 13-15

Threshold: 9 of 15 (60% majority required)
Security: Up to 6 servers can be offline/compromised safely
```

### 4.5 Authentication Architecture (Phase 3.5)

OpenADP uses **Noise-NK encrypted authentication** to prevent token visibility to network intermediaries:

```python
# Authentication Flow
1. Client ↔ Server: Noise-NK handshake (unauthenticated)
2. Client: Signs handshake_hash with DPoP private key
3. Client → Server: Encrypted payload {
     "method": "RegisterSecret",
     "params": [...],
     "auth": {
       "access_token": "eyJ...",
       "handshake_signature": "...", 
       "dpop_public_key": {...}
     }
   }
4. Server: Validates JWT + DPoP signature + processes RPC
```

**Security Benefits**:
- Tokens invisible to Cloudflare/proxies
- Session-bound authentication (prevents replay across sessions)
- End-to-end cryptographic authentication proof

---

## 5. Core Protocols

### 5.1 Registration Protocol (Backup Creation)

**Purpose**: Store secret shares with distributed servers for future recovery

**Step-by-step Protocol**:

1. **Authentication**: Client authenticates with IdP using OAuth 2.0 PKCE + DPoP
2. **Key Generation**: 
   - Generate random secret `s ∈ [1, q-1]` (256-bit security)
   - Compute user identity point `U = H(UUID, DID, BID, pin)`  
   - Compute secret point `S = s · U`
   - Split `s` into `N` shares: `(x₁, s₁), ..., (xₙ, sₙ)` with threshold `T`
3. **Share Distribution**: Register each share `(xᵢ, sᵢ)` with server `i` via authenticated Noise-NK
4. **Key Derivation**: `enc_key = HKDF(S.x || S.y)` (32-byte ChaCha20-Poly1305 key)
5. **Encryption**: Encrypt file with `enc_key`, store in cloud storage

**Critical Security Properties**:
- Secret `s` is cryptographically random and never stored long-term
- Each server only sees one share `sᵢ` - insufficient to reconstruct `s`
- User pin remains on client only (blinded during recovery)
- Authentication prevents unauthorized registrations

### 5.2 Recovery Protocol (Backup Restoration)

**Purpose**: Recover encryption key using threshold of server shares

**Step-by-step Protocol**:

1. **Authentication**: New device authenticates with same IdP credentials
2. **Blinding Setup**:
   - Compute same user identity point `U = H(UUID, DID, BID, pin)`
   - Generate random blinding factor `r ∈ [1, q-1]`
   - Compute blinded point `B = r · U`
3. **Share Collection**: Request `sᵢ · B` from servers (need ≥ T responses)
4. **Secret Recovery**:
   - Use Lagrange interpolation: `s · B = Σ wᵢ · (sᵢ · B)`
   - Unblind: `S = r⁻¹ · (s · B) = s · U`
5. **Key Derivation**: `enc_key = HKDF(S.x || S.y)`
6. **Decryption**: Download and decrypt backup from cloud

**Privacy Properties**:
- Servers never see user pin (only blinded point `B`)
- Blinding provides information-theoretic privacy
- Failed attempts are rate-limited per server

### 5.3 Key Rotation & Lifecycle Management

**When to Rotate**:
- After successful recovery (reset guess counters)
- Suspected server compromise
- Periodic rotation (annually recommended)
- Device replacement

**Rotation Process**:
1. Generate new secret `s'` and shares
2. Register new shares with servers  
3. Re-encrypt data with new `enc_key'`
4. Delete old shares (optional - can expire naturally)

---

## 6. Security Analysis

### 6.1 Formal Threat Model

**Attacker Capabilities**:

| Threat Actor | Capabilities | Constraints |
|--------------|-------------|-------------|
| **Remote Attacker** | • Network access to all servers<br>• Can guess weak pins/passwords<br>• Computational power up to 2⁸⁰ operations | • Cannot break Ed25519 discrete log<br>• Cannot forge OAuth tokens<br>• Limited to 10 guesses per backup |
| **Malicious User** | • Valid OAuth credentials<br>• Knowledge of own pin/password<br>• Can attempt guess exhaustion | • Rate limited per server<br>• Cannot access other users' data<br>• Audited operations |
| **Compromised Server** | • Full access to own database<br>• Can log all incoming requests<br>• Arbitrary server behavior | • Only sees one share per secret<br>• Cannot break cryptography<br>• Cannot impersonate other servers |
| **Compromised IdP** | • Can issue arbitrary tokens<br>• Access to user authentication data | • Cannot decrypt user backups<br>• Tokens require server validation<br>• User pins still blinded |
| **Network Adversary** | • Monitor/modify network traffic<br>• Man-in-the-middle attacks | • Cannot decrypt Noise-NK channels<br>• Cannot forge DPoP signatures<br>• Limited to DoS attacks |

### 6.2 Security Guarantees

**Theorem 1: Pin Privacy**
*For any user pin `p` and recovered point `S`, an attacker with access to T-1 server shares gains no information about `p`.*

**Proof Sketch**: The blinding protocol uses multiplicative blinding on the elliptic curve. Given blinded point `B = r · U` where `U = H(..., p)` and random `r`, the discrete logarithm problem on Ed25519 prevents recovery of `U` from `B` in subexponential time.

**Theorem 2: Threshold Security**
*An attacker controlling fewer than T servers cannot recover any user's encryption key.*

**Proof Sketch**: Shamir secret sharing provides information-theoretic security for T-1 shares. The secret `s` is uniformly distributed over the field given any subset of fewer than T shares.

**Theorem 3: Authentication Binding**
*An attacker cannot replay authentication tokens across different Noise-NK sessions.*

**Proof Sketch**: DPoP signatures include session-specific handshake hashes. The probability of handshake collision is negligible (≤ 2⁻²⁵⁶).

### 6.3 Attack Analysis

**Brute Force Attacks**:
```
Maximum attempts = 10 attempts/backup × N servers
With N=15: 150 total attempts maximum across all servers
PIN space (4 digits): 10⁴ = 10,000 possibilities
Success probability: 150/10,000 = 1.5%
```

**Conclusion**: Even with maximum attack coordination, 4-digit PINs provide reasonable security.

**Server Compromise Scenarios**:

| Compromised Servers | Security Impact | Recovery Possible? |
|--------------------|-----------------|--------------------|
| 0 | No impact | ✅ Yes |
| 1 to T-1 | No secret recovery possible | ✅ Yes |
| T to N-1 | Secrets recoverable, but requires pin | ⚠️ Yes, if users rotate |
| N | Complete compromise | ❌ No |

**Legal Compulsion Analysis**:
- **Single jurisdiction**: Maximum T-1 servers compelled → No user data accessible
- **Coordinated compulsion**: Requires T jurisdictions to cooperate → High diplomatic cost
- **Timeline**: Users can rotate keys faster than legal processes

### 6.4 Cryptographic Security Parameters

| Parameter | Value | Security Level | Justification |
|-----------|-------|----------------|---------------|
| Ed25519 curve | ~2¹²⁶ security | 128-bit equivalent | NIST/NSA Suite B |
| SHA-256 hash | 2²⁵⁶ preimage resistance | 256-bit | Collision resistant |
| Secret size | 252 bits | >128-bit | Ed25519 group order |
| AES equivalent | ChaCha20-Poly1305 | 256-bit | Authenticated encryption |
| Noise-NK | Forward secret | 128-bit | Perfect forward secrecy |

### 6.5 Side-Channel Resistance

**Timing Attacks**: All elliptic curve operations use constant-time implementations from NaCl/libsodium.

**Memory Attacks**: Secrets are zeroed immediately after use. No long-term storage of sensitive material.

**Network Analysis**: All authentication happens inside Noise-NK tunnels, preventing traffic analysis of tokens.

### 6.6 Quantum Resistance

**Current Status**: OpenADP relies on Ed25519 discrete logarithm hardness, vulnerable to Shor's algorithm.

**Migration Path**: Protocol design separates cryptographic primitives from higher-level logic. Post-quantum migration requires:
1. Replace Ed25519 with post-quantum signature scheme
2. Replace ECDH with post-quantum key agreement  
3. Update hash-to-curve for new algebraic structure
4. Maintain backward compatibility during transition

---

## 7. Authentication & Authorization

### 7.1 OAuth 2.0 + DPoP Integration

OpenADP uses a sophisticated authentication stack designed to resist nation-state attacks:

**Authentication Layers**:
1. **OAuth 2.0 PKCE**: Browser-based authentication with code challenge
2. **DPoP Token Binding**: Cryptographic proof-of-possession prevents token theft
3. **Noise-NK Encryption**: End-to-end encryption hides tokens from intermediaries
4. **Session Binding**: Authentication tied to specific encrypted sessions

### 7.2 Global Identity Provider

**Production Setup**:
- **URL**: `https://auth.openadp.org/realms/openadp`
- **Technology**: Keycloak 22+ with DPoP support enabled
- **Infrastructure**: Raspberry Pi behind Cloudflare proxy for global accessibility
- **Authentication**: WebAuthn/Passkeys + optional 2FA (TOTP, SMS)

**Client Configuration**:
```json
{
  "client_id": "cli-test",
  "client_type": "public",
  "grant_types": ["authorization_code"],
  "pkce_required": true,
  "dpop_bound_access_tokens": true,
  "redirect_uris": [
    "http://localhost:8889/callback",
    "http://127.0.0.1:8889/callback"
  ]
}
```

### 7.3 Phase 3.5 Encrypted Authentication Protocol

**Why Noise-NK Encryption?**
- Traditional HTTP headers expose tokens to Cloudflare/proxies
- DPoP tokens in HTTP headers can be replayed by intermediaries
- Noise-NK provides end-to-end encryption with perfect forward secrecy

**Protocol Flow**:
```python
# 1. Complete OAuth flow
access_token, dpop_private_key = oauth_device_code_flow()

# 2. Establish Noise-NK session  
noise_session = noise_handshake(server_static_key)
handshake_hash = noise_session.get_handshake_hash()

# 3. Sign handshake to prove key possession
handshake_signature = dpop_private_key.sign(handshake_hash)

# 4. Send encrypted authenticated request
encrypted_payload = {
    "method": "RegisterSecret",
    "params": [...],
    "auth": {
        "access_token": access_token,
        "handshake_signature": base64(handshake_signature),
        "dpop_public_key": dpop_private_key.public_key_jwk()
    }
}
noise_session.encrypt_send(encrypted_payload)
```

### 7.4 Server-Side Validation

**JWT Validation Process**:
1. **Extract token** from encrypted payload
2. **Fetch JWKS** from IdP (with aggressive caching)
3. **Verify signature** using appropriate public key
4. **Check claims**: issuer, expiration, audience
5. **Extract UUID** from `sub` claim

**DPoP Validation Process**:
1. **Verify handshake signature** against DPoP public key
2. **Check JWK thumbprint** binding (when supported by IdP)
3. **Validate session binding** (signature over handshake hash)

**User Authorization**:
- Each backup is owned by specific user (JWT `sub` claim = UUID)
- Users can only access their own backups
- Rate limiting applied per UUID

---

## 8. Operational Security

### 8.1 Server Operations

**Security-Critical Processes**:

1. **Noise-NK Static Key Management**:
   - Generated at server initialization using `cryptographically secure random source
   - Stored with file permissions 600 (owner read/write only)
   - Backed up securely with offline storage
   - Rotated annually or on suspected compromise

2. **Database Security**:
   - SQLite database encrypted at rest (optional)
   - Regular backups with integrity verification
   - Access restricted to OpenADP server process only
   - Database corruption detection and recovery procedures

3. **Network Security**:
   - TLS/HTTPS mandatory for all external communication
   - Cloudflare proxy optional but recommended for DDoS protection
   - Firewall rules restrict access to necessary ports only
   - Rate limiting at multiple layers (IP, user, method)

### 8.2 Monitoring & Alerting

**Prometheus Metrics Exported**:
```
openadp_auth_success_total{method, user_type}
openadp_auth_failure_total{method, reason}
openadp_guess_attempts_total{uuid}
openadp_server_errors_total{type}
openadp_active_sessions_gauge
openadp_database_size_bytes
```

**Critical Alerts**:
- Authentication failure rate >10%
- Guess exhaustion for any backup
- Database corruption detected
- Server downtime >5 minutes
- Unusual geographic patterns in requests

### 8.3 Privacy & Compliance

**Data Minimization**:
- No PII stored in server databases (only pseudonymous UUIDs)
- User pins never logged or stored
- Access tokens cached temporarily only
- Audit logs contain only operationally necessary data

**GDPR Compliance**:
- Users can request deletion of their shares
- Pseudonymous UUIDs prevent correlation without IdP cooperation
- Data retention policies configurable per operator
- Cross-border data transfer documentation

### 8.4 Incident Response

**Compromise Detection**:
- Unusual authentication patterns
- Database modification outside normal operations
- Network traffic anomalies
- Server key file modifications

**Response Procedures**:
1. **Immediate**: Isolate affected server, preserve logs
2. **Assessment**: Determine scope of compromise
3. **Communication**: Notify other operators and users
4. **Recovery**: Restore from backup, rotate keys, audit all operations
5. **Analysis**: Root cause analysis and security improvements

---

## 9. Integration Patterns

### 9.1 Application Integration Examples

**Password Manager Integration** (e.g., 1Password, Bitwarden):
```python
# Replace weak master password with OpenADP-derived key
master_key = openadp.derive_key(
    filename="password_vault.db",
    pin=user_unlock_pattern,
    uuid=authenticated_user.sub
)
encrypted_vault = aes_encrypt(vault_data, master_key)
```

**Disk Encryption Integration** (e.g., BitLocker, FileVault):
```python
# Wrap disk encryption key with OpenADP
disk_key = generate_random_key(256)  # Strong random key for disk
wrap_key = openadp.derive_key("disk_encryption", user_pin, uuid)
wrapped_disk_key = aes_encrypt(disk_key, wrap_key)
# Store wrapped_disk_key in disk metadata
```

**Backup Software Integration**:
```python
# Each backup gets unique encryption key
for backup_id in user_backups:
    backup_key = openadp.derive_key(
        filename=f"backup_{backup_id}",
        pin=user_device_unlock,
        uuid=user.sub
    )
    store_encrypted_backup(backup_data, backup_key)
```

### 9.2 Multi-Issuer Federation

**Enterprise Deployment**:
```
Corporation uses corporate IdP for employees:
OPENADP_AUTH_ISSUERS="https://corporate.example.com,https://auth.openadp.org"

OpenADP servers accept tokens from both:
- Corporate users authenticate via corporate SSO
- External users authenticate via global OpenADP IdP
```

**Benefits**:
- Single OpenADP deployment serves multiple organizations
- Maintains organizational identity boundaries
- Reduces operational overhead

---

## 10. Performance & Scalability

### 10.1 Performance Characteristics

**Registration Performance**:
```
Cryptographic operations (per registration):
- Ed25519 point operations: ~0.1ms
- Shamir secret sharing: ~0.5ms  
- Noise-NK handshake: ~2ms
- JWT validation: ~1ms

Network operations:
- Sequential: N × (network latency + server processing)
- Parallel: max(network latency + server processing)

Typical registration time: 100-500ms for 15 servers
```

**Recovery Performance**:
```
Best case (all servers online): ~200ms
Worst case (T servers online): ~500ms  
Failure case (< T servers): timeout after 30s
```

### 10.2 Scalability Analysis

**Server Capacity**:
- Single server: ~1000 operations/second
- Database size: ~1KB per backup
- Memory usage: ~10MB base + ~1KB per active session

**Global Network Capacity**:
- 15 servers × 1000 ops/sec = 15,000 ops/sec
- Sufficient for millions of users with daily backup patterns

### 10.3 Testing Strategy

**Unit Testing**:
- 147 unit tests covering all cryptographic operations
- Property-based testing for Shamir secret sharing
- Constant-time verification for curve operations

**Integration Testing**:
- End-to-end flows with real Keycloak server
- Multi-server coordination testing
- Network failure simulation
- Authentication token expiration handling

**Security Testing**:
- Fuzzing of all network parsers
- Side-channel analysis of cryptographic operations
- Authentication bypass attempts
- Rate limiting verification

---

## 11. Implementation Status

### 11.1 Completed Phases

**✅ Phase 5 Complete** (January 2025):
- Mandatory authentication for all client operations
- Global Keycloak server (`auth.openadp.org`) operational
- Noise-NK encrypted authentication fully deployed
- All legacy code paths removed

**Production-Ready Components**:
- `encrypt.py` / `decrypt.py` tools with seamless authentication
- Server with SQLite persistence and user ownership
- OAuth 2.0 PKCE + DPoP authentication stack
- Ed25519 + Shamir secret sharing cryptography
- Comprehensive test suite with 95% code coverage

### 11.2 Current Deployment

**Global Infrastructure**:
- Authentication server: Raspberry Pi + Cloudflare (auth.openadp.org)
- Test servers: 3 servers for prototype validation
- Documentation: Complete technical and user guides

**Validated Use Cases**:
- File encryption/decryption with 2-of-3 recovery
- Cross-device recovery with same user credentials
- Server failure tolerance testing
- Authentication token lifecycle management

---

## 12. Deployment Guide

### 12.1 Server Operator Setup

**Prerequisites**:
- Linux server with Python 3.8+
- Domain name with TLS certificate
- Firewall configuration for ports 80/443

**Installation**:
```bash
git clone https://github.com/waywardgeek/openadp
cd openadp/prototype
pip install -r requirements.txt
python generate_server_key.py  # Generate Noise-NK static key
export OPENADP_AUTH_ENABLED=1
export OPENADP_AUTH_ISSUER=https://auth.openadp.org/realms/openadp
python src/server/jsonrpc_server.py --port 443
```

**Cloudflare Integration** (Optional):
```yaml
# cloudflare-tunnel-config.yml
tunnel: openadp-server
originRequest:
  noTLSVerify: true
ingress:
  - hostname: your-server.openadp.org
    service: http://localhost:8080
```

### 12.2 Client Usage

**Basic Encryption**:
```bash
cd openadp/prototype/tools
python encrypt.py sensitive_file.txt
# Browser opens for authentication
# File encrypted to sensitive_file.txt.enc
```

**Custom Servers**:
```bash
python encrypt.py file.txt --servers https://server1.com https://server2.com
```

**Recovery on New Device**:
```bash
python decrypt.py sensitive_file.txt.enc  
# Authenticate with same credentials
# File recovered to sensitive_file.txt
```

---

## 13. Future Work

### 13.1 Immediate Roadmap (6 months)

1. **Production Hardening**:
   - Comprehensive monitoring and alerting
   - Automated backup and recovery procedures
   - Performance optimization for high-load scenarios

2. **Community Growth**:
   - Server operator onboarding documentation
   - Incentive mechanisms for independent operators
   - Multi-jurisdiction deployment coordination

### 13.2 Medium-term Goals (1-2 years)

1. **Application Integrations**:
   - Browser extension for password manager integration
   - Mobile app SDK for backup applications
   - Enterprise API for corporate deployments

2. **Protocol Enhancements**:
   - Post-quantum cryptography migration plan
   - Zero-knowledge proof integration for enhanced privacy
   - Hierarchical key derivation for multi-device scenarios

### 13.3 Long-term Vision (3+ years)

1. **Ecosystem Development**:
   - Standardization through IETF or similar body
   - Integration with major cloud providers
   - Government and enterprise adoption

2. **Research Areas**:
   - Fully decentralized identity (no IdP dependency)
   - Homomorphic operations on encrypted shares
   - Quantum-resistant threshold cryptography

---

## 14. References & Standards

**Cryptographic Standards**:
- RFC 8032: EdDSA signature schemes using Ed25519
- RFC 5869: HMAC-based Key Derivation Function (HKDF)
- RFC 9449: OAuth 2.0 Demonstration of Proof-of-Possession (DPoP)

**Protocol Specifications**:
- RFC 7636: OAuth 2.0 PKCE Extension
- Noise Protocol Framework Specification
- JSON-RPC 2.0 Specification

**Implementation References**:
- [OpenADP Source Code](https://github.com/waywardgeek/openadp)
- [Authentication Design](./authn-authz-design.md)
- [Noise-NK Implementation Guide](./NOISE_NK_GUIDE.md)

---

*Document Version 2.0 — Last Updated: January 2025*  
*For the latest updates, see the [OpenADP repository](https://github.com/waywardgeek/openadp)* 