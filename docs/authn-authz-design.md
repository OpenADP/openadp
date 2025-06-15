# OpenADP Authentication & Authorization Design

*Version 0.1 — **Draft** (for review and iteration)*

---

## 1  Objectives

1. **Stop unauthenticated password-guessing & DoS** on `RegisterSecret` / `RecoverSecret`.
2. **Bind every state-changing RPC to a real user** (human or service) for quotas, audit and revocation.
3. **Keep deployment flexible**  
   • Servers may sit behind Cloudflare **or** expose public TLS directly.  
   • No hard dependency on Cloudflare APIs or call-outs.
4. **Hard cut-over** — all clients **must** use PoP-JWT from day one (no legacy phase).
5. **Future-proof** toward *Proof-of-Possession* (PoP) tokens **and passkeys** without locking us out today.

---

## 2  Threat Model (update)

| Actor | Capability | Mitigation goal |
|-------|------------|-----------------|
| Remote attacker | Reach any OpenADP node; can guess `(UID,DID,BID)`; can brute 10×4-digit PINs per backup | Require prior authentication, per-user quotas |
| Malicious but authenticated user | Has valid login; may hammer backup guesses | Per-user rate-limit, per-backup guess counter |
| Compromised node operator | Can read their own DB; can tamper with traffic they terminate | Data already secret-shared; auth tokens carry minimal PII |

---

## 3  Architectural Overview

```text
(Optional Cloudflare)           Public TLS Node
┌────────────┐                  ┌────────────┐
│ Cloudflare │   JWT (header)   │  OpenADP   │
│  Access +  │ ───────────────► │  Node      │
│  Worker    │                  └────────────┘
└─────▲──────┘
      │ (mTLS tunnel or TLS-ORIGIN)
      │
┌─────┴──────┐
│   Client   │  HTTPS + JSON-RPC (+Noise-NK)  (always includes JWT)
└────────────┘
```

* **Client** (`encrypt.py`, automated script, mobile app…) acquires an **OIDC access token** and sends it in every RPC (`Authorization: Bearer <jwt>`).
* When the node is behind **Cloudflare**:  
  • Cloudflare Access verifies OIDC and **injects** a short-lived signed header (`cf-access-jwt-assertion`) or passes through the original JWT.  
  • Node trusts that header *or* validates the JWT locally (no outbound call).
* When the node is **directly on the Internet**:  
  • Node validates the JWT signature against the IdP's JWKS endpoint it cached.
* No node ever needs to contact Cloudflare.

### 3.1  Token Type

Only one token type is permitted:

| Token | Details |
|-------|---------|
| **PoP-JWT bound via DPoP (RFC 9449)** | • Access token contains `cnf` claim with device public key.<br>• Every HTTP request carries a DPoP header signed with that key.<br>• Server verifies both JWT and DPoP header; rejects anything else. |

*Bearer-only tokens are **not accepted**.*

### 3.2  Passkeys, 2FA & WebAuthn

* Users authenticate to the IdP with **passkeys** (WebAuthn resident credentials).  
* Successful ceremony returns an OAuth **device-bound PoP token** as above.  
* For CLI flows, we rely on the **Device Code** grant: user completes the WebAuthn step in their browser; CLI polls and then receives the PoP token + device JWK.

### 3.3  Two-Factor (2FA)

IdP policy can enforce additional factors (TOTP, push, SMS) **before** issuing the PoP token. OpenADP nodes stay agnostic—only care that the token is valid.

---

## 4  Identity Provider (IdP) Requirements

1. **OIDC-compliant** (Auth0, Cloudflare Identity, Cognito, Keycloak, …).
2. Exposes **JWKS** endpoint (`/.well-known/jwks.json`).
3. Supports:  
   • **WebAuthn / Passkeys** for first-factor login.  
   • **Device Code or PKCE flow** (CLI friendly).  
   • **Client Credentials** (service accounts / CI).  
   • **Optional 2FA** (TOTP / push) policy hooks.
4. Optional MFA / WebAuthn policy (future).

We **do not** ship or operate the IdP; node operators point configuration at the community IdP *or* their own.

---

## 9  Identity Provider (IdP) Compatibility

PoP-JWT support status (mid-2025):

| IdP | PoP / DPoP Availability | Notes |
|-----|-------------------------|-------|
| **Keycloak ≥ 22** | **Native** (enable `dpopBoundAccessTokens`) | OSS; easy self-host. |
| **Auth0** | *Public Beta* feature flag | Docs: *"DPoP for SPA / M2M"*. |
| **Okta** | Roadmap Q3 2025 | Early-access program available. |
| **Cloudflare Identity** | Not yet (only bearer) | We can still run Keycloak behind Access. |
| **AWS Cognito** | No (as of 2025-06) | Workaround: custom authorizer with Lambda. |

Take-away: **at least one solid OSS option (Keycloak)** and one mainstream SaaS (Auth0) already ship PoP-JWT. Others are catching up. Since OpenADP nodes only verify tokens, they will automatically work as vendors add support.

### 9.1  Cloudflare Proxy Considerations

**Important**: When deploying IdPs behind Cloudflare proxy, JWKS endpoint requests require User-Agent headers to avoid 403 Forbidden responses.

**Required Fix for Server-Side JWKS Fetching**:
```python
# ❌ This fails with 403 behind Cloudflare
response = urllib.request.urlopen(jwks_url)

# ✅ This works - include User-Agent header
request = urllib.request.Request(jwks_url)
request.add_header('User-Agent', 'OpenADP-Server/1.0')
response = urllib.request.urlopen(request)
```

This requirement affects all HTTP clients fetching JWKS from Cloudflare-protected endpoints, not just OpenADP servers. The User-Agent header can be any valid string.

---

## 5  Request Flow Details

### 5.1  Human-driven CLI (Device Code + Passkey)

1. Tool checks local token cache (PoP-JWT + JWK).
2. If missing/expired → starts *Device Code* flow.  
   • User visits URL, completes **passkey** authentication (and any configured 2FA).  
   • IdP issues PoP-JWT containing `cnf` = device JWK.  
   • IdP returns the JWK (public) so CLI can generate DPoP headers.
3. CLI stores `{access_token, jwk, refresh_token}` securely and signs a fresh DPoP header for every request.

### 5.2  Request Example

```
POST /jsonrpc HTTP/1.1
Authorization: DPoP <access_token>
DPoP: eyJ....<signed-header>
Content-Type: application/json

{"jsonrpc":"2.0", ...}
```

Server steps:
1. Verify JWT signature (issuer, expiry, audience).  
2. Extract `cnf` → JWK; verify DPoP header signature with it.  
3. Enforce `jti` uniqueness (replay protection).  
4. Proceed with authZ logic (quota, ownership, etc.).

### 5.3  Automation / CI

• Service account obtains a **Client Credentials** token and injects it.

### 5.4  Server-side Middleware (all nodes)

```python
# pseudo-code
jwt = extract_header(request)
claims = verify_signature(jwt, jwks_cache)
request.context.user_id = claims["sub"]
```

If verification fails ⇒ HTTP 401 (JSON-RPC error "Unauthorized").

Handlers (`RegisterSecret`, `RecoverSecret`) then:
1. Check/record **ownership** of `(UID,DID)` → `user_id`.
2. Enforce **per-user** & **per-backup** quotas.
3. Log (`user_id`, method, outcome, timestamp).

### 5.5  Token Lifetimes

After token issuance, the **access token** is short-lived (≈5 minutes) while a **refresh token** tied to the same JWK lives up to **90 days**. The CLI renews access tokens silently using the refresh token—no user interaction until the 90-day mark or manual revocation.

---

## 6  Migration / Roll-out Plan (simplified)

| Step | Action |
|------|--------|
| 1 | Stand up IdP with PoP-JWT enabled. |
| 2 | Release CLI/tooling with Device Code + DPoP flow. |
| 3 | Deploy new server build: `auth.enabled=true` (no fallback). |
| 4 | All legacy clients break → forces upgrade. |

Rollback: set `auth.enabled=false` temporally.

---

## 7  Configuration Knobs for Operators

| Setting | Description | Default |
|---------|-------------|---------|
| `auth.enabled` | Enforce JWT on state-changing RPCs | `true` (since Phase 4.1) |
| `auth.issuer` | Expected `iss` claim (IdP URL) | `https://auth.openadp.org/realms/openadp` |
| `auth.jwks_url` | JWKS endpoint (cached, refreshing) | `${issuer}/protocol/openid-connect/certs` |
| `auth.cache_ttl` | Seconds to cache JWKS | 3600 |
| `rate.user_rps` | Requests/sec per user | 5 |
| `rate.ip_rps` | Requests/sec per IP (pre-auth) | 20 |
| `guess.max_attempts` | PIN guesses per backup | 10 |
| `auth.access_ttl` | Access-token lifetime seconds | 300 |
| `auth.refresh_ttl` | Refresh-token lifetime seconds | 7_776_000 (≈90 days) |

Operators behind Cloudflare set `tls.origin=unix:///var/run/cloudflared.sock`, otherwise same config.

---

## 10  Open Questions — **Resolved**

1. **Store OAuth `sub` in DB?** → *No.* We will include it only in the audit log, not in the operational tables.
2. **Anonymous backups?** → *No.* All state-changing RPCs require authentication.
3. **Token lifetime?** → Access ≈5 min + refresh 90 days. Users are not bothered unless token expires or is revoked.
4. **Client token storage?** → Yes, CLI/tools persist refresh & JWK (encrypted on disk) to avoid re-login.
5. **mTLS?** → *Dropped.*

---

## 11  Next Steps

1. Choose reference IdP (Keycloak in Docker for dev; Cloudflare Identity for prod test).
2. Draft the **JWT verification middleware** interface (no implementation yet).
3. Prototype CLI Device Code flow (`oauthlib`) to ensure UX.
4. Gather feedback from node operators on configuration section (§7).
5. Iterate this doc → **v0.2**.

---

*End of v0.1 — please review & comment.*

## 8  Alternative: Noise-NK Encrypted Authentication

**Current Status**: ✅ **IMPLEMENTED AND DEPLOYED** (Phase 5 Complete - January 2025)

This is the **active authentication approach** used by OpenADP. All client tools now use mandatory Noise-NK encrypted authentication with the global server at `https://auth.openadp.org`.

### 8.1  Security Motivation

After implementation and review, we identified significant security concerns with HTTP header-based DPoP authentication:

1. **Cloudflare Visibility**: Access tokens and DPoP headers are visible to Cloudflare, creating potential for token replay attacks by privileged Cloudflare staff
2. **Complex Attack Surface**: Multiple layers (HTTP headers, DPoP verification, JWT validation) increase complexity and potential for bugs
3. **"Squishy" Security Model**: Trust boundaries unclear when intermediaries can inspect authentication credentials

### 8.2  Proposed Architecture

Instead of HTTP headers, we propose **Noise-NK encrypted authentication**:

1. **Complete Noise-NK handshake** (unauthenticated, as normal)
2. **Client signs `handshake_hash`** with DPoP private key  
3. **Send encrypted payload** within Noise-NK channel:
   ```json
   {
     "auth": {
       "access_token": "eyJ...",
       "handshake_signature": "base64...",
       "dpop_public_key": {"kty": "EC", ...}
     },
     "method": "RegisterSecret",
     "params": {...}
   }
   ```
4. **Server processing**:
   - Decrypt payload using Noise-NK session key
   - Verify `handshake_signature` against DPoP public key and handshake hash
   - Validate JWT access token
   - Process RPC method if authentication succeeds

### 8.3  Security Benefits

- **End-to-End Encryption**: Tokens invisible to Cloudflare and network intermediaries
- **Session Binding**: Authentication cryptographically bound to specific Noise-NK session
- **Simple Trust Model**: Only client and server involved; no intermediary access to credentials
- **Clean Reasoning**: "If you can decrypt + verify signature = you're authenticated"

### 8.4  Implementation Phases

This approach replaces the original HTTP header roadmap:

**Phase 3.5 - Noise-NK Authentication Protocol**
- Modify `noise_client.py` to support post-handshake authentication
- Update JSON-RPC payload structure to include `auth` field
- Implement handshake signature verification on server side
- Maintain backward compatibility during transition

**Phase 4 - Server Integration** ✅ **COMPLETED**  
- Update server handlers to extract authentication from decrypted payload
- Add ownership tracking using JWT `sub` claim
- Implement per-user rate limiting

**Phase 5 - Client Default** ✅ **COMPLETED** (January 2025)
- Make authentication mandatory for all operations
- Remove `--auth` flag; authentication always enabled
- Clean up legacy HTTP header code
- Updated documentation to reflect mandatory authentication
- Set global server (`https://auth.openadp.org`) as default

**Phase 6 - Production Hardening**
- Change server default to `OPENADP_AUTH_ENABLED='1'`
- Deploy authentication enforcement to production servers
- Remove legacy unauthenticated code paths

**Phase 7 - Multi-Issuer Support**
- Support multiple trusted OAuth issuers per server
- Server configuration: `OPENADP_AUTH_ISSUERS="issuer1,issuer2,issuer3"`
- Per-issuer JWKS caching and validation
- JWT `iss` claim determines which issuer's keys to use for validation
- Enterprise federation support (corporate identity + community identity)

### 8.5  Trade-off Analysis

**Advantages**:
- Superior security model (no token visibility to intermediaries)
- Simpler implementation (single authentication point)
- Session binding prevents token reuse across connections
- Clean separation of transport security (Noise-NK) and authentication

**Disadvantages**:
- Servers must complete full handshake before rejecting invalid authentication (DDoS risk)
- More complex integration with existing Noise-NK implementation
- Cannot use standard HTTP authentication middleware

### 8.6  DDoS Mitigation

The main downside is that servers must complete the expensive Noise-NK handshake before authenticating users, similar to how TLS servers must complete handshakes before seeing HTTP authentication headers. Mitigation strategies:

1. **Rate limit handshakes per IP** before authentication check
2. **Connection pooling** on client side to amortize handshake costs
3. **Fast-fail patterns** for obviously invalid authentication attempts

This is equivalent to the security/performance trade-off made by all TLS-protected authentication systems.

### 8.7  Migration Strategy

1. **Phase 1-2**: Complete current Device Flow + token acquisition (reusable) ✅ **COMPLETED**
2. **Phase 3**: Implement Noise-NK authentication (new approach) ✅ **COMPLETED**
3. **Phase 4**: Deploy server-side support with `auth.method=noise-nk` ✅ **COMPLETED**
4. **Phase 5**: Update clients to use new protocol ✅ **COMPLETED** (January 2025)
5. **Phase 6**: Remove legacy HTTP header authentication code

The OAuth2 Device Flow and DPoP key management work completed in Phases 1-2 remains fully applicable—only the transport mechanism changes.

### 8.8  Multi-Issuer Architecture (Phase 7)

**Problem**: Organizations want to use their corporate identity provider while still allowing community identity providers.

**Solution**: Server accepts JWTs from multiple pre-configured trusted issuers.

#### Validation Flow
```
1. Extract `iss` claim from JWT
2. Check if issuer is in server's trusted list
3. Fetch/cache JWKS from `{iss}/.well-known/jwks.json`
4. Validate JWT signature using issuer-specific public keys
```

#### Server Configuration
```bash
# Single issuer (current - Phase 4.1)
OPENADP_AUTH_ISSUER="https://auth.openadp.org/realms/openadp"

# Multiple issuers (Phase 7)
OPENADP_AUTH_ISSUERS="https://auth.openadp.org/realms/openadp,https://corporate.example.com,https://community.openadp.org"
```

#### Security Properties
- **Client cannot forge issuer**: `iss` claim is cryptographically signed
- **Server controls trust boundary**: Only pre-configured issuers accepted  
- **No cross-issuer token reuse**: Each issuer's keys validate only their own tokens
- **Independent JWKS caching**: Per-issuer public key caches with separate TTLs

#### Enterprise Use Cases
- **Corporate + Community**: Employees use corporate SSO, external users use GitHub/Google
- **Multi-tenant**: Different customer organizations with their own identity providers
- **Development**: Local test issuer + production issuer support in same server config

---

## 12  Appendix A – Terminology: PoP vs DPoP

* **PoP (Proof-of-Possession) Token** – Generic term for any access token that tells the resource server *which* public key the client must prove it controls. The proof can happen at TLS layer, in an HTTP header, etc.
* **DPoP (Demonstration of Proof-of-Possession)** – A specific OAuth 2 draft (now RFC 9449) that defines **how** the client proves possession: it signs a small JWS (the "DPoP header") for every HTTP request. That header includes a nonce (`jti`), the HTTP method, URL, and the current timestamp. The server verifies the signature using the JWK from the token's `cnf` claim. 

In our design *all* PoP tokens use the **DPoP** mechanism for the proof step. 

## 13  Implementation Roadmap (Original HTTP Header Approach)

**⚠️ NOTE: This roadmap describes the original HTTP header-based DPoP approach. See Section 8 for the preferred Noise-NK encrypted authentication approach that replaces this implementation plan.**

Each phase is sized to fit a single pull-request and can be tested independently.

### Phase 0 – Prep (no repo changes)
*Tasks*
- 🐳 **Spin-up IdP**: Run Keycloak 22 via Docker Compose with `dpopBoundAccessTokens=true`.
- 🔑 Create *OpenADP* realm, `cli-test` client (public) and two user accounts.
- 🛰️ Launch a **staging OpenADP node** (anywhere) with `auth.enabled=false`.
- 📝 Capture a sample PoP access-token, paste its decoded payload (showing `cnf.jwk`) in the wiki.

*Acceptance tests*
- Token can be introspected at `https://idp/realms/openadp/protocol/openid-connect/userinfo`.

---

### Phase 1 – Client key & token handling
*Code*
1. `prototype/src/openadp/auth/keys.py`
   - `generate_keypair()` → returns `(private_key_obj, public_jwk_dict)`.
   - `load_private_key()` / `save_private_key()` (file + `chmod 600`).
2. `prototype/src/openadp/auth/device_flow.py`
   - Runs OAuth 2 Device-Code flow; returns `{access, refresh, jwk_pub}`.
3. `prototype/src/openadp/auth/dpop.py`
   - `make_dpop_header(method, url, priv_key)`.
4. Wire into `encrypt.py` behind `--auth` flag (default *off*).

*Unit tests*
- `tests/auth/test_keys.py`: key serialization round-trip.
- `tests/auth/test_dpop.py`: header verifies, `jti` uniqueness, wrong method fails.

*Integration (CI)*
- GitHub Action uses Keycloak container, acquires token, calls `/echo` on staging (ignoring auth).

---

### Phase 2 – Server token verification middleware
*Code*
1. **`prototype/src/server/auth_middleware.py`** (new)  
   Implements **`validate_auth(request_bytes, headers)`** → `(user_id | None, error_str | None)`.
2. Modify **`prototype/src/server/jsonrpc_server.py`**:  
   - In `RPCRequestHandler.do_POST` call `validate_auth()` **before** parsing the JSON-RPC body.  
   - If `auth.enabled` is *false* → bypass check (for dev).  
   - On failure, return JSON-RPC error `{code:-32001, message:"Unauthorized"}`.
3. Lightweight config via **env-vars** (no dedicated config module yet):  
   - `OPENADP_AUTH_ENABLED`  ("0"|"1")  
   - `OPENADP_AUTH_ISSUER`   
   - `OPENADP_AUTH_JWKS_URL`.
4. **Replay cache**: simple in-memory `set()` keyed by `jti` with timestamp eviction (sliding 5-min window).  No Redis yet—can swap later.

*Unit tests*
- `tests/server/test_auth_positive.py`: valid token + DPoP header accepted.
- `tests/server/test_auth_negative.py`:  
  • expired token  
  • wrong `htu`  
  • duplicate `jti` ⇒ 401.

*Integration*
- Docker-compose spins IdP + **current `jsonrpc_server`**; pytest posts a `RegisterSecret` with valid PoP token and receives 200.

---

### Phase 3 – Auth-aware server logic
*Code*
1. Alembic migration: add `owner_sub` VARCHAR to `backups` table.
2. Update handlers:
   - **RegisterSecret**: if row absent ⇒ insert with `owner_sub=user_id`; else verify match.
   - **RecoverSecret**: require `owner_sub` match.
3. Simple Redis token-bucket per `user_id` (config knobs `rate.user_rps`).

*Unit tests*
- `tests/server/test_ownership.py`: two users, same UID ⇒ second register fails.
- `tests/server/test_ratelimit.py`: 10 rapid calls ⇒ 429.

*Migration test*
- `scripts/dev/migrate_legacysql.sh` backfills `owner_sub='legacy'` and passes recovery.

---

### Phase 4 – Client default-on
*Code*
- Remove `--auth`; auth code path always used.
- Token refresh: `refresh_if_needed()` before each request (400-line diff max).

*Tests*
- Regression suite previously written continues to pass with `auth.enabled=true`.

---

### Phase 5 – Ops & observability (**DEPRECATED** - HTTP Header Approach)
**Note**: This Phase 5 is part of the deprecated HTTP header approach. The implemented Phase 5 (Client Default) is documented in Section 8.4.

*Code/Infra*
- Prometheus exporter counters: `openadp_auth_success_total`, `…_failure_total`, `…_replay_total`.
- Structured JSON audit logger writes to file or Loki.
- Grafana dashboard JSON committed in `ops/grafana/`.

*Tests*
- Unit: metrics increment properly.
- Manual: dashboard shows traffic on staging.

---

### Phase 6 – Rollout & cleanup
*Tasks*
- Remove `--allow-unauth` flag; config default `auth.enabled=true`.
- Update documentation & README quick-start.
- Publish migration guide in `docs/migrating-to-pop.md`.

*Acceptance*
- Production nodes run for ≥1 week with zero unauth traffic.

---

## 15  Phase 4.1 - COMPLETED ✅

**Global Authentication Server Deployment - January 2025**

Phase 4.1 has been successfully completed with full end-to-end authentication working using the global Keycloak server at `https://auth.openadp.org`.

### Key Achievements

1. **Global Server Transition**: Successfully moved from local to global authentication
2. **Cloudflare Integration**: Resolved HTTP/HTTPS protocol mismatch with proxy configuration
3. **Public Client Configuration**: Updated from confidential to public client for CLI tools
4. **JWKS Access Fix**: Resolved critical User-Agent header requirement for JWKS requests

### Critical Technical Discovery: JWKS User-Agent Requirement

**Issue**: JWKS requests to `https://auth.openadp.org/realms/openadp/protocol/openid-connect/certs` failed with 403 Forbidden when sent without User-Agent header.

**Root Cause**: Cloudflare proxy blocks requests without User-Agent headers as potential bot traffic.

**Solution Applied**: Updated server JWKS fetching code:
```python
# Before: Failed with 403 Forbidden
response = urllib.request.urlopen(AUTH_JWKS_URL)

# After: Success with User-Agent header
req = urllib.request.Request(AUTH_JWKS_URL)
req.add_header('User-Agent', 'OpenADP-Server/1.0')
response = urllib.request.urlopen(req)
```

This fix has been applied to:
- `prototype/src/server/jsonrpc_server.py` (line 58)
- `prototype/src/server/auth_middleware.py` (if implemented)

### Validation Results

**Complete end-to-end testing successful:**
- ✅ Authentication flow working with global server
- ✅ Encryption with 3-server threshold (2 of 3 recovery)
- ✅ Decryption with authenticated token validation
- ✅ DPoP token binding with handshake signature verification

### Architecture Status

- **Authentication Server**: https://auth.openadp.org (Keycloak on Raspberry Pi + Cloudflare)
- **Production Servers**: 3 servers (xyzzy, sky, minime) validating global tokens
- **Security Stack**: PKCE + DPoP + Noise-NK + Shamir secret sharing
- **Client Tools**: Updated to use global issuer by default

Token lifetime parameters (see §7) remain: access 5 min, refresh 90 days.

---

## 16  Phase 5 - COMPLETED ✅

**Client Default Authentication - January 2025**

Phase 5 has been successfully completed, making authentication mandatory for all client operations and removing the optional `--auth` flag.

### Key Achievements

1. **Mandatory Authentication**: Removed all `--auth` flags from client tools
2. **Simplified User Experience**: Users no longer need to remember authentication flags
3. **Consistent Behavior**: All operations now require authentication by default
4. **Documentation Cleanup**: Updated all examples and documentation to reflect mandatory authentication

### Changes Implemented

#### Client Tool Updates ✅
- **`encrypt.py`**: Removed optional authentication, always requires auth
- **`decrypt.py`**: Removed `[--auth]` from usage, authentication always enabled
- **Updated Comments**: Changed from "Phase 4" to "Phase 5 - mandatory"
- **Global Server Default**: Both tools use `https://auth.openadp.org/realms/openadp` by default

#### Documentation Updates ✅
- **`AUTHENTICATION-TESTING.md`**: Removed all `--auth` flag references
- **Command Examples**: Simplified to show authentication is automatic
- **Tool Options**: Updated help text to reflect Phase 5 status
- **Server Configuration**: Updated to show auth-enabled-by-default

### Behavioral Changes

**Before Phase 5:**
```bash
# Authentication was optional
python encrypt.py file.txt --auth --servers http://localhost:8080
python decrypt.py file.txt.enc --auth
```

**After Phase 5:**
```bash
# Authentication is always enabled
python encrypt.py file.txt --servers http://localhost:8080
python decrypt.py file.txt.enc
```

### Security Benefits

- **No Unauthenticated Bypass**: Users cannot accidentally skip authentication
- **Consistent Identity**: All operations are tied to authenticated users
- **Simplified Security Model**: Single code path reduces complexity
- **Audit Trail**: Every action has an associated user identity

### Validation Results

**Complete Phase 5 testing successful:**
- ✅ `encrypt.py` and `decrypt.py` always require authentication
- ✅ Help output shows no `--auth` flag (removed)
- ✅ Global server used by default (`https://auth.openadp.org/realms/openadp`)
- ✅ Documentation updated to reflect mandatory authentication
- ✅ Backward compatibility maintained (legacy files still decrypt)

### Migration Impact

- **Existing Scripts**: Need to remove `--auth` flags (breaking change)
- **New Users**: Simpler onboarding with consistent authentication
- **Existing Files**: All previously encrypted files still decrypt correctly

Phase 5 establishes OpenADP as an **authentication-first system** with no unauthenticated operation modes for end users.

---

## 14  Future Enhancement: Offline IdP Key Validation

**Status**: Future enhancement (post-Phase 4)  
**Goal**: Eliminate network dependencies for JWT validation while maintaining compatibility with major IdPs

### 14.1  Current Limitation

The current design requires network calls to fetch JWKS during JWT validation:
```python
# Current approach - requires network call
jwks_response = requests.get(f"{issuer}/.well-known/jwks.json")
public_keys = jwks_response.json()
```

**Problems**:
- Network dependency reveals OpenADP server to IdP
- Potential privacy/anonymity compromise for operators
- Latency and availability issues
- Creates targetable infrastructure

### 14.2  Proposed Solution: Aggressive JWKS Caching

Implement aggressive caching of IdP public keys with fallback mechanisms:

```python
# Enhanced validation with caching
async def validate_jwt_token(token: str) -> Optional[str]:
    # 1. Extract kid from JWT header
    header = jwt.get_unverified_header(token)
    kid = header.get('kid')
    issuer = jwt.decode(token, options={"verify_signature": False}).get('iss')
    
    # 2. Check cache first
    cached_key = get_cached_jwks_key(issuer, kid)
    if cached_key:
        return validate_with_key(token, cached_key)
    
    # 3. Fallback: fetch fresh JWKS (minimal network calls)
    fresh_keys = await fetch_and_cache_jwks(issuer)
    key = fresh_keys.get(kid)
    
    if key:
        return validate_with_key(token, key)
    
    return None  # Unknown key
```

### 14.3  Caching Strategy

**Cache Duration**: 24 hours (recommended by major IdPs)
**Cache Keys**: `{issuer}:{kid}` pairs
**Storage**: In-memory with persistent backup
**Refresh**: Lazy refresh on unknown `kid` or cache expiry

```python
JWKS_CACHE = {
    "appleid.apple.com": {
        "keys": {
            "AIDOPK1": {
                "key": rsa_public_key_object,
                "algorithm": "RS256",
                "expires": timestamp + 86400
            }
        },
        "last_fetch": timestamp,
        "next_refresh": timestamp + 86400
    }
}
```

### 14.4  Network Call Minimization

Network calls only occur:
1. **Server startup** - populate cache for configured issuers
2. **Unknown kid** - JWT uses key not in cache (rare)
3. **Cache expiry** - after 24 hours of no refresh
4. **Explicit refresh** - administrative cache invalidation

**Typical operation**: 99.9% of JWT validations happen offline

### 14.5  Big Tech Compatibility

This approach works seamlessly with major IdPs:

| IdP | JWKS Endpoint | Rotation Frequency | Cache Compatibility |
|-----|---------------|-------------------|-------------------|
| **Apple** | `appleid.apple.com/auth/keys` | Weeks/Months | ✅ Excellent |
| **Google** | `www.googleapis.com/oauth2/v3/certs` | Days/Weeks | ✅ Good |
| **Microsoft** | `login.microsoftonline.com/common/discovery/v2.0/keys` | Weeks | ✅ Excellent |
| **Auth0** | `{tenant}.auth0.com/.well-known/jwks.json` | Configurable | ✅ Excellent |

**Key Insight**: All major IdPs support multiple concurrent signing keys, making caching safe and effective.

### 14.6  Configuration

```bash
# Enable aggressive caching
OPENADP_JWKS_CACHE_TTL=86400          # 24 hours
OPENADP_JWKS_PRELOAD_ISSUERS=true     # Fetch keys on startup
OPENADP_JWKS_OFFLINE_MODE=false       # Set true to disable all network calls

# Per-issuer settings
OPENADP_JWKS_APPLE_TTL=172800         # 48 hours for Apple (slower rotation)
OPENADP_JWKS_GOOGLE_TTL=21600         # 6 hours for Google (faster rotation)
```

### 14.7  Privacy Benefits

**Before**: Every JWT validation reveals OpenADP server to IdP
```
OpenADP Server → IdP: "I'm validating tokens for my users"
```

**After**: Minimal, batched network fingerprint
```
OpenADP Server → IdP: "Getting public keys" (once per day)
```

The network pattern becomes indistinguishable from any other API server using standard OAuth practices.
