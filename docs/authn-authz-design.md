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

## 4  Identity Provider (IdP) Compatibility

PoP-JWT support status (mid-2025):

| IdP | PoP / DPoP Availability | Notes |
|-----|-------------------------|-------|
| **Keycloak ≥ 22** | **Native** (enable `dpopBoundAccessTokens`) | OSS; easy self-host. |
| **Auth0** | *Public Beta* feature flag | Docs: *"DPoP for SPA / M2M"*. |
| **Okta** | Roadmap Q3 2025 | Early-access program available. |
| **Cloudflare Identity** | Not yet (only bearer) | We can still run Keycloak behind Access. |
| **AWS Cognito** | No (as of 2025-06) | Workaround: custom authorizer with Lambda. |

Take-away: **at least one solid OSS option (Keycloak)** and one mainstream SaaS (Auth0) already ship PoP-JWT. Others are catching up. Since OpenADP nodes only verify tokens, they will automatically work as vendors add support.

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
| `auth.enabled` | Enforce JWT on state-changing RPCs | `false` (until Phase 3) |
| `auth.issuer` | Expected `iss` claim (IdP URL) | — |
| `auth.jwks_url` | JWKS endpoint (cached, refreshing) | `${issuer}/.well-known/jwks.json` |
| `auth.cache_ttl` | Seconds to cache JWKS | 3600 |
| `rate.user_rps` | Requests/sec per user | 5 |
| `rate.ip_rps` | Requests/sec per IP (pre-auth) | 20 |
| `guess.max_attempts` | PIN guesses per backup | 10 |
| `auth.access_ttl` | Access-token lifetime seconds | 300 |
| `auth.refresh_ttl` | Refresh-token lifetime seconds | 7_776_000 (≈90 days) |

Operators behind Cloudflare set `tls.origin=unix:///var/run/cloudflared.sock`, otherwise same config.

---

## 8  Open Questions — **Resolved**

1. **Store OAuth `sub` in DB?** → *No.* We will include it only in the audit log, not in the operational tables.
2. **Anonymous backups?** → *No.* All state-changing RPCs require authentication.
3. **Token lifetime?** → Access ≈5 min + refresh 90 days. Users are not bothered unless token expires or is revoked.
4. **Client token storage?** → Yes, CLI/tools persist refresh & JWK (encrypted on disk) to avoid re-login.
5. **mTLS?** → *Dropped.*

---

## 9  Next Steps

1. Choose reference IdP (Keycloak in Docker for dev; Cloudflare Identity for prod test).
2. Draft the **JWT verification middleware** interface (no implementation yet).
3. Prototype CLI Device Code flow (`oauthlib`) to ensure UX.
4. Gather feedback from node operators on configuration section (§7).
5. Iterate this doc → **v0.2**.

---

*End of v0.1 — please review & comment.*

## 10  Appendix A – Terminology: PoP vs DPoP

* **PoP (Proof-of-Possession) Token** – Generic term for any access token that tells the resource server *which* public key the client must prove it controls. The proof can happen at TLS layer, in an HTTP header, etc.
* **DPoP (Demonstration of Proof-of-Possession)** – A specific OAuth 2 draft (now RFC 9449) that defines **how** the client proves possession: it signs a small JWS (the "DPoP header") for every HTTP request. That header includes a nonce (`jti`), the HTTP method, URL, and the current timestamp. The server verifies the signature using the JWK from the token's `cnf` claim. 

In our design *all* PoP tokens use the **DPoP** mechanism for the proof step. 