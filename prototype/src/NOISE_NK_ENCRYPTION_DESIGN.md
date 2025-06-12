# Noise-NK Encryption Layer Design

## Overview

This document describes the architecture for adding optional end-to-end encryption to our existing JSON-RPC API using the Noise-NK protocol. The design maintains full backward compatibility while providing strong security guarantees for sensitive operations.

## Problem Statement

Our current system relies on TLS termination at Cloudflare, which means:
- Cloudflare can inspect all API traffic in plaintext
- Cloudflare could potentially modify requests/responses
- No protection against insider threats at the CDN level
- Compliance requirements may mandate end-to-end encryption

## Goals

1. **End-to-End Security**: Messages encrypted from client to server, invisible to Cloudflare
2. **Backward Compatibility**: Existing unencrypted JSON-RPC methods continue to work unchanged
3. **Single Endpoint**: Avoid complexity of separate encrypted/unencrypted endpoints
4. **Simple Client API**: Encryption should be a simple boolean flag from client perspective
5. **Transport Compatibility**: Must work over HTTP/JSON-RPC (Cloudflare requirement)

## Why Noise-NK?

We chose the **Noise-NK** handshake pattern for several reasons:

### Technical Properties
- **Responder Authentication**: Clients can verify server identity using known public key
- **Client Anonymity**: Server cannot identify specific clients (no client static keys)
- **Forward Secrecy**: Session keys are ephemeral and independent of static keys
- **Replay Protection**: Built-in nonce progression prevents message replay
- **Zero-RTT Capability**: Future versions could allow encrypted data in first message

### Implementation Benefits
- **Well-Specified**: Part of the standardized Noise Protocol Framework
- **Battle-Tested Crypto**: Uses X25519 + AES-256-GCM + SHA-256
- **Simple State Machine**: Clear handshake sequence with minimal complexity
- **Library Support**: Good Python implementation available (dissononce)

### Security Model Fit
- **Server-Centric**: Our API model has known servers, anonymous clients
- **Session-Based**: Fits our request/response model with ephemeral sessions
- **Certificate-Like**: Server public key can be distributed like TLS certificates

## Architecture

### High-Level Flow

```
Client Perspective:
┌─────────────────────────────────────────────────────────────┐
│ result = client.call("getUserData", {"userId": 123})        │ ← Unencrypted (1 round)
│ result = client.call("getUserData", {"userId": 123},        │ ← Encrypted (2 rounds)
│                      encrypted=True)                        │   under the hood
└─────────────────────────────────────────────────────────────┘

Network Traffic (what Cloudflare sees):
┌─────────────────────────────────────────────────────────────┐
│ Unencrypted: {"method": "getUserData", "params": {...}}     │
│                                                             │
│ Encrypted Round 1: {"method": "noise_handshake",           │
│                     "params": {"message": "...", ...}}     │
│ Encrypted Round 2: {"method": "encrypted_call",            │
│                     "params": {"data": "encrypted_blob"}}  │
└─────────────────────────────────────────────────────────────┘
```

### Message Flow

#### Unencrypted Path (1 Round)
```json
Client → Cloudflare → Server:
{
  "jsonrpc": "2.0",
  "method": "getUserData", 
  "params": {"userId": 123},
  "id": 1
}

Server → Cloudflare → Client:
{
  "jsonrpc": "2.0",
  "result": {"userData": "..."},
  "id": 1
}
```

#### Encrypted Path (2 Rounds)

**Round 1: Noise-NK Handshake**
```json
Client → Cloudflare → Server:
{
  "jsonrpc": "2.0",
  "method": "noise_handshake",
  "params": {
    "session": "AbCd...123=",  // 16 random bytes, base64
    "message": "noise_handshake_msg_1_base64"
  },
  "id": 1
}

Server → Cloudflare → Client:
{
  "jsonrpc": "2.0", 
  "result": {
    "message": "noise_handshake_msg_2_base64"
  },
  "id": 1
}
```

**Round 2: Encrypted Call**
```json
Client → Cloudflare → Server:
{
  "jsonrpc": "2.0",
  "method": "encrypted_call",
  "params": {
    "session": "AbCd...123=",  // Same session ID
    "data": "encrypted_getUserData_call_base64"
  },
  "id": 2
}

Server → Cloudflare → Client:
{
  "jsonrpc": "2.0",
  "result": {
    "data": "encrypted_response_base64"
  },
  "id": 2
}
```

Where the encrypted data contains:
```json
// Inside encrypted blob (Round 2 request):
{
  "jsonrpc": "2.0",
  "method": "getUserData",
  "params": {"userId": 123},
  "id": 2
}

// Inside encrypted blob (Round 2 response):
{
  "jsonrpc": "2.0",
  "result": {"userData": "..."},
  "id": 2
}
```

## Implementation Components

### Client Library Changes
- **API Extension**: Add `encrypted=True` parameter to existing methods
- **Session Management**: Generate unique session IDs, manage Noise-NK state
- **Automatic Handshake**: Transparent 2-round flow when encryption requested
- **Error Handling**: Graceful fallback and clear error messages

### Server Changes
- **Method Routing**: Route based on method name (`noise_handshake`, `encrypted_call`, or regular)
- **Session Storage**: Temporary storage of Noise-NK cipher states
- **Encryption/Decryption**: Transparent encryption layer before business logic
- **Session Cleanup**: Immediate cleanup after single use

### Security Components
- **Key Management**: Server static key generation and distribution
- **Session Isolation**: Each encrypted call uses fresh ephemeral keys
- **Timing Attack Protection**: Consistent response times regardless of encryption
- **Error Information**: Minimal error leakage to prevent oracle attacks

## Security Analysis

### Threat Model

**Protected Against:**
- ✅ **CDN/Proxy Inspection**: Cloudflare cannot read method names, parameters, or responses
- ✅ **CDN/Proxy Modification**: Any tampering causes decryption failure
- ✅ **Network Eavesdropping**: TLS + Noise-NK provides defense in depth
- ✅ **Replay Attacks**: Noise-NK nonce progression prevents replay
- ✅ **Server Impersonation**: Client verifies server's static key

**Not Protected Against:**
- ❌ **Client Compromise**: Compromised client can decrypt its own traffic
- ❌ **Server Compromise**: Compromised server can decrypt all traffic
- ❌ **Traffic Analysis**: Cloudflare can still see timing, sizes, patterns
- ❌ **DoS**: Encrypted calls require more server resources

### Session Security
- **Ephemeral Keys**: Each session uses fresh ephemeral keypairs
- **Single Use**: Sessions destroyed immediately after one method call
- **No Persistence**: No long-lived encryption state on server
- **Forward Secrecy**: Past sessions cannot be decrypted if keys compromised

## Implementation Phases

### Phase 1: Core Infrastructure
- [ ] Move Noise-NK implementation to `prototype/src/openadp/`
- [ ] Implement server-side session management
- [ ] Add `noise_handshake` and `encrypted_call` handlers
- [ ] Basic client library extension

### Phase 2: Integration
- [ ] Integrate with existing JSON-RPC handler
- [ ] Add client-side `encrypted=True` parameter
- [ ] Implement transparent 2-round flow
- [ ] Error handling and fallback logic

### Phase 3: Production Readiness  
- [ ] Performance optimization
- [ ] Comprehensive testing
- [ ] Key distribution mechanism
- [ ] Monitoring and alerting
- [ ] Documentation and examples

## Trade-offs and Decisions

### Why Single Endpoint?
**Decision**: Use same endpoint for encrypted/unencrypted traffic
**Rationale**: Simpler deployment, same handler class, easier routing
**Trade-off**: Slightly more complex method dispatch logic

### Why 2-Round Instead of 1-Round?
**Decision**: Separate handshake and encrypted call
**Rationale**: Clear separation, easier debugging, standard Noise-NK flow
**Trade-off**: Extra network round-trip for encrypted calls

### Why Session-Per-Call?
**Decision**: Destroy session after single method call
**Rationale**: Stateless server, no session cleanup complexity, perfect forward secrecy
**Trade-off**: Cannot amortize handshake cost over multiple calls

### Why 16-byte Session IDs?
**Decision**: Use 16 random bytes for session identification
**Rationale**: 128-bit entropy prevents collision, standard size
**Trade-off**: Slightly larger than necessary, but negligible overhead

## Future Enhancements

### Possible Optimizations
- **Batch Calls**: Single handshake for multiple method calls
- **Connection Reuse**: Longer-lived sessions for interactive clients
- **Zero-RTT**: Send encrypted data in first handshake message
- **Key Rotation**: Automatic server key rotation with overlap period

### Monitoring Additions
- **Encryption Ratio**: Track percentage of calls using encryption
- **Performance Impact**: Measure latency overhead of encrypted calls
- **Error Rates**: Monitor handshake failures and decryption errors
- **Resource Usage**: Track memory and CPU impact of session management

## Conclusion

This design provides strong end-to-end encryption while maintaining backward compatibility and operational simplicity. The Noise-NK protocol gives us excellent security properties with a clean implementation path that fits well within our existing JSON-RPC architecture.

The key insight is treating encryption as a transport-level concern that's transparent to the business logic layer, while using the JSON-RPC method dispatch to route between encrypted and unencrypted code paths. 