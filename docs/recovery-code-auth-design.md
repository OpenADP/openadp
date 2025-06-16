# OpenADP Recovery Code Authentication System Design

**Version 1.0 — Recovery Code Authentication Redesign**  
**Date:** January 2025  
**Status:** Design Phase

---

## 1. Executive Summary

This document proposes a fundamental redesign of OpenADP's authentication system, replacing the current centralized OAuth/DPoP architecture with a distributed recovery code system. This change eliminates the single point of failure inherent in centralized authentication while dramatically simplifying the system architecture.

### Key Changes
- **Replace**: Centralized Keycloak + OAuth/DPoP flows
- **With**: Distributed recovery code authentication
- **Result**: No single point of failure, 10x simpler architecture, better user experience

---

## 2. Problem Statement

### Current System Flaws
1. **Single Point of Failure**: Global Keycloak server at `https://auth.openadp.org`
2. **Architectural Complexity**: OAuth + DPoP + Noise-NK + JWT validation
3. **Browser Dependencies**: Device code flows require user interaction
4. **Performance Overhead**: 5+ network round trips for authentication
5. **Operational Burden**: Maintaining global authentication infrastructure

### Design Goals
1. **Eliminate SPOF**: No central authentication dependency
2. **Simplify Architecture**: Reduce complexity by 90%
3. **Maintain Security**: Preserve authentication requirements
4. **Improve UX**: Faster, simpler authentication flow
5. **Enable Offline**: Work without internet connectivity to auth servers

---

## 3. Recovery Code Authentication Model

### Core Concept
Users obtain a **base recovery code** from their trusted cloud provider (Apple, Google, Microsoft, etc.). This code is then used to derive **server-specific recovery codes** for each OpenADP server.

### Mathematical Foundation
```
Base Recovery Code: 256-bit random value from user's cloud provider
Server Recovery Code = SHA256(base_recovery_code || server_url)
```

### Trust Model
- **User's Cloud Provider**: Authenticates user, provides base recovery code
- **OpenADP Servers**: Validate server-specific recovery codes independently
- **No Central Authority**: Each server operates autonomously

---

## 4. System Architecture

### 4.1 High-Level Flow

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User's Cloud  │    │   OpenADP Client │    │  OpenADP Server │
│   Provider      │    │                  │    │                 │
│  (Apple/Google) │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ 1. Authenticate       │                       │
         │ ◄─────────────────────┤                       │
         │                       │                       │
         │ 2. Base Recovery Code │                       │
         │ ──────────────────────►                       │
         │                       │                       │
         │                       │ 3. Derive Server Code │
         │                       │ ──────────────────────►
         │                       │                       │
         │                       │ 4. Register/Recover   │
         │                       │ ──────────────────────►
         │                       │                       │
         │                       │ 5. Success/Failure    │
         │                       │ ◄──────────────────────
```

### 4.2 Recovery Code Format

```
Base Recovery Code: 64 hex characters (256 bits)
Example: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"

Server Recovery Code: SHA256 hash (64 hex characters)
Example: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

### 4.3 Server-Side Validation

```python
def validate_recovery_code(recovery_code: str, server_url: str) -> bool:
    # 1. Format validation
    if not re.match(r'^[0-9a-f]{64}$', recovery_code):
        return False
    
    # 2. Entropy check (prevent trivial codes)
    if calculate_entropy(recovery_code) < MIN_ENTROPY_BITS:
        return False
    
    # 3. Blacklist check (known bad patterns)
    if recovery_code in BLACKLISTED_CODES:
        return False
    
    return True
```

---

## 5. Security Analysis

### 5.1 Security Properties Maintained

| Property | Current System | Recovery Code System |
|----------|----------------|---------------------|
| **Authentication Required** | ✅ OAuth + DPoP | ✅ Cloud provider auth |
| **Replay Protection** | ✅ JTI cache | ✅ Per-backup usage tracking |
| **Rate Limiting** | ✅ Per-user quotas | ✅ Per-code quotas |
| **Audit Trail** | ✅ JWT sub claims | ✅ Recovery code hashes |

### 5.2 Security Improvements

1. **No Token Theft**: Recovery codes are single-use per backup
2. **Perfect Forward Secrecy**: No long-lived tokens to compromise
3. **Server Isolation**: Compromise of one server doesn't affect others
4. **Privacy Enhancement**: Servers never learn user identity

### 5.3 Threat Analysis

| Threat | Mitigation |
|--------|------------|
| **Fake Recovery Codes** | Entropy validation, proof-of-work, rate limiting |
| **Code Reuse Attacks** | Per-backup usage tracking, expiration |
| **DDoS Amplification** | Adaptive proof-of-work, IP rate limiting |
| **Server Compromise** | Codes are server-specific, limited blast radius |

---

## 6. DDoS Defense Strategy

### 6.1 Adaptive Proof-of-Work

```python
class AdaptiveDDoSDefense:
    def __init__(self):
        self.base_difficulty = 0
        self.max_difficulty = 24
        self.load_threshold = 0.7
    
    def get_required_difficulty(self) -> int:
        current_load = self.measure_server_load()
        
        if current_load < self.load_threshold:
            return self.base_difficulty
        
        # Exponential difficulty increase
        excess_load = current_load - self.load_threshold
        additional_bits = int(excess_load * 20)  # Up to 20 extra bits
        
        return min(self.base_difficulty + additional_bits, self.max_difficulty)
    
    def verify_proof_of_work(self, nonce: str, difficulty: int, 
                           challenge: str) -> bool:
        hash_input = f"{challenge}:{nonce}"
        hash_result = hashlib.sha256(hash_input.encode()).hexdigest()
        
        # Check if hash has required number of leading zeros
        required_prefix = "0" * difficulty
        return hash_result.startswith(required_prefix)
```

### 6.2 Time-Lock Puzzles

```python
def create_time_lock_puzzle(difficulty_seconds: int) -> dict:
    """Create a puzzle that takes 'difficulty_seconds' to solve."""
    # Based on repeated squaring in RSA groups
    # Client must compute: result = base^(2^iterations) mod n
    
    return {
        "base": random_base(),
        "modulus": generate_rsa_modulus(),
        "iterations": calculate_iterations_for_time(difficulty_seconds),
        "challenge_id": generate_challenge_id()
    }
```

### 6.3 Multi-Layer Defense

1. **Pre-Authentication Rate Limiting**: IP-based, geographic
2. **Recovery Code Validation**: Format, entropy, blacklists
3. **Proof-of-Work**: Adaptive difficulty based on server load
4. **Time-Lock Puzzles**: Force minimum time delays
5. **Behavioral Analysis**: Detect automated attack patterns

---

## 7. Implementation Architecture

### 7.1 Server-Side Changes

#### New Authentication Middleware
```python
class RecoveryCodeAuth:
    def __init__(self, config):
        self.ddos_defense = AdaptiveDDoSDefense()
        self.code_usage_tracker = RecoveryCodeTracker()
        self.blacklist = RecoveryCodeBlacklist()
    
    def authenticate_request(self, recovery_code: str, 
                           request_context: dict) -> AuthResult:
        # 1. DDoS defense
        if self.ddos_defense.is_defense_active():
            if not self.verify_proof_of_work(request_context):
                return AuthResult.PROOF_OF_WORK_REQUIRED
        
        # 2. Recovery code validation
        if not self.validate_recovery_code(recovery_code):
            return AuthResult.INVALID_CODE
        
        # 3. Usage tracking
        if self.code_usage_tracker.is_exhausted(recovery_code):
            return AuthResult.CODE_EXHAUSTED
        
        return AuthResult.SUCCESS
```

#### Updated RPC Handlers
```python
def register_secret(recovery_code: str, uid: str, did: str, 
                   bid: str, secret_share: bytes) -> RPCResponse:
    # Authenticate
    auth_result = auth_middleware.authenticate_request(recovery_code, request)
    if not auth_result.success:
        return error_response(auth_result.error_message)
    
    # Store secret with recovery code as key
    secret_key = f"{recovery_code}:{uid}:{did}:{bid}"
    database.store_secret(secret_key, secret_share)
    
    # Track usage
    auth_middleware.record_usage(recovery_code, uid, did, bid)
    
    return success_response()
```

### 7.2 Client-Side Changes

#### Recovery Code Management
```python
class RecoveryCodeManager:
    def __init__(self, cloud_provider: CloudProvider):
        self.cloud_provider = cloud_provider
        self.code_cache = {}
    
    def get_base_recovery_code(self) -> str:
        """Get base recovery code from user's cloud provider."""
        # This would integrate with iCloud, Google Drive, etc.
        return self.cloud_provider.get_recovery_code()
    
    def derive_server_code(self, base_code: str, server_url: str) -> str:
        """Derive server-specific recovery code."""
        combined = f"{base_code}:{server_url}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def get_server_codes(self, server_urls: list) -> dict:
        """Get recovery codes for all servers."""
        base_code = self.get_base_recovery_code()
        
        return {
            url: self.derive_server_code(base_code, url)
            for url in server_urls
        }
```

#### Updated Client Tools
```python
def encrypt_file(filename: str, servers: list) -> None:
    # Get recovery codes for all servers
    recovery_manager = RecoveryCodeManager(get_cloud_provider())
    server_codes = recovery_manager.get_server_codes(servers)
    
    # Register secret with each server
    for server_url, recovery_code in server_codes.items():
        client = OpenADPClient(server_url)
        client.register_secret(
            recovery_code=recovery_code,
            uid=user_id,
            did=device_id,
            bid=backup_id,
            secret_share=secret_shares[server_url]
        )
```

### 7.3 Cloud Provider Integration

#### Abstract Interface
```python
class CloudProvider(ABC):
    @abstractmethod
    def authenticate_user(self) -> bool:
        """Authenticate user with cloud provider."""
        pass
    
    @abstractmethod
    def get_recovery_code(self) -> str:
        """Get base recovery code for authenticated user."""
        pass
    
    @abstractmethod
    def store_recovery_code(self, code: str) -> bool:
        """Store recovery code securely in cloud."""
        pass
```

#### Implementation Examples
```python
class iCloudProvider(CloudProvider):
    def get_recovery_code(self) -> str:
        # Use iCloud Keychain API
        return keychain.get_item("openadp_recovery_code")

class GoogleDriveProvider(CloudProvider):
    def get_recovery_code(self) -> str:
        # Use Google Drive API with app-specific folder
        return drive_api.get_file_content("openadp_recovery_code.txt")
```

---

## 8. Migration Strategy

### 8.1 Backward Compatibility

During migration, servers will support both authentication methods:

```python
def authenticate_request(request) -> AuthResult:
    # Try recovery code authentication first
    if 'recovery_code' in request.headers:
        return recovery_code_auth.authenticate(request)
    
    # Fall back to OAuth/DPoP for legacy clients
    if 'authorization' in request.headers:
        return oauth_auth.authenticate(request)
    
    return AuthResult.UNAUTHORIZED
```

### 8.2 Migration Phases

See Implementation Phases section below for detailed breakdown.

---

## 9. Performance Analysis

### 9.1 Authentication Latency Comparison

| Operation | Current System | Recovery Code System | Improvement |
|-----------|----------------|---------------------|-------------|
| **First Auth** | ~5-10 seconds | ~100ms | 50-100x faster |
| **Subsequent Auth** | ~500ms | ~10ms | 50x faster |
| **Network Calls** | 5+ round trips | 1 round trip | 5x fewer |
| **Browser Dependency** | Required | None | Eliminated |

### 9.2 Server Resource Usage

| Resource | Current System | Recovery Code System | Improvement |
|----------|----------------|---------------------|-------------|
| **Memory** | JWT cache + JWKS cache | Recovery code tracker | 80% reduction |
| **CPU** | JWT validation + DPoP | SHA256 + entropy check | 90% reduction |
| **Network** | JWKS fetching | None | 100% reduction |
| **Dependencies** | PyJWT, cryptography | hashlib (built-in) | Simplified |

---

## 10. Operational Benefits

### 10.1 Deployment Simplification

**Removed Components:**
- Keycloak server infrastructure
- OAuth endpoint configuration
- JWKS caching and refresh logic
- DPoP key management
- JWT validation libraries

**Simplified Configuration:**
```yaml
# Old configuration (50+ lines)
auth:
  enabled: true
  issuer: https://auth.openadp.org/realms/openadp
  jwks_url: https://auth.openadp.org/realms/openadp/protocol/openid-connect/certs
  cache_ttl: 3600
  dpop_validation: true
  # ... many more options

# New configuration (5 lines)
auth:
  enabled: true
  min_entropy_bits: 128
  max_attempts_per_code: 10
  ddos_defense: adaptive
```

### 10.2 Monitoring and Alerting

**Simplified Metrics:**
- Recovery code validation rate
- DDoS defense activation frequency
- Server load and response times
- Code usage patterns

**Removed Complexity:**
- OAuth flow monitoring
- JWT validation failures
- JWKS fetch failures
- Token refresh cycles

---

## 11. Implementation Phases

### Phase 1: Core Recovery Code Infrastructure (2-3 weeks)

**Objectives:**
- Implement basic recovery code validation
- Create server-side authentication middleware
- Add recovery code support to existing RPC handlers

**Deliverables:**
1. **Recovery Code Validation Library**
   - Format validation (64 hex chars)
   - Entropy calculation and checking
   - Blacklist management
   - Unit tests (>95% coverage)

2. **Server Authentication Middleware**
   - `RecoveryCodeAuth` class
   - Integration with existing `jsonrpc_server.py`
   - Backward compatibility with OAuth (dual-mode)
   - Configuration management

3. **Database Schema Updates**
   - Add recovery code tracking tables
   - Usage counters per code/backup combination
   - Migration scripts from existing auth data

4. **Basic Client Support**
   - `RecoveryCodeManager` class
   - Manual recovery code input (CLI)
   - Integration with existing client tools

**Success Criteria:**
- [ ] Recovery code validation working with 100% test coverage
- [ ] Server accepts both OAuth and recovery code auth
- [ ] Basic client can authenticate with manual recovery codes
- [ ] All existing tests pass with dual-mode authentication

### Phase 2: DDoS Defense Implementation (2-3 weeks)

**Objectives:**
- Implement adaptive proof-of-work system
- Add time-lock puzzle support
- Create comprehensive rate limiting

**Deliverables:**
1. **Adaptive Proof-of-Work**
   - `AdaptiveDDoSDefense` class
   - Server load monitoring
   - Dynamic difficulty adjustment
   - Client-side PoW solver

2. **Time-Lock Puzzles**
   - RSA-based time-lock implementation
   - Configurable difficulty levels
   - Client-side puzzle solver
   - Server-side verification

3. **Multi-Layer Rate Limiting**
   - IP-based pre-authentication limits
   - Recovery code usage tracking
   - Geographic filtering capabilities
   - Behavioral analysis (basic)

4. **Monitoring and Alerting**
   - DDoS attack detection
   - Defense activation metrics
   - Performance impact monitoring
   - Alert integration (email, Slack, etc.)

**Success Criteria:**
- [ ] System survives simulated DDoS attacks
- [ ] Proof-of-work difficulty adapts to server load
- [ ] Time-lock puzzles work correctly
- [ ] Legitimate users unaffected during attacks
- [ ] Comprehensive monitoring dashboard

### Phase 3: Cloud Provider Integration (3-4 weeks)

**Objectives:**
- Integrate with major cloud providers
- Implement secure recovery code storage
- Create user-friendly setup flows

**Deliverables:**
1. **Cloud Provider Abstractions**
   - `CloudProvider` abstract base class
   - Authentication flow interfaces
   - Secure storage abstractions
   - Error handling and retry logic

2. **Provider Implementations**
   - iCloud Keychain integration
   - Google Drive API integration
   - Microsoft OneDrive support
   - Local encrypted storage fallback

3. **User Setup Flows**
   - First-time setup wizard
   - Recovery code generation and storage
   - Provider selection and configuration
   - Backup and recovery procedures

4. **Security Enhancements**
   - Recovery code encryption at rest
   - Provider authentication validation
   - Secure key derivation (PBKDF2/Argon2)
   - Audit logging for code access

**Success Criteria:**
- [ ] Users can seamlessly get recovery codes from cloud providers
- [ ] Recovery codes stored securely in user's cloud
- [ ] Setup process takes <5 minutes for new users
- [ ] Recovery works across devices and platforms
- [ ] Security audit passes with no critical issues

### Phase 4: Client Tool Integration (2-3 weeks)

**Objectives:**
- Update all client tools to use recovery codes
- Implement automatic cloud provider detection
- Create migration tools for existing users

**Deliverables:**
1. **Updated Client Tools**
   - `encrypt.py` with recovery code auth
   - `decrypt.py` with automatic code retrieval
   - Removal of OAuth/DPoP dependencies
   - Simplified command-line interfaces

2. **Automatic Provider Detection**
   - Platform detection (macOS, Windows, Linux)
   - Cloud provider availability checking
   - Fallback to manual entry if needed
   - User preference storage

3. **Migration Tools**
   - OAuth-to-recovery-code migration script
   - Existing backup re-authentication
   - Bulk migration for enterprise users
   - Migration status tracking

4. **Documentation Updates**
   - Updated user guides
   - API documentation
   - Troubleshooting guides
   - Video tutorials

**Success Criteria:**
- [ ] All client tools work with recovery codes
- [ ] Migration from OAuth completes successfully
- [ ] New user onboarding takes <10 minutes
- [ ] Documentation is comprehensive and clear
- [ ] User acceptance testing passes

### Phase 5: Testing and Validation (2-3 weeks)

**Objectives:**
- Comprehensive end-to-end testing
- Performance benchmarking
- Security penetration testing
- Load testing and optimization

**Deliverables:**
1. **Comprehensive Test Suite**
   - E2E tests with real cloud providers
   - Multi-server failure scenarios
   - Concurrent user testing
   - Edge case validation

2. **Performance Benchmarking**
   - Authentication latency measurements
   - Server resource usage analysis
   - Scalability testing
   - Comparison with OAuth system

3. **Security Testing**
   - Penetration testing by external firm
   - Code review by security experts
   - Vulnerability scanning
   - Threat model validation

4. **Load Testing**
   - Simulated user load testing
   - DDoS attack simulations
   - Server capacity planning
   - Performance optimization

**Success Criteria:**
- [ ] All tests pass with >99% reliability
- [ ] Performance meets or exceeds OAuth system
- [ ] Security audit finds no critical vulnerabilities
- [ ] System handles 10x expected load
- [ ] Ready for production deployment

### Phase 6: Production Deployment (2-3 weeks)

**Objectives:**
- Deploy to production servers
- Monitor system performance
- Gradual rollout to users
- Remove OAuth dependencies

**Deliverables:**
1. **Production Deployment**
   - Staged rollout to production servers
   - Blue-green deployment strategy
   - Rollback procedures
   - Monitoring and alerting setup

2. **User Migration**
   - Gradual user migration from OAuth
   - Support for mixed authentication during transition
   - User communication and support
   - Migration success tracking

3. **OAuth Deprecation**
   - Removal of OAuth/DPoP code
   - Keycloak server decommissioning
   - Documentation updates
   - Final security audit

4. **Post-Deployment Monitoring**
   - 24/7 monitoring setup
   - Performance metrics collection
   - User feedback collection
   - Incident response procedures

**Success Criteria:**
- [ ] 100% of users migrated to recovery codes
- [ ] OAuth system completely removed
- [ ] No production incidents during migration
- [ ] User satisfaction scores >90%
- [ ] System performance exceeds baseline

---

## 12. Risk Assessment and Mitigation

### High-Risk Items

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **DDoS attacks overwhelm system** | Medium | High | Comprehensive defense layers, monitoring |
| **Cloud provider API changes** | Medium | Medium | Multiple provider support, fallback options |
| **User adoption resistance** | Low | Medium | Clear migration path, user education |
| **Security vulnerabilities** | Low | High | External security audit, penetration testing |

### Medium-Risk Items

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Performance degradation** | Low | Medium | Extensive load testing, optimization |
| **Migration complexity** | Medium | Low | Phased rollout, comprehensive testing |
| **Documentation gaps** | Medium | Low | User testing, feedback incorporation |

---

## 13. Success Metrics

### Technical Metrics
- **Authentication Latency**: <100ms (vs 5-10s current)
- **System Availability**: >99.9% (vs current Keycloak dependency)
- **Resource Usage**: <20% of current server resources
- **Code Complexity**: <10% of current authentication code

### User Experience Metrics
- **Setup Time**: <5 minutes for new users
- **Authentication Success Rate**: >99.5%
- **User Satisfaction**: >90% positive feedback
- **Support Tickets**: <50% of current auth-related tickets

### Security Metrics
- **Zero Critical Vulnerabilities**: External security audit
- **DDoS Resistance**: Survive 10x normal load
- **Privacy Enhancement**: No user identity leakage to servers
- **Attack Surface Reduction**: 90% fewer external dependencies

---

## 14. Conclusion

The recovery code authentication system represents a fundamental architectural improvement for OpenADP. By eliminating the single point of failure inherent in centralized authentication and dramatically simplifying the system, we achieve:

1. **Better Reliability**: No central auth server dependency
2. **Improved Security**: Enhanced privacy and reduced attack surface  
3. **Superior User Experience**: Faster, simpler authentication
4. **Operational Excellence**: Easier deployment and maintenance
5. **Architectural Alignment**: Distributed trust model matches OpenADP philosophy

The proposed implementation phases provide a clear path forward with manageable risk and measurable progress. The system can be deployed incrementally while maintaining backward compatibility, ensuring a smooth transition for existing users.

This redesign positions OpenADP as a truly distributed, resilient system that can scale globally without central dependencies—fulfilling the original vision of nation-state-resistant data protection.
