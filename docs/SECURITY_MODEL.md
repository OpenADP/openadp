# OpenADP Security Model

Initial security analysis of the OpenADP distributed cryptography system.

## Executive Summary

OpenADP provides **information-theoretic security** for secret protection using distributed threshold cryptography. Even weak PINs like "3344" become cryptographically strong when protected by the OpenADP network.

### Key Security Guarantees

- **🔐 Information-Theoretic Security**: Attackers learn nothing about your PIN or secret, even with unlimited computational power
- **🛡️ Nation-State Resistant**: Secure against government coercion of individual servers
- **⚡ Quantum Resistant**: Immune to quantum computer attacks
- **🌍 No Single Point of Failure**: Distributed across multiple countries and jurisdictions
- **🔒 Zero-Knowledge**: Servers never see your PIN or secret data

---

## Threat Model

### Protected Against

#### ✅ Server Compromise
- **Scenario**: Attacker compromises up to t-1 servers (where t is the threshold)
- **Protection**: Threshold cryptography ensures insufficient information to reconstruct secrets
- **Result**: Complete security maintained

#### ✅ Network Eavesdropping  
- **Scenario**: Attacker monitors all network traffic
- **Protection**: TLS encryption + Noise-NK + zero-knowledge proofs
- **Result**: No sensitive information exposed even if TLS is compromised

#### ✅ Offline Brute Force Attacks
- **Scenario**: Attacker obtains metadata and attempts offline PIN cracking
- **Protection**: 128-bit security level, attacker has negligible chance
- **Result**: Even weak PINs are protected due to limited guesses

#### ✅ Quantum Computer Attacks
- **Scenario**: Attacker uses quantum computers to break cryptographic primitives
- **Protection**: Information-theoretic security for pins doesn't rely on computational hardness
- **Result**: Quantum-resistant by design, though TLS and Noise-NK layers could be broken

#### ✅ Database Breaches
- **Scenario**: Attacker steals application database containing metadata
- **Protection**: Metadata contains no recoverable information without PIN
- **Result**: Attacker could DoS users, and succeed in guessing a small fraction of PINs

#### ✅ Government/Legal Coercion
- **Scenario**: Government forces individual servers to cooperate
- **Protection**: Distributed across multiple jurisdictions, threshold security
- **Result**: No single government can access user data against the will of node operators

#### ✅ Insider Threats
- **Scenario**: Malicious employees at server providers
- **Protection**: Noise-NK prevent insider access to secrets

### Not Protected Against

#### ❌ Client-Side Malware
- **Scenario**: Malware on user's device steals PIN during entry
- **Mitigation**: Use secure PIN entry methods, endpoint protection
- **Note**: This is a client-side vulnerability, not a protocol weakness

#### ❌ Social Engineering
- **Scenario**: Attacker tricks user into revealing PIN
- **Mitigation**: User education, phishing protection
- **Note**: Human factors are outside the cryptographic protocol

#### ❌ Physical Device Access
- **Scenario**: Attacker has physical access to unlocked device
- **Mitigation**: Device locking, biometric authentication
- **Note**: Standard mobile security best practices apply

#### ❌ Simultaneous Compromise of All Servers
- **Scenario**: Unprecedented coordinated attack on entire network
- **Probability**: Extremely low due to geographic/jurisdictional distribution
- **Note**: Would require simultaneous compromise across multiple countries

---

## Cryptographic Design

### Threshold Secret Sharing

OpenADP uses **Shamir's Secret Sharing** with the following parameters:

- **Threshold (t)**: Default of floor(N/2) + 1 servers required for reconstruction
- **Total Shares (n)**: Typically 15 servers hold shares
- **Security**: Information-theoretic - no computational assumptions

```
Example: (9,15) threshold scheme
- Secret split into 15 shares
- Any 9 shares can reconstruct the secret
- 8 or fewer shares reveal nothing
```

### Zero-Knowledge PIN Verification

PIN verification uses **zero-knowledge proofs** ensuring:

- Servers never see the actual PIN
- Servers can verify PIN correctness without learning it
- Failed attempts are tracked without exposing the PIN
- Information-theoretic security preserved

**Protocol Flow:**
1. Client derives verification key from PIN using secure hash
2. Client generates zero-knowledge proof of PIN knowledge
3. Servers verify proof without learning PIN
4. Servers return blinded shares which are valid only if PIN is correct

### Cryptographic Primitives

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| **Secret Sharing** | Shamir's Secret Sharing | Information-theoretic |
| **Symmetric Encryption** | AES-256-GCM | 128-bit security |
| **Key Derivation** | HKDF-SHA256 | 256-bit security |
| **Transport Security** | TLS 1.3 | Post-quantum ready |
| **Digital Signatures** | Ed25519 | 126-bit security |

### Randomness and Key Generation

- **Entropy Source**: OS cryptographically secure random number generator
- **Key Derivation**: HKDF with unique salt per operation
- **Share Generation**: Cryptographically secure polynomial evaluation
- **Nonce Generation**: Unique per operation, never reused

---

## Security Protocols

### Registration Protocol

```
1. Client generates random secret `s`
2. Client splits `s` into n shares using Shamir's Secret Sharing
4. Client sends shares to servers, encrypted over Noise-NK
5. Servers store plaintext shares
6. Client receives confirmation and constructs metadata
```

**Security Properties:**
- Servers never see the secret `s`, nor the PIN
- Each server sees only their share
- Threshold number of servers needed for reconstruction
- Metadata is sensitive information that enables an attacker to make PIN guesses

### Recovery Protocol

```
1. Client hashes userID + PIN to point U on the curve
2. Client computes blinted point B = r*U, where r is random in [1..Q-1]
3. Client preovides blinded point B to servers derived from their PIN
4. Servers return return `s[i]*B`
5. Client reconstructs `s*B`, and unblineds by `s*U = (1/r)s*B`
```

**Security Properties:**
- PIN never transmitted to servers
- Failed attempts tracked distributedly
- Servers cannot collude to learn PIN
- Perfect forward secrecy maintained

### Guess Limiting Protocol

```
1. Each server maintains independent guess counter
2. Each server increments counter on eacy recovery attempt
3. Backup share locked when max guesses exceeded
4. Distributed locking prevents bypass
```

**Security Properties:**
- No single server can lock an account
- No single server can reset counters
- Partial Byzantine fault tolerance: attacker must allow messages to be delivered

---

## Operational Security

### Server Infrastructure

**Geographic Distribution: Goal, not yet achieved**
- Servers in 5+ countries across 3+ continents
- No single jurisdiction controls majority
- Diverse legal and regulatory environments

**Server Security:**
- OpenADP node operator volunteers cross-authenticate each other
- Future: cross-singing of Noise-NK public keys by node operators

### Network Security

**DDoS Protection:**
- CloudFlare protection
- Distributed anycast network
- Automated traffic filtering
- Rate limiting and throttling

**Noise-NK Configuration:**
- Prevents access by MitM corporate monitoring devices and by Cloudflare
- Perfect forward secrecy

### Future: Monitoring and Alerting

**Recommended Monitoring:**
- Failed authentication attempts
- Network connectivity issues
- Server response times
- Unusual access patterns

**Alerting Thresholds:**
- Multiple failed attempts from same IP
- Unusual geographic access patterns
- Server downtime or degradation
- Metadata corruption detection

---

## Conclusion

The combination of information-theoretic security, geographic distribution, and oblivious protocols creates a uniquely robust security posture that protects user secrets even when individual components are compromised.
