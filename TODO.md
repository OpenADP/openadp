# OpenADP TODO List

## High Priority

### Security Improvements
- [ ] **Sign servers.json to remove Cloudflare from TCB**
  - Implement cryptographic signing of the server list
  - Allow clients to verify server list authenticity without trusting Cloudflare
  - Use Ed25519 signatures with a well-known public key
  - Priority: High (reduces trust dependencies)

## Medium Priority

### Health Monitoring & Operations
- [ ] **Health monitoring dashboard**
  - Public dashboard for server selection
  - Volunteer dashboard with detailed metrics and alerts
  - Real-time server status and historical data

- [ ] **Alert system for server operators**
  - Discord notifications for real-time issues
  - Email alerts for node operators when their server is down
  - Configurable thresholds (>15% error rate for 30+ minutes)

### Protocol Enhancements
- [ ] **Post-quantum cryptography migration plan**
  - Research NIST post-quantum standards
  - Plan migration path for existing deployments
  - Implement hybrid classical/post-quantum approach

- [ ] **Zero-knowledge proof integration**
  - Enhanced privacy for authentication
  - Reduce metadata leakage during recovery operations

### Application Integrations
- [ ] **Browser extension SDK**
  - Password manager integration
  - Seamless backup/recovery for web applications

- [ ] **Mobile app SDK**
  - iOS and Android libraries
  - Native integration for mobile backup applications

## Low Priority

### Development & Testing
- [ ] **Comprehensive fuzzing**
  - Expand fuzz testing to cover more edge cases
  - Protocol-level fuzzing for network communications

- [ ] **Performance optimization**
  - Profile and optimize cryptographic operations
  - Reduce memory allocation in hot paths

### Documentation
- [ ] **API documentation improvements**
  - OpenAPI/Swagger specifications
  - Interactive API explorer

- [ ] **Deployment guides**
  - Docker containerization
  - Kubernetes deployment manifests
  - Cloud provider specific guides

## Completed Items

### Phase 1-5 (Completed)
- [x] Core cryptographic operations (Ed25519, Shamir secret sharing)
- [x] Distributed threshold recovery system
- [x] Authentication system with OAuth 2.0 + DPoP
- [x] Noise-NK encryption for client-server communication
- [x] Production-ready Go implementation
- [x] Comprehensive test suite with fuzz testing
- [x] Automated node operator installation scripts
- [x] Website with volunteer recruitment and developer ecosystem
- [x] Multi-platform builds and deployment automation

---

**Last Updated**: January 2025  
**Next Review**: Quarterly or when priorities change

## Contributing

When adding items to this TODO:
1. Categorize by priority (High/Medium/Low)
2. Include brief description and rationale
3. Estimate complexity if known
4. Move completed items to the "Completed Items" section 