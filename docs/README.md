# 📚 OpenADP Documentation Hub

**Welcome to the comprehensive OpenADP documentation center!** All documentation has been consolidated and reorganized for maximum clarity and usability.

## 🚀 Start Here

### Core Documentation (New!)
- **[Getting Started](GETTING_STARTED.md)** - Complete guide from installation to production integration
- **[SDK Guide](SDK_GUIDE.md)** - Unified documentation for all 6+ language SDKs
- **[API Reference](API_REFERENCE.md)** - Detailed technical reference for all functions
- **[Security Model](SECURITY_MODEL.md)** - Threat model, audit results, and compliance information

### Quick Navigation
- **New to OpenADP?** → Start with [Getting Started](GETTING_STARTED.md)
- **Integrating into your app?** → See [SDK Guide](SDK_GUIDE.md)  
- **Need API details?** → Check [API Reference](API_REFERENCE.md)
- **Security questions?** → Read [Security Model](SECURITY_MODEL.md)

## 🛠️ Technical Documentation

### Architecture & Design
- **[Project Overview](PROJECT-OVERVIEW.md)** - High-level project goals and architecture
- **[Server API](SERVER_API.md)** - Complete server API specification
- **[Ocrypt Design](ocrypt_design.md)** - Cryptographic design and implementation

### Security & Cryptography
- **[Noise-NK Encryption Design](NOISE_NK_ENCRYPTION_DESIGN.md)** - Noise-NK protocol implementation details
- **[Noise-NK Guide](NOISE_NK_GUIDE.md)** - Guide for implementing Noise-NK protocol
- **[Fuzz Testing](FUZZ_TESTING.md)** - Fuzzing and security testing documentation

### Development Resources
- **[Comprehensive Test Plan](comprehensive-test-plan.md)** - Testing strategy and coverage requirements
- **[Authentication Code Design](authentication-code-design.md)** - Authentication system design
- **[Detailed Design](detailed-design.md)** - Comprehensive technical design document

## 🌍 Production-Ready SDKs

OpenADP provides **production-ready SDKs** in 6+ languages:

| Language | Status | Package/Import | Installation |
|----------|---------|----------------|--------------|
| **Python** | ✅ Production | `from openadp import ocrypt` | `pip install openadp` |
| **JavaScript (Node.js)** | ✅ Production | `import { register, recover } from '@openadp/sdk'` | `npm install @openadp/sdk` |
| **JavaScript (Browser)** | ✅ Production | `import { register, recover } from './sdk/browser-javascript/ocrypt.js'` | Include from local files |
| **Go** | ✅ Production | `github.com/OpenADP/openadp/sdk/go/ocrypt` | `go get github.com/OpenADP/openadp/sdk/go@latest` |
| **Rust** | ✅ Production | `openadp_ocrypt` | `cargo add openadp-ocrypt` |
| **C++** | ✅ Production | `#include <openadp/ocrypt.hpp>` | Build from source |

## 📋 Current Status

### What's Working
- ✅ **Multi-Language SDKs**: Working implementations in 6+ languages
- ✅ **Unified API**: Consistent `register()` and `recover()` functions across all languages
- ✅ **Cross-Language Compatibility**: All SDKs interoperate seamlessly
- ✅ **Browser Support**: JavaScript SDK works in browsers with WebCrypto API
- ✅ **Test Vector Framework**: Comprehensive test vectors for cross-language validation
- ✅ **Production Ready**: All SDKs handle network failures, retries, and error cases
- ✅ **Comprehensive Documentation**: Consolidated guides for all use cases

### Demo Application
- **[👻 Ghost Notes](../ghost-notes/README.md)** - Complete OpenADP-enabled web application demonstrating secure note-taking

## 🎯 API Overview

All SDKs provide the same simple 2-function API:

**Python:**
```python
from openadp import ocrypt

# Protect a secret with a PIN
metadata = ocrypt.register("user@example.com", "myapp", secret_bytes, "1234", 10)

# Later: recover the secret
secret, remaining, updated_metadata = ocrypt.recover(metadata, "1234")
```

**JavaScript:**
```javascript
import { register, recover } from '@openadp/sdk';

// Protect a secret with a PIN
const metadata = await register("user@example.com", "myapp", secretBytes, "1234", 10);

// Later: recover the secret
const { secret, remaining, updatedMetadata } = await recover(metadata, "1234");
```

**Go:**
```go
import "github.com/OpenADP/openadp/sdk/go/ocrypt"

// Protect a secret with a PIN
metadata, err := ocrypt.Register("user@example.com", "myapp", secretBytes, "1234", 10, "")

// Later: recover the secret
secret, remaining, updatedMetadata, err := ocrypt.Recover(metadata, "1234", "")
```

## 🚀 Getting Started

1. **Choose your language** from the SDKs above
2. **Install the SDK** using the provided installation command
3. **Follow the [Getting Started Guide](GETTING_STARTED.md)** for detailed setup
4. **Review the [API Reference](API_REFERENCE.md)** for complete function documentation
5. **Check the [Security Model](SECURITY_MODEL.md)** to understand the security guarantees

## 📁 Key Files & Directories

### SDK Implementations
- `../sdk/go/ocrypt/ocrypt.go` - Go reference implementation
- `../sdk/python/openadp/ocrypt.py` - Python SDK implementation  
- `../sdk/javascript/src/ocrypt.js` - JavaScript SDK implementation
- `../sdk/browser-javascript/ocrypt.js` - Browser-compatible JavaScript SDK
- `../sdk/rust/src/ocrypt.rs` - Rust SDK implementation
- `../sdk/cpp/src/ocrypt.cpp` - C++ SDK implementation

### Testing & Validation
- `../test_vectors.json` - Cross-language compatibility test vectors
- `../run_all_tests.py` - Comprehensive test runner for all languages
- `../ghost-notes/` - Demo application showcasing OpenADP integration

---

This documentation provides comprehensive coverage of OpenADP's **production-ready, multi-language SDK ecosystem** providing distributed cryptographic protection for user data with **information-theoretic security** against even quantum computers and nation-state attacks. 