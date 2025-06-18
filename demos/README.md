# OpenADP Demo Applications

This directory contains demonstration applications that showcase OpenADP's distributed cryptographic capabilities. These demos serve as both educational tools for developers and practical examples of how to integrate OpenADP into real applications.

## Directory Structure

```
demos/
├── README.md                    # This file
├── private-notes/              # Private Notes demo app
│   ├── DESIGN.md              # Design document
│   ├── linux-client/          # Linux PWA client
│   ├── android-client/        # Android client (future)
│   ├── ios-client/            # iOS client (future)
│   └── shared/                # Shared resources
├── secure-vault/              # Document vault demo (future)
├── anonymous-feedback/        # Anonymous feedback demo (future)
└── shared-components/         # Common demo components
    ├── openadp-js/           # JavaScript OpenADP client
    ├── ui-components/        # Reusable UI components
    └── test-utils/           # Testing utilities
```

## Demo Applications

### 🔒 Private Notes (Current)
**Status**: In Development  
**Platforms**: Linux PWA, Android (planned), iOS (planned)  
**Purpose**: "Hello World" app demonstrating basic OpenADP encryption/decryption

A simple notes application that encrypts user notes using OpenADP's distributed secret sharing. Perfect for developers learning OpenADP integration.

**Key Features**:
- PIN-based encryption using OpenADP
- Cross-device sync via Cloudflare R2
- Offline-first Progressive Web App
- Zero cloud storage costs for developers

### 🗃️ Secure Vault (Planned)
**Purpose**: Document storage with distributed trust

Store important documents (PDFs, images, certificates) with OpenADP encryption. Demonstrates file handling and larger data encryption.

### 📝 Anonymous Feedback (Planned)
**Purpose**: Cryptographically anonymous communication

Submit feedback or reports while maintaining true anonymity through OpenADP's distributed trust model.

## Getting Started

### For Developers
1. **Choose a demo**: Start with Private Notes for basic OpenADP integration
2. **Read the design doc**: Each demo has a detailed `DESIGN.md` file
3. **Follow the tutorial**: Step-by-step implementation guides
4. **Adapt for your needs**: Use as a starting point for your own apps

### For Contributors
1. **Follow the structure**: Use the established directory patterns
2. **Document thoroughly**: Include design docs and tutorials
3. **Test across platforms**: Ensure demos work on target platforms
4. **Keep it simple**: Demos should be educational, not feature-complete

## Design Principles

### Educational Value
- **Clear code structure** - Easy to understand and modify
- **Comprehensive comments** - Explain OpenADP integration points
- **Step-by-step tutorials** - Guide developers through implementation
- **Best practices** - Show proper error handling and security

### Practical Utility
- **Real-world useful** - Demos solve actual problems
- **Production patterns** - Show scalable architecture approaches
- **Platform-appropriate** - Use native patterns for each platform
- **Cost-conscious** - Minimize infrastructure requirements

### OpenADP Showcase
- **Core features** - Demonstrate distributed secret sharing
- **Security benefits** - Show advantages over centralized solutions
- **Integration patterns** - Multiple ways to use OpenADP
- **Cross-platform** - Work across different environments

## Contributing

### Adding New Demos
1. **Create directory structure** following the established pattern
2. **Write comprehensive design doc** explaining architecture and decisions
3. **Implement with clear documentation** and educational comments
4. **Test thoroughly** across target platforms
5. **Update this README** with demo description

### Improving Existing Demos
1. **Follow existing code style** and patterns
2. **Add tests** for new functionality
3. **Update documentation** as needed
4. **Consider cross-platform impact** of changes

## Support

- **GitHub Issues**: Report bugs or request features
- **Documentation**: Check individual demo design docs
- **Community**: Join OpenADP developer discussions
- **Examples**: Look at existing demos for patterns

---

**Goal**: Make OpenADP accessible to developers through practical, educational demo applications that showcase the power of distributed cryptographic trust. 