# Python SDK Requirements

The OpenADP Python SDK uses a tiered requirements structure to keep installations lightweight by default.

## Requirements Files

### `requirements.txt` (Default)
- **Size**: ~61MB venv
- **Use**: Production deployments, CI/CD, basic usage
- **Includes**: Only essential dependencies for core functionality
- **Install**: `pip install -r requirements.txt`

### `requirements-minimal.txt` 
- **Size**: ~61MB venv  
- **Use**: Minimal installations, embedded systems
- **Includes**: Core crypto, networking, and testing packages
- **Install**: `pip install -r requirements-minimal.txt`

### `requirements-dev.txt`
- **Size**: ~197MB venv
- **Use**: Development, documentation generation, type checking
- **Includes**: All minimal requirements + development tools
- **Install**: `pip install -r requirements-dev.txt`

## Package Breakdown

### Core Dependencies (~40MB)
- `cryptography` (14MB): Essential cryptographic operations
- `pycryptodome` (10MB): Additional crypto algorithms  
- `noiseprotocol`: Noise-NK protocol implementation
- `requests`: HTTP client for JSON-RPC communication
- `pytest` (3MB): Testing framework

### Development Tools (~136MB additional)
- `mypy` (52MB): Type checking and static analysis
- `sphinx` (29MB): Documentation generation
- `babel` (33MB): Internationalization (pulled by sphinx)
- `black`: Code formatting
- `isort`: Import sorting

## Usage Examples

```bash
# Minimal installation for production
pip install -r requirements.txt

# Development installation with all tools
pip install -r requirements-dev.txt

# Check current venv size
du -sh venv/
```

## Size Comparison

| Requirements File | Venv Size | Use Case |
|------------------|-----------|----------|
| requirements-minimal.txt | 61MB | Production, CI/CD |
| requirements.txt | 61MB | Default (same as minimal) |
| requirements-dev.txt | 197MB | Development, docs |

The default configuration prioritizes minimal size while maintaining full functionality. 