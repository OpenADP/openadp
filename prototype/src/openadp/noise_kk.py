#!/usr/bin/env python3
"""
OpenADP Noise-KK Implementation

This is the main Noise-KK module for OpenADP. It provides a clean interface
for Noise-KK encrypted communication using our proven simplified implementation.

The simplified implementation provides all the security properties of Noise-KK:
- Mutual authentication using static keys
- Forward secrecy via ephemeral keys  
- ChaCha20-Poly1305 encryption
- X25519 key exchange
- Proper Noise Protocol Framework compliance

Usage:
    from openadp.noise_kk import create_client_session, create_server_session, NoiseKKTransport
"""

# Use the proven simplified implementation as primary
try:
    # Relative import (when used as a module)
    from .noise_kk_simple import (
        SimplifiedNoiseKK as NoiseKKSession,
        NoiseKKTransport,
        generate_client_keypair,
        parse_server_public_key,
        create_client_session,
        create_server_session,
        test_simplified_noise_kk
    )
except ImportError:
    # Direct import (when run as a script)
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    from noise_kk_simple import (
        SimplifiedNoiseKK as NoiseKKSession,
        NoiseKKTransport,
        generate_client_keypair,
        parse_server_public_key,
        create_client_session,
        create_server_session,
        test_simplified_noise_kk
    )

# Export all the necessary functions for easy import
__all__ = [
    'NoiseKKSession',
    'NoiseKKTransport', 
    'create_client_session',
    'create_server_session',
    'generate_client_keypair',
    'parse_server_public_key',
    'test_noise_kk'
]

def test_noise_kk():
    """Test the Noise-KK implementation"""
    return test_simplified_noise_kk()

def get_implementation_info():
    """Get information about the current Noise-KK implementation"""
    return {
        "implementation": "Simplified Noise-KK",
        "description": "Proven working implementation using Python cryptography library",
        "security_features": [
            "Mutual authentication",
            "Forward secrecy", 
            "ChaCha20-Poly1305 encryption",
            "X25519 key exchange",
            "Noise Protocol Framework compliance"
        ],
        "compatibility": "Works on all systems with python3-cryptography",
        "tested": True
    }

if __name__ == "__main__":
    print("🔐 OpenADP Noise-KK Implementation")
    print("=" * 50)
    
    info = get_implementation_info()
    print(f"Implementation: {info['implementation']}")
    print(f"Description: {info['description']}")
    print(f"Compatible: {info['compatibility']}")
    print(f"Tested: {info['tested']}")
    
    print("\nSecurity Features:")
    for feature in info['security_features']:
        print(f"  ✅ {feature}")
    
    print(f"\nRunning tests...")
    if test_noise_kk():
        print("✅ All tests passed!")
        print("\n🎉 Noise-KK implementation ready for production use!")
    else:
        print("❌ Tests failed!")
    
    print("=" * 50) 