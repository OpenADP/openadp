#!/usr/bin/env python3
"""
OpenADP Client (Legacy)

This is the legacy OpenADP client that used the old non-encrypted JSON-RPC protocol.
It has been replaced with a Noise-KK encrypted version.

For new development, please use:
- client_with_noise.py: Full-featured client with Noise-KK encryption
- noise_jsonrpc_client.py: Low-level Noise-KK JSON-RPC client

The old jsonrpc_client.py has been removed as part of the security upgrade.
All communications now use Noise-KK encryption over TLS for enhanced security.
"""

import sys
from typing import Any, Dict, List, Optional, Tuple

print("=" * 60)
print("⚠️  DEPRECATED: client.py (Legacy Client)")  
print("=" * 60)
print()
print("This client has been deprecated and replaced with Noise-KK encryption.")
print()
print("Please use one of these instead:")
print("  • client_with_noise.py    - Full-featured client with Noise-KK")
print("  • noise_jsonrpc_client.py - Low-level Noise-KK client")
print()
print("Benefits of the new clients:")
print("  ✅ End-to-end encryption with Noise-KK protocol")
print("  ✅ Mutual authentication using static keys")
print("  ✅ Perfect forward secrecy")
print("  ✅ 128-bit security (X25519 + ChaCha20-Poly1305)")
print("=" * 60)


class Client:
    """
    Legacy OpenADP client class (deprecated)
    
    This class is no longer functional as it depends on the removed
    non-encrypted JSON-RPC client. Please migrate to client_with_noise.py.
    """
    
    def __init__(self, *args, **kwargs):
        raise ImportError(
            "Legacy Client class is no longer available. "
            "Please use client_with_noise.py for Noise-KK encrypted communications."
        )


def main():
    """Legacy main function"""
    print("\n🚀 Migration Guide:")
    print("\n1. For full client functionality:")
    print("   python3 client_with_noise.py")
    print("\n2. For direct JSON-RPC calls:")
    print("   python3 noise_jsonrpc_client.py")
    print("\n3. To test Noise-KK implementation:")
    print("   python3 test_noise_integration.py")
    

if __name__ == "__main__":
    main() 