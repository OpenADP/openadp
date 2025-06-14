"""
OpenADP Authentication & Authorization Module

This package implements DPoP (Demonstration of Proof-of-Possession) authentication
for OpenADP clients and servers, following RFC 9449.

Phase 1: Client key & token handling
- Key generation and management
- OAuth 2.0 Device Code flow
- DPoP header generation
"""

from .keys import generate_keypair, load_private_key, save_private_key
from .device_flow import run_device_flow
from .pkce_flow import run_pkce_flow
from .dpop import make_dpop_header

__all__ = [
    'generate_keypair',
    'load_private_key', 
    'save_private_key',
    'run_device_flow',
    'run_pkce_flow',
    'make_dpop_header'
] 