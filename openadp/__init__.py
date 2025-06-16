"""
OpenADP (Open Asynchronous Distributed Password) Library

A distributed secret sharing system that replaces traditional password-based 
key derivation with a more secure distributed approach using threshold cryptography.

Key Components:
- crypto: Ed25519-based cryptographic operations
- sharing: Secret sharing and reconstruction algorithms  
- database: SQLite database operations for server storage
- keygen: High-level key generation and recovery functions
- noise_nk: Simple Noise-NK encryption for secure JSON-RPC communication
"""

import sys
import os

# Add the current directory to Python path to allow absolute imports
sys.path.insert(0, os.path.dirname(__file__))

from crypto import *
from sharing import *
from database import Database
from noise_nk import NoiseNK, generate_keypair

__version__ = "0.1.0"
__author__ = "OpenADP Contributors"
__license__ = "MIT"

__all__ = [
    # Crypto functions
    'H', 'deriveEncKey', 'point_mul', 'point_add', 'point_compress', 'point_decompress',
    'secret_to_public', 'G', 'q', 'p',
    
    # Sharing functions  
    'make_random_shares', 'recover_sb',
    
    # Database
    'Database',
    
    # Noise-NK encryption
    'NoiseNK', 'generate_keypair',
] 