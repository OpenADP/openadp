"""
OpenADP Python SDK

This package provides Python implementations for OpenADP (Open Advanced Data Protection),
a distributed secret sharing system designed to protect against nation-state attacks.

Key Features:
- Ed25519 elliptic curve operations
- Shamir secret sharing with threshold recovery
- Noise-NK protocol for secure communication
- JSON-RPC 2.0 API with multi-server support
- Cross-language compatibility with Go implementation

Main Components:
- Cryptographic operations (crypto module)
- Key generation and recovery (keygen module)  
- Client implementations (client module)

Example Usage:
    from openadp import EncryptedOpenADPClient, MultiServerClient
    from openadp.keygen import generate_encryption_key, recover_encryption_key
    
    # Generate encryption key with distributed backup
    key, auth_code = generate_encryption_key(
        password="secure_password",
        uid="user@example.com", 
        did="device123",
        bid="backup456"
    )
    
    # Create multi-server client
    client = MultiServerClient()
    
    # Later, recover the key
    recovered_key = recover_encryption_key(
        password="secure_password",
        auth_code=auth_code,
        uid="user@example.com",
        did="device123", 
        bid="backup456",
        client=client
    )
"""

# Core cryptographic operations
from .crypto import (
    # Point operations
    Point2D, Point4D, G, P, Q, D,
    point_add, point_mul, point_mul8,
    point_compress, point_decompress,
    is_valid_point, expand, unexpand,
    
    # Hash and key derivation
    H, sha256_hash, prefixed,
    
    # Shamir secret sharing
    ShamirSecretSharing,
    
    # Utilities
    mod_inverse
)

# Key generation and recovery
from .keygen import (
    Identity,
    generate_encryption_key,
    recover_encryption_key,
    generate_auth_codes
)

# Ocrypt - Drop-in replacement for password hashing functions
from .ocrypt import (
    register as ocrypt_register,
    recover as ocrypt_recover
)

# Debug functionality
from .debug import (
    set_debug_mode,
    is_debug_mode_enabled,
    debug_log,
    get_deterministic_main_secret,
    get_deterministic_random_hex,
    get_deterministic_random_bytes,
    get_deterministic_ephemeral_secret,
    secure_random_scalar,
)

# Client implementations
from .client import (
    # Core client classes
    OpenADPClient,
    EncryptedOpenADPClient, 
    MultiServerClient,
    
    # Noise-NK protocol
    NoiseNK,
    generate_keypair,
    parse_server_public_key,
    
    # Data structures
    ServerInfo,
    RegisterSecretRequest,
    RegisterSecretResponse,
    RecoverSecretRequest,
    RecoverSecretResponse,
    ListBackupsRequest,
    ListBackupsResponse,
    BackupInfo,
    ServerInfoResponse,
    
    # Enums
    ErrorCode,
    ServerSelectionStrategy,
    
    # Exceptions
    OpenADPError,
    
    # Server discovery
    get_servers,
    get_server_urls,
    scrape_server_urls,
    get_servers_by_country,
    get_fallback_servers,
    get_fallback_server_info,
    convert_urls_to_server_info,
    discover_servers,
    discover_server_urls
)

__version__ = "0.1.3"
__author__ = "OpenADP Team"
__email__ = "contact@openadp.org"
__description__ = "OpenADP Python SDK for distributed secret sharing and advanced data protection"

# Convenience aliases for common use cases
Client = MultiServerClient  # Most users will want the multi-server client
BasicClient = OpenADPClient  # For simple use cases without encryption

__all__ = [
    # Crypto
    "Point2D", "Point4D", "G", "P", "Q", "D",
    "point_add", "point_mul", "point_mul8", 
    "point_compress", "point_decompress",
    "is_valid_point", "expand", "unexpand",
    "H", "sha256_hash", "prefixed",
    "ShamirSecretSharing",
    "mod_inverse",
    
    # Keygen
    "Identity", "generate_encryption_key", "recover_encryption_key",
    
    # Ocrypt
    "ocrypt_register", "ocrypt_recover",
    
    # Debug
    "set_debug_mode", "is_debug_mode_enabled", "debug_log",
    "get_deterministic_random_hex", "get_deterministic_random_bytes",
    "get_deterministic_ephemeral_secret", "secure_random_scalar",
    
    # Client classes
    "OpenADPClient", "EncryptedOpenADPClient", "MultiServerClient",
    "Client", "BasicClient",  # Aliases
    
    # Noise-NK
    "NoiseNK", "generate_keypair", "parse_server_public_key",
    
    # Data structures
    "ServerInfo", "RegisterSecretRequest", "RegisterSecretResponse",
    "RecoverSecretRequest", "RecoverSecretResponse", 
    "ListBackupsRequest", "ListBackupsResponse", "BackupInfo",
    "ServerInfoResponse",
    
    # Enums and errors
    "ErrorCode", "ServerSelectionStrategy", "OpenADPError",
    
    # Server discovery
    "get_servers", "get_server_urls", "scrape_server_urls",
    "get_servers_by_country", "get_fallback_servers", 
    "get_fallback_server_info", "convert_urls_to_server_info",
    "discover_servers", "discover_server_urls",
    
    # Package metadata
    "__version__", "__author__", "__email__", "__description__"
] 
