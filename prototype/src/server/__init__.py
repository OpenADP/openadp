"""
OpenADP Server Components

This package contains server-side components for running OpenADP servers:
- server: Core server business logic  
- noise_jsonrpc_server: JSON-RPC server with Noise-KK encryption
- grpc_server: gRPC server implementation
"""

from .server import register_secret, recover_secret, list_backups
from .noise_jsonrpc_server import main as jsonrpc_main

try:
    from .grpc_server import main as grpc_main
    __all__ = ['register_secret', 'recover_secret', 'list_backups', 'jsonrpc_main', 'grpc_main']
except ImportError:
    # gRPC not available
    __all__ = ['register_secret', 'recover_secret', 'list_backups', 'jsonrpc_main'] 