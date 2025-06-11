"""
OpenADP Client Components

This package contains client-side components for communicating with OpenADP servers:
- client: High-level client business logic
- noise_jsonrpc_client: JSON-RPC transport layer with Noise-KK encryption
- scrape: Server discovery and scraping functionality
"""

from .client import Client
from .noise_jsonrpc_client import create_noise_client
from .scrape import scrape_server_urls, get_fallback_servers

__all__ = ['Client', 'create_noise_client', 'scrape_server_urls', 'get_fallback_servers'] 