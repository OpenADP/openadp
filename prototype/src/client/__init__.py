"""
OpenADP Client Components

This package contains client-side components for communicating with OpenADP servers:
- client: High-level client business logic
- jsonrpc_client: JSON-RPC transport layer
- scrape: Server discovery and scraping functionality
"""

from .client import Client
from .jsonrpc_client import OpenADPClient
from .scrape import scrape_server_urls, get_fallback_servers

__all__ = ['Client', 'OpenADPClient', 'scrape_server_urls', 'get_fallback_servers'] 