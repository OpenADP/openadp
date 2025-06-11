"""
OpenADP Client Components

This package contains client-side components for communicating with OpenADP servers:
- noise_jsonrpc_client: JSON-RPC transport layer with Noise-KK encryption
- scrape: Server discovery and scraping functionality
"""

from .noise_jsonrpc_client import create_noise_client
from .scrape import scrape_server_urls, get_fallback_servers

__all__ = ['create_noise_client', 'scrape_server_urls', 'get_fallback_servers'] 