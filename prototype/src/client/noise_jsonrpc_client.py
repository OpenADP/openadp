#!/usr/bin/env python3
"""
Noise-KK Enabled JSON-RPC Client for OpenADP (Cloudflare Compatible)

This client wraps the standard JSON-RPC client with a Noise-KK layer for additional
security. Communication flow:
1. HTTPS to Cloudflare 
2. Cloudflare terminates TLS and forwards HTTP to server
3. Noise-KK handshake over HTTP POST requests
4. JSON-RPC messages encrypted through Noise-KK over HTTP

This provides the security architecture described in the OpenADP README:
"JSON-RPC, tunneled over Noise-KK, tunneled over HTTP, tunneled over TLS"
Compatible with Cloudflare reverse proxy setup.
"""

import json
import ssl
import urllib.request
import urllib.parse
import urllib.error
import base64
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import logging

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from openadp.noise_kk import (
    generate_client_keypair, parse_server_public_key,
    create_client_session
)

logger = logging.getLogger(__name__)


class NoiseKKJSONRPCClient:
    """
    JSON-RPC client with Noise-KK encryption over HTTP (Cloudflare compatible).
    
    This provides the same interface as the standard OpenADPClient but with
    an additional layer of Noise-KK encryption for enhanced security.
    Uses HTTP POST requests instead of direct socket operations for Cloudflare compatibility.
    """
    
    def __init__(self, server_url: str, server_public_key: str, timeout: float = 30.0):
        """
        Initialize the Noise-KK enabled JSON-RPC client.
        
        Args:
            server_url: Server URL (HTTPS for Cloudflare, HTTP for direct)
            server_public_key: Server's public key in "ed25519:base64" format
            timeout: HTTP request timeout in seconds
        """
        self.server_url = server_url
        self.server_public_key = server_public_key
        self.timeout = timeout
        self.request_id = 0
        
        # Parse URL
        parsed = urllib.parse.urlparse(server_url)
        self.hostname = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.scheme = parsed.scheme
        
        # Initialize Noise-KK session
        self.noise_session = create_client_session(server_public_key)
        
        # Connection state
        self._handshake_done = False
        
        # Create SSL context for HTTPS
        self.ssl_context = ssl.create_default_context()
        # Allow self-signed certificates for testing
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def _next_request_id(self):
        """Get next JSON-RPC request ID"""
        self.request_id += 1
        return self.request_id
    
    def _http_post(self, jsonrpc_request: dict) -> dict:
        """Send HTTP POST with JSON-RPC payload and return parsed response"""
        # Serialize JSON-RPC request
        request_data = json.dumps(jsonrpc_request).encode('utf-8')
        
        # Create HTTP request
        req = urllib.request.Request(
            self.server_url,
            data=request_data,
            headers={
                'Content-Type': 'application/json',
                'Content-Length': str(len(request_data)),
                'User-Agent': 'OpenADP-NoiseKK-Client/1.0'
            },
            method='POST'
        )
        
        try:
            # Send request with SSL context
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as response:
                response_data = response.read()
                return json.loads(response_data.decode('utf-8'))
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP error {e.code}: {e.reason}")
            raise RuntimeError(f"HTTP error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            logger.error(f"URL error: {e.reason}")
            raise RuntimeError(f"Connection error: {e.reason}")
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise RuntimeError(f"Request failed: {e}")
    
    def _perform_handshake(self):
        """Perform Noise-KK handshake over HTTP"""
        if self._handshake_done:
            return
        
        try:
            # Client: start handshake
            msg1 = self.noise_session.start_handshake()
            
            # Encode handshake data as base64 for JSON transport
            msg1_b64 = base64.b64encode(msg1).decode('ascii')
            
            # Send handshake via JSON-RPC over HTTP
            handshake_request = {
                "jsonrpc": "2.0",
                "method": "noise-handshake",
                "params": [msg1_b64],
                "id": self._next_request_id()
            }
            
            logger.info("Performing Noise-KK handshake over HTTP...")
            response = self._http_post(handshake_request)
            
            # Check for JSON-RPC error
            if "error" in response:
                raise RuntimeError(f"Handshake error: {response['error']}")
            
            # Decode server response
            msg2_b64 = response["result"]
            msg2 = base64.b64decode(msg2_b64)
            
            # Process server response
            _, complete = self.noise_session.process_handshake_message(msg2)
            
            if not complete:
                raise RuntimeError("Handshake failed to complete")
            
            self._handshake_done = True
            logger.info("Noise-KK handshake completed successfully over HTTP")
            
        except Exception as e:
            logger.error(f"Noise-KK handshake failed: {e}")
            raise
    
    def _send_encrypted_jsonrpc(self, method: str, params: List[Any]) -> Tuple[Optional[Any], Optional[str]]:
        """
        Send an encrypted JSON-RPC request and return the result.
        
        Args:
            method: JSON-RPC method name
            params: List of parameters
            
        Returns:
            Tuple of (result, error). If successful, error is None.
        """
        try:
            # Ensure handshake is complete
            self._perform_handshake()
            
            # Build inner JSON-RPC request
            inner_request = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": self._next_request_id()
            }
            
            # Serialize and encrypt inner request
            inner_data = json.dumps(inner_request).encode('utf-8')
            encrypted_data = self.noise_session.encrypt(inner_data)
            
            # Encode encrypted data as base64
            encrypted_b64 = base64.b64encode(encrypted_data).decode('ascii')
            
            # Build outer JSON-RPC request
            outer_request = {
                "jsonrpc": "2.0",
                "method": "noise-data",
                "params": [encrypted_b64],
                "id": self._next_request_id()
            }
            
            # Send via HTTP
            response = self._http_post(outer_request)
            
            # Check for outer JSON-RPC error
            if "error" in response:
                return None, f"Transport error: {response['error']}"
            
            # Decode and decrypt response
            response_encrypted_b64 = response["result"]
            response_encrypted = base64.b64decode(response_encrypted_b64)
            response_decrypted = self.noise_session.decrypt(response_encrypted)
            
            # Parse inner JSON-RPC response
            inner_response = json.loads(response_decrypted.decode('utf-8'))
            
            # Check for inner JSON-RPC error
            if "error" in inner_response:
                return None, inner_response["error"].get("message", "Unknown error")
            
            return inner_response.get("result"), None
            
        except Exception as e:
            logger.error(f"Encrypted JSON-RPC request failed: {e}")
            return None, str(e)
    
    def register_secret(self, uid: str, did: str, bid: str, version: int, 
                       x: int, y: bytes, max_guesses: int, expiration: int) -> Tuple[Optional[bool], Optional[str]]:
        """
        Register a secret with the server.
        
        Args:
            uid: User identifier
            did: Device identifier  
            bid: Backup identifier
            version: Version number
            x: X coordinate for secret sharing
            y: Y coordinate (secret share bytes)
            max_guesses: Maximum guess attempts
            expiration: Expiration timestamp (0 for no expiration)
            
        Returns:
            Tuple of (success, error_message)
        """
        # Convert bytes to base64 for JSON transport
        y_b64 = base64.b64encode(y).decode('ascii')
        
        params = [uid, did, bid, version, x, y_b64, max_guesses, expiration]
        result, error = self._send_encrypted_jsonrpc("RegisterSecret", params)
        
        if error:
            return None, error
        
        return result, None
    
    def recover_secret(self, uid: str, did: str, bid: str, b: Any, guess_num: int) -> Tuple[Optional[Any], Optional[str]]:
        """
        Recover a secret from the server.
        
        Args:
            uid: User identifier
            did: Device identifier
            bid: Backup identifier
            b: Point B (will be converted to base64)
            guess_num: Current guess number
            
        Returns:
            Tuple of (result, error_message)
        """
        # Convert point B to base64 if it's bytes
        if isinstance(b, bytes):
            b_b64 = base64.b64encode(b).decode('ascii')
        else:
            b_b64 = str(b)  # Assume it's already a string
        
        params = [uid, did, bid, b_b64, guess_num]
        result, error = self._send_encrypted_jsonrpc("RecoverSecret", params)
        
        if error:
            return None, error
        
        return result, None
    
    def list_backups(self, uid: str) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """
        List all backups for a user.
        
        Args:
            uid: User identifier
            
        Returns:
            Tuple of (backup_list, error_message)
        """
        params = [uid]
        result, error = self._send_encrypted_jsonrpc("ListBackups", params)
        
        if error:
            return None, error
        
        return result, None
    
    def echo(self, message: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Echo test method.
        
        Args:
            message: Message to echo
            
        Returns:
            Tuple of (echoed_message, error_message)
        """
        params = [message]
        result, error = self._send_encrypted_jsonrpc("Echo", params)
        
        if error:
            return None, error
        
        return result, None
    
    def close(self):
        """Close the client (nothing to clean up for HTTP client)"""
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def create_noise_client(server_url: str, server_public_key: str) -> NoiseKKJSONRPCClient:
    """
    Create a Noise-KK enabled JSON-RPC client.
    
    Args:
        server_url: Server URL (https:// for Cloudflare, http:// for direct)
        server_public_key: Server public key in "ed25519:base64" format
        
    Returns:
        Configured NoiseKKJSONRPCClient instance
    """
    return NoiseKKJSONRPCClient(server_url, server_public_key)


# For backward compatibility
NoiseKKClient = NoiseKKJSONRPCClient


def main():
    """Test the Noise-KK JSON-RPC client"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test Noise-KK JSON-RPC Client')
    parser.add_argument('server_url', help='Server URL (e.g. https://server.example.com)')
    parser.add_argument('public_key', help='Server public key (ed25519:base64)')
    parser.add_argument('--message', default='Hello, OpenADP!', help='Message to echo')
    
    args = parser.parse_args()
    
    print(f"🔐 Testing Noise-KK connection to {args.server_url}")
    print(f"   Using key: {args.public_key[:30]}...")
    
    try:
        with create_noise_client(args.server_url, args.public_key) as client:
            result, error = client.echo(args.message)
            
            if error:
                print(f"❌ Echo failed: {error}")
                return 1
            else:
                print(f"✅ Echo successful: {result}")
                return 0
                
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main()) 