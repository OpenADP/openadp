#!/usr/bin/env python3
"""
Noise-KK Enabled JSON-RPC Client for OpenADP

This client wraps the standard JSON-RPC client with a Noise-KK layer for additional
security. Communication flow:
1. TLS connection to server
2. Noise-KK handshake over TLS
3. JSON-RPC messages encrypted through Noise-KK

This provides the security architecture described in the OpenADP README:
"gRPC, tunneled over Noise-KK, tunneled over TLS"
(We use JSON-RPC instead of gRPC for Cloudflare compatibility)
"""

import json
import ssl
import socket
import urllib.parse
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import logging

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from openadp.noise_kk import (
    NoiseKKSession, NoiseKKTransport, 
    generate_client_keypair, parse_server_public_key,
    create_client_session
)

logger = logging.getLogger(__name__)


class NoiseKKJSONRPCClient:
    """
    JSON-RPC client with Noise-KK encryption over TLS.
    
    This provides the same interface as the standard OpenADPClient but with
    an additional layer of Noise-KK encryption for enhanced security.
    """
    
    def __init__(self, server_url: str, server_public_key: str, timeout: float = 30.0):
        """
        Initialize the Noise-KK enabled JSON-RPC client.
        
        Args:
            server_url: Server URL (must be HTTPS)
            server_public_key: Server's public key in "ed25519:base64" format
            timeout: Connection timeout in seconds
        """
        self.server_url = server_url
        self.server_public_key = server_public_key
        self.timeout = timeout
        self.request_id = 0
        
        # Parse URL
        parsed = urllib.parse.urlparse(server_url)
        if parsed.scheme not in ['https']:
            raise ValueError("Only HTTPS URLs are supported for Noise-KK")
        
        self.hostname = parsed.hostname
        self.port = parsed.port or 443
        self.path = parsed.path or '/'
        
        # Initialize Noise-KK session
        self.noise_session = create_client_session(server_public_key)
        
        # Connection state
        self._socket = None
        self._noise_transport = None
        self._connected = False
    
    def _connect(self):
        """Establish TLS connection and perform Noise-KK handshake"""
        if self._connected:
            return
        
        try:
            # Create TLS connection
            context = ssl.create_default_context()
            
            # Create socket and connect
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(self.timeout)
            
            # Wrap with TLS
            self._socket = context.wrap_socket(raw_socket, server_hostname=self.hostname)
            self._socket.connect((self.hostname, self.port))
            
            logger.info(f"TLS connection established to {self.hostname}:{self.port}")
            
            # Perform Noise-KK handshake
            self._noise_transport = NoiseKKTransport(self._socket, self.noise_session)
            self._noise_transport.perform_handshake()
            
            logger.info("Noise-KK handshake completed")
            self._connected = True
            
        except Exception as e:
            logger.error(f"Failed to establish Noise-KK connection: {e}")
            self._cleanup()
            raise
    
    def _cleanup(self):
        """Clean up connection resources"""
        if self._noise_transport:
            self._noise_transport.close()
            self._noise_transport = None
        
        if self._socket:
            self._socket.close()
            self._socket = None
        
        self._connected = False
    
    def _send_jsonrpc_request(self, method: str, params: List[Any]) -> Tuple[Optional[Any], Optional[str]]:
        """
        Send a JSON-RPC request over the Noise-KK encrypted channel.
        
        Args:
            method: JSON-RPC method name
            params: List of parameters
            
        Returns:
            Tuple of (result, error). If successful, error is None.
        """
        try:
            self._connect()
            
            # Build JSON-RPC request
            self.request_id += 1
            request = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": self.request_id
            }
            
            # Serialize request
            request_data = json.dumps(request).encode('utf-8')
            
            # Send encrypted request
            self._noise_transport.send_encrypted(request_data)
            
            # Receive encrypted response
            response_data = self._noise_transport.recv_encrypted()
            
            # Parse response
            response = json.loads(response_data.decode('utf-8'))
            
            # Check for JSON-RPC error
            if "error" in response:
                return None, response["error"].get("message", "Unknown error")
            
            return response.get("result"), None
            
        except Exception as e:
            logger.error(f"JSON-RPC request failed: {e}")
            self._cleanup()  # Force reconnection on next request
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
        import base64
        y_b64 = base64.b64encode(y).decode('ascii')
        
        params = [uid, did, bid, version, x, y_b64, max_guesses, expiration]
        result, error = self._send_jsonrpc_request("RegisterSecret", params)
        
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
            b: Point B for recovery (will be serialized)
            guess_num: Expected guess number
            
        Returns:
            Tuple of (recovery_result, error_message)
        """
        # Serialize point B for transport
        if hasattr(b, 'public_bytes'):
            # It's likely a public key object
            import base64
            from cryptography.hazmat.primitives import serialization
            b_bytes = b.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            b_b64 = base64.b64encode(b_bytes).decode('ascii')
        elif isinstance(b, bytes):
            import base64
            b_b64 = base64.b64encode(b).decode('ascii')
        else:
            # Assume it's already a string
            b_b64 = str(b)
        
        params = [uid, did, bid, b_b64, guess_num]
        result, error = self._send_jsonrpc_request("RecoverSecret", params)
        
        if error:
            return None, error
        
        return result, None
    
    def list_backups(self, uid: str) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """
        List backups for a user.
        
        Args:
            uid: User identifier
            
        Returns:
            Tuple of (backup_list, error_message)
        """
        params = [uid]
        result, error = self._send_jsonrpc_request("ListBackups", params)
        
        if error:
            return None, error
        
        return result, None
    
    def echo(self, message: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Test connectivity with echo.
        
        Args:
            message: Message to echo
            
        Returns:
            Tuple of (echoed_message, error_message)
        """
        params = [message]
        result, error = self._send_jsonrpc_request("Echo", params)
        
        if error:
            return None, error
        
        return result, None
    
    def close(self):
        """Close the connection"""
        self._cleanup()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


def create_noise_client(server_url: str, server_public_key: str) -> NoiseKKJSONRPCClient:
    """
    Convenience function to create a Noise-KK enabled client.
    
    Args:
        server_url: Server URL (must be HTTPS)
        server_public_key: Server public key in "ed25519:base64" format
        
    Returns:
        Configured NoiseKKJSONRPCClient instance
    """
    return NoiseKKJSONRPCClient(server_url, server_public_key)


if __name__ == "__main__":
    # Test the Noise-KK client
    print("Testing Noise-KK JSON-RPC Client...")
    
    # This would normally use a real server public key from servers.json
    test_server_key = "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder1XyZzyBillServer12345TestKey"
    test_url = "https://xyzzybill.openadp.org"
    
    try:
        with create_noise_client(test_url, test_server_key) as client:
            print(f"Created Noise-KK client for {test_url}")
            
            # Test echo (this will fail without a real server, but tests the client structure)
            result, error = client.echo("Hello, Noise-KK!")
            if error:
                print(f"Expected error (no real server): {error}")
            else:
                print(f"Echo result: {result}")
            
    except Exception as e:
        print(f"Expected error (no real server): {e}")
    
    print("✅ Noise-KK client implementation completed!") 