#!/usr/bin/env python3
"""
Enhanced JSON-RPC Client for OpenADP Server with Noise-NK Encryption

This client extends the basic JSON-RPC client to support optional end-to-end encryption
using the Noise-NK protocol. It provides the same API as the basic client but with an
optional `encrypted=True` parameter for any method call.

Usage:
    client = EncryptedOpenADPClient("https://server.example.com", server_public_key)
    
    # Unencrypted call (1 round)
    result, error = client.echo("test message")
    
    # Encrypted call (2 rounds under the hood)
    result, error = client.echo("test message", encrypted=True)
"""

import base64
import json
import logging
import os
import secrets
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

# Add path to access noise_nk module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'openadp'))

from noise_nk import NoiseNK, generate_keypair
from jsonrpc_client import OpenADPClient

logger = logging.getLogger(__name__)


class EncryptedOpenADPClient(OpenADPClient):
    """Enhanced OpenADP client with Noise-NK encryption support."""
    
    def __init__(self, server_url: str = "http://localhost:8080", server_public_key: Optional[bytes] = None):
        """
        Initialize the encrypted OpenADP client.
        
        Args:
            server_url: URL of the JSON-RPC server
            server_public_key: Server's Noise-NK public key (32 bytes). Required for encryption.
        """
        super().__init__(server_url)
        self.server_public_key = server_public_key
        
        if server_public_key and len(server_public_key) != 32:
            raise ValueError("Server public key must be exactly 32 bytes")
        
        logger.debug(f"Initialized encrypted client for {server_url}")
        if server_public_key:
            logger.debug(f"Server public key: {server_public_key.hex()[:32]}...")
    
    def _make_encrypted_request(self, method: str, params: List[Any], request_id: int) -> Tuple[Any, Optional[str]]:
        """
        Make an encrypted JSON-RPC request using Noise-NK.
        
        Args:
            method: The RPC method name
            params: List of parameters for the method
            request_id: Request ID for JSON-RPC
            
        Returns:
            Tuple of (result, error_message). If successful, error_message is None.
        """
        if self.server_public_key is None:
            return None, "No server public key provided - encryption not available"
        
        try:
            # Generate unique session ID
            session_id = base64.b64encode(secrets.token_bytes(16)).decode('ascii')
            
            # Create Noise-NK client (initiator) 
            # First create a NoiseNK instance to get access to the DH object
            temp_client = NoiseNK(role='responder')  # Just to get the dh object
            dh = temp_client.dh
            server_public_key_obj = dh.create_public(self.server_public_key)
            
            # Now create the real client with the proper key object
            noise_client = NoiseNK(
                role='initiator',
                remote_static_key=server_public_key_obj
            )
            
            # Round 1: Handshake
            logger.debug(f"Starting handshake for session {session_id[:16]}...")
            client_handshake = noise_client.write_handshake_message(b"Client handshake")
            
            handshake_payload = {
                "jsonrpc": "2.0",
                "method": "noise_handshake",
                "params": [session_id, base64.b64encode(client_handshake).decode('ascii')],
                "id": request_id
            }
            
            # Send handshake
            handshake_response = self._send_request(handshake_payload)
            if "error" in handshake_response:
                error_info = handshake_response["error"]
                if isinstance(error_info, dict):
                    error_msg = error_info.get("message", str(error_info))
                else:
                    error_msg = str(error_info)
                return None, f"Handshake failed: {error_msg}"
            
            # Process server's handshake response
            server_handshake_b64 = handshake_response["result"]["message"]
            server_handshake = base64.b64decode(server_handshake_b64)
            
            try:
                server_payload = noise_client.read_handshake_message(server_handshake)
                logger.debug(f"Received handshake payload: {server_payload}")
            except Exception as e:
                return None, f"Handshake processing failed: {str(e)}"
            
            if not noise_client.is_handshake_complete():
                return None, "Handshake not completed properly"
            
            logger.debug(f"Handshake completed for session {session_id[:16]}...")
            
            # Round 2: Encrypted call
            inner_request = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": request_id + 1
            }
            
            # Encrypt the inner request
            inner_json = json.dumps(inner_request).encode('utf-8')
            encrypted_inner = noise_client.encrypt(inner_json)
            
            encrypted_payload = {
                "jsonrpc": "2.0",
                "method": "encrypted_call",
                "params": [session_id, base64.b64encode(encrypted_inner).decode('ascii')],
                "id": request_id + 1
            }
            
            # Send encrypted call
            encrypted_response = self._send_request(encrypted_payload)
            if "error" in encrypted_response:
                error_info = encrypted_response["error"]
                if isinstance(error_info, dict):
                    error_msg = error_info.get("message", str(error_info))
                else:
                    error_msg = str(error_info)
                return None, f"Encrypted call failed: {error_msg}"
            
            # Decrypt the response
            encrypted_response_b64 = encrypted_response["result"]["data"]
            encrypted_response_data = base64.b64decode(encrypted_response_b64)
            
            try:
                decrypted_json = noise_client.decrypt(encrypted_response_data)
                final_response = json.loads(decrypted_json.decode('utf-8'))
            except Exception as e:
                return None, f"Response decryption failed: {str(e)}"
            
            # Extract result from final response
            if "error" in final_response:
                error_info = final_response["error"]
                if isinstance(error_info, dict):
                    error_msg = error_info.get("message", str(error_info))
                else:
                    error_msg = str(error_info)
                return None, error_msg
            
            logger.debug(f"Successfully completed encrypted call for session {session_id[:16]}...")
            return final_response.get("result"), None
            
        except Exception as e:
            logger.error(f"Unexpected error in encrypted request: {e}")
            return None, f"Encryption error: {str(e)}"
    
    def _send_request(self, payload: Dict) -> Dict:
        """Send a raw JSON-RPC request and return the parsed response."""
        import requests
        
        response = requests.post(
            self.server_url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def _make_request(self, method: str, params: List[Any], encrypted: bool = False) -> Tuple[Any, Optional[str]]:
        """
        Make a JSON-RPC request, optionally encrypted.
        
        Args:
            method: The RPC method name
            params: List of parameters for the method
            encrypted: Whether to encrypt the request
            
        Returns:
            Tuple of (result, error_message). If successful, error_message is None.
        """
        self.request_id += 1
        
        if encrypted:
            return self._make_encrypted_request(method, params, self.request_id)
        else:
            # Use parent class implementation for unencrypted calls
            return super()._make_request(method, params)
    
    # Enhanced method signatures with encryption support
    
    def register_secret(self, uid: str, did: str, bid: str, version: int, 
                       x: str, y: str, max_guesses: int, expiration: int, 
                       encrypted: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Register a secret with the server.
        
        Args:
            uid: User ID
            did: Device ID
            bid: Backup ID
            version: Version number
            x: X coordinate
            y: Y coordinate
            max_guesses: Maximum number of guesses allowed
            expiration: Expiration timestamp
            encrypted: Whether to encrypt the request with Noise-NK
            
        Returns:
            Tuple of (success, error_message). If successful, error_message is None.
        """
        params = [uid, did, bid, version, x, y, max_guesses, expiration]
        result, error = self._make_request("RegisterSecret", params, encrypted)
        
        if error:
            return False, error
        
        return bool(result), None
    
    def recover_secret(self, uid: str, did: str, bid: str, b: str, guess_num: int,
                      encrypted: bool = False) -> Tuple[Optional[str], Optional[str]]:
        """
        Recover a secret from the server.
        
        Args:
            uid: User ID
            did: Device ID
            bid: Backup ID
            b: B parameter for recovery
            guess_num: Guess number
            encrypted: Whether to encrypt the request with Noise-NK
            
        Returns:
            Tuple of (recovered_secret, error_message). If successful, error_message is None.
        """
        params = [uid, did, bid, b, guess_num]
        result, error = self._make_request("RecoverSecret", params, encrypted)
        
        if error:
            return None, error
        
        return result, None
    
    def list_backups(self, uid: str, encrypted: bool = False) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """
        List backups for a user.
        
        Args:
            uid: User ID
            encrypted: Whether to encrypt the request with Noise-NK
            
        Returns:
            Tuple of (backup_list, error_message). If successful, error_message is None.
        """
        params = [uid]
        result, error = self._make_request("ListBackups", params, encrypted)
        
        if error:
            return None, error
        
        return result, None
    
    def echo(self, message: str, encrypted: bool = False) -> Tuple[Optional[str], Optional[str]]:
        """
        Echo a message (for testing connectivity).
        
        Args:
            message: Message to echo
            encrypted: Whether to encrypt the request with Noise-NK
            
        Returns:
            Tuple of (echoed_message, error_message). If successful, error_message is None.
        """
        params = [message]
        result, error = self._make_request("Echo", params, encrypted)
        
        if error:
            return None, error
        
        return result, None


# Convenience functions with encryption support
def create_encrypted_client(server_url: str = "http://localhost:8080", 
                           server_public_key: Optional[bytes] = None) -> EncryptedOpenADPClient:
    """Create and return a new encrypted OpenADP client instance."""
    return EncryptedOpenADPClient(server_url, server_public_key)


def parse_server_public_key(key_b64: str) -> bytes:
    """Parse a base64-encoded server public key."""
    try:
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key_bytes)}")
        return key_bytes
    except Exception as e:
        raise ValueError(f"Invalid server public key: {str(e)}")


if __name__ == "__main__":
    # Simple test/demo
    import sys
    logging.basicConfig(level=logging.DEBUG)
    
    if len(sys.argv) < 2:
        print("Usage: python encrypted_jsonrpc_client.py <server_public_key_base64>")
        print("Example: python encrypted_jsonrpc_client.py 'bf7fd106094050f57d5b683f1bfb2874283cba2388dc12ed0cbe84753835607e'")
        sys.exit(1)
    
    # Parse server public key
    try:
        if len(sys.argv[1]) == 64:  # Hex format
            server_key = bytes.fromhex(sys.argv[1])
        else:  # Base64 format
            server_key = parse_server_public_key(sys.argv[1])
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    print("Testing Encrypted JSON-RPC Client...")
    client = EncryptedOpenADPClient("http://localhost:8080", server_key)
    
    # Test unencrypted echo
    print("\n1. Testing unencrypted echo...")
    result, error = client.echo("Hello unencrypted!")
    if error:
        print(f"Error: {error}")
    else:
        print(f"Result: {result}")
    
    # Test encrypted echo
    print("\n2. Testing encrypted echo...")
    result, error = client.echo("Hello encrypted!", encrypted=True)
    if error:
        print(f"Error: {error}")
    else:
        print(f"Result: {result}")
    
    print("\n✅ Client test completed!") 