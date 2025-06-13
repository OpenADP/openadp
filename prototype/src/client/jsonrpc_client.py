#!/usr/bin/env python3
"""
JSON-RPC Client for OpenADP Server with Automatic Encryption

This client provides Python methods to interact with the OpenADP JSON-RPC server.
It automatically uses Noise-NK encryption for security-sensitive operations:
- register_secret: Encrypted by default
- recover_secret: Encrypted by default  
- list_backups: Encrypted by default
- echo: Unencrypted by default (for connectivity testing)

The client auto-discovers the server's public key and handles encryption transparently.
"""

import base64
import json
import logging
import os
import requests
import secrets
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

# Add path to access noise_nk module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'openadp'))

try:
    from noise_nk import NoiseNK, generate_keypair
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    logging.warning("Noise-NK encryption not available - falling back to unencrypted mode")

logger = logging.getLogger(__name__)


class OpenADPClient:
    """Client for communicating with OpenADP JSON-RPC server with automatic encryption."""
    
    def __init__(self, server_url: str = "http://localhost:8080"):
        """
        Initialize the OpenADP client.
        
        Args:
            server_url: URL of the JSON-RPC server (default: http://localhost:8080)
        """
        self.server_url = server_url
        self.request_id = 0
        self.server_public_key = None
        self._server_info_cached = False
        
        # Auto-discover server capabilities
        self._discover_server_info()
    
    def _discover_server_info(self) -> None:
        """Auto-discover server public key and capabilities."""
        try:
            result, error = self._make_plain_request("GetServerInfo", [])
            if error:
                logger.warning(f"Could not discover server info: {error}")
                return
            
            if result and "noise_nk_public_key" in result:
                try:
                    self.server_public_key = base64.b64decode(result["noise_nk_public_key"])
                    logger.debug(f"Discovered server public key: {self.server_public_key.hex()[:32]}...")
                    self._server_info_cached = True
                except Exception as e:
                    logger.warning(f"Could not decode server public key: {e}")
            else:
                logger.warning("Server did not provide public key - encryption not available")
                
        except Exception as e:
            logger.warning(f"Server discovery failed: {e}")
    
    def _make_plain_request(self, method: str, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Make an unencrypted JSON-RPC request to the server.
        
        Args:
            method: The RPC method name
            params: List of parameters for the method
            
        Returns:
            Tuple of (result, error_message). If successful, error_message is None.
        """
        self.request_id += 1
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.request_id
        }
        
        try:
            response = requests.post(
                self.server_url,
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                timeout=30
            )
            response.raise_for_status()
            
            result = response.json()
            
            if "error" in result:
                error_info = result["error"]
                if isinstance(error_info, dict):
                    error_msg = error_info.get("message", str(error_info))
                else:
                    error_msg = str(error_info)
                return None, error_msg
            
            return result.get("result"), None
            
        except requests.exceptions.RequestException as e:
            return None, f"Network error: {str(e)}"
        except json.JSONDecodeError as e:
            return None, f"JSON decode error: {str(e)}"
        except Exception as e:
            return None, f"Unexpected error: {str(e)}"
    
    def _make_encrypted_request(self, method: str, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Make an encrypted JSON-RPC request using Noise-NK.
        
        Args:
            method: The RPC method name
            params: List of parameters for the method
            
        Returns:
            Tuple of (result, error_message). If successful, error_message is None.
        """
        if not ENCRYPTION_AVAILABLE:
            return None, "Encryption not available - missing noise_nk module"
        
        if self.server_public_key is None:
            return None, "No server public key available - encryption not possible"
        
        try:
            # Generate unique session ID
            session_id = base64.b64encode(secrets.token_bytes(16)).decode('ascii')
            
            # Create Noise-NK client (initiator) 
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
            
            self.request_id += 1
            handshake_payload = {
                "jsonrpc": "2.0",
                "method": "noise_handshake",
                "params": [session_id, base64.b64encode(client_handshake).decode('ascii')],
                "id": self.request_id
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
            self.request_id += 1
            inner_request = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": self.request_id
            }
            
            # Encrypt the inner request
            inner_json = json.dumps(inner_request).encode('utf-8')
            encrypted_inner = noise_client.encrypt(inner_json)
            
            encrypted_payload = {
                "jsonrpc": "2.0",
                "method": "encrypted_call",
                "params": [session_id, base64.b64encode(encrypted_inner).decode('ascii')],
                "id": self.request_id
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
        response = requests.post(
            self.server_url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    
    def _make_request(self, method: str, params: List[Any], encrypted: Optional[bool] = None) -> Tuple[Any, Optional[str]]:
        """
        Make a JSON-RPC request with automatic encryption for security-sensitive operations.
        
        Args:
            method: The RPC method name
            params: List of parameters for the method
            encrypted: Override encryption behavior. If None, uses smart defaults:
                      - RegisterSecret, RecoverSecret, ListBackups: encrypted by default
                      - Echo, GetServerInfo: unencrypted by default
            
        Returns:
            Tuple of (result, error_message). If successful, error_message is None.
        """
        # Determine encryption behavior
        if encrypted is None:
            # Smart defaults: encrypt security-sensitive operations
            encrypted = method in ['RegisterSecret', 'RecoverSecret', 'ListBackups']
        
        if encrypted:
            return self._make_encrypted_request(method, params)
        else:
            return self._make_plain_request(method, params)

    def register_secret(self, uid: str, did: str, bid: str, version: int, 
                       x: str, y: str, max_guesses: int, expiration: int, 
                       encrypted: Optional[bool] = None) -> Tuple[bool, Optional[str]]:
        """
        Register a secret with the server (encrypted by default).
        
        Args:
            uid: User ID
            did: Device ID
            bid: Backup ID
            version: Version number
            x: X coordinate
            y: Y coordinate
            max_guesses: Maximum number of guesses allowed
            expiration: Expiration timestamp
            encrypted: Override encryption (default: True for security)
            
        Returns:
            Tuple of (success, error_message). If successful, error_message is None.
        """
        params = [uid, did, bid, version, x, y, max_guesses, expiration]
        result, error = self._make_request("RegisterSecret", params, encrypted)
        
        if error:
            return False, error
        
        return bool(result), None
    
    def recover_secret(self, uid: str, did: str, bid: str, b: str, guess_num: int,
                      encrypted: Optional[bool] = None) -> Tuple[Optional[str], Optional[str]]:
        """
        Recover a secret from the server (encrypted by default).
        
        Args:
            uid: User ID
            did: Device ID
            bid: Backup ID
            b: B parameter for recovery
            guess_num: Guess number
            encrypted: Override encryption (default: True for security)
            
        Returns:
            Tuple of (recovered_secret, error_message). If successful, error_message is None.
        """
        params = [uid, did, bid, b, guess_num]
        result, error = self._make_request("RecoverSecret", params, encrypted)
        
        if error:
            return None, error
        
        return result, None
    
    def list_backups(self, uid: str, encrypted: Optional[bool] = None) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """
        List backups for a user (encrypted by default).
        
        Args:
            uid: User ID
            encrypted: Override encryption (default: True for security)
            
        Returns:
            Tuple of (backup_list, error_message). If successful, error_message is None.
        """
        params = [uid]
        result, error = self._make_request("ListBackups", params, encrypted)
        
        if error:
            return None, error
        
        return result, None
    
    def echo(self, message: str, encrypted: Optional[bool] = None) -> Tuple[Optional[str], Optional[str]]:
        """
        Echo a message (unencrypted by default for connectivity testing).
        
        Args:
            message: Message to echo
            encrypted: Override encryption (default: False for connectivity testing)
            
        Returns:
            Tuple of (echoed_message, error_message). If successful, error_message is None.
        """
        params = [message]
        result, error = self._make_request("Echo", params, encrypted)
        
        if error:
            return None, error
        
        return result, None

    def get_server_info(self) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Get server information including public key (always unencrypted).
        
        Returns:
            Tuple of (server_info, error_message). If successful, error_message is None.
        """
        params = []
        result, error = self._make_request("GetServerInfo", params, encrypted=False)
        
        if error:
            return None, error
        
        return result, None


# Convenience functions for simple usage without creating a client instance
def create_client(server_url: str = "http://localhost:8080") -> OpenADPClient:
    """Create and return a new OpenADP client instance."""
    return OpenADPClient(server_url)


def register_secret(uid: str, did: str, bid: str, version: int, 
                   x: str, y: str, max_guesses: int, expiration: int,
                   server_url: str = "http://localhost:8080") -> Tuple[bool, Optional[str]]:
    """Convenience function to register a secret."""
    client = OpenADPClient(server_url)
    return client.register_secret(uid, did, bid, version, x, y, max_guesses, expiration)


def recover_secret(uid: str, did: str, bid: str, b: str, guess_num: int,
                  server_url: str = "http://localhost:8080") -> Tuple[Optional[str], Optional[str]]:
    """Convenience function to recover a secret."""
    client = OpenADPClient(server_url)
    return client.recover_secret(uid, did, bid, b, guess_num)


def list_backups(uid: str, server_url: str = "http://localhost:8080") -> Tuple[Optional[List[Dict]], Optional[str]]:
    """Convenience function to list backups."""
    client = OpenADPClient(server_url)
    return client.list_backups(uid)


def echo(message: str, server_url: str = "http://localhost:8080") -> Tuple[Optional[str], Optional[str]]:
    """Convenience function to echo a message."""
    client = OpenADPClient(server_url)
    return client.echo(message)


if __name__ == "__main__":
    # Simple test/demo
    client = OpenADPClient("https://xyzzybill.openadp.org")
    
    print("Testing echo...")
    result, error = client.echo("Hello, World!")
    if error:
        print(f"Error: {error}")
    else:
        print(f"Echo result: {result}")
