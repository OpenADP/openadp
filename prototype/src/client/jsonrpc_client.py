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
# Import dependencies for unified client
from typing import Any, Dict, List, Optional, Tuple, Union
import base64
import json
import logging
import os
import requests
import secrets
import sys

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
    """Base client for communicating with OpenADP JSON-RPC server."""
    
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
    
    def _make_request(self, method: str, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Make a plain JSON-RPC request (base implementation).
        
        Args:
            method: The RPC method name
            params: List of parameters for the method
            
        Returns:
            Tuple of (result, error_message). If successful, error_message is None.
        """
        return self._make_plain_request(method, params)
    
    def get_server_info(self) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Get server information including public key.
        
        Returns:
            Tuple of (server_info, error_message). If successful, error_message is None.
        """
        return self._make_plain_request("GetServerInfo", [])
    
    def echo(self, message: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Echo a message (for testing connectivity).
        
        Args:
            message: Message to echo
            
        Returns:
            Tuple of (echoed_message, error_message). If successful, error_message is None.
        """
        return self._make_plain_request("Echo", [message])
    
    def register_secret(self, uid: str, did: str, bid: str, version: int, 
                       x: str, y: str, max_guesses: int, expiration: int, 
                       encrypted: bool = False, auth_data: Optional[Dict] = None) -> Tuple[bool, Optional[str]]:
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
            encrypted: Whether to encrypt the request with Noise-NK (ignored in base client)
            auth_data: Authentication data (ignored in base client)
            
        Returns:
            Tuple of (success, error_message). If successful, error_message is None.
        """
        params = [uid, did, bid, version, x, y, max_guesses, expiration]
        result, error = self._make_plain_request("RegisterSecret", params)
        
        if error:
            return False, error
        
        return bool(result), None
    
    def recover_secret(self, uid: str, did: str, bid: str, b: str, guess_num: int,
                      encrypted: bool = False, auth_data: Optional[Dict] = None) -> Tuple[Optional[str], Optional[str]]:
        """
        Recover a secret from the server.
        
        Args:
            uid: User ID
            did: Device ID
            bid: Backup ID
            b: B parameter for recovery
            guess_num: Guess number
            encrypted: Whether to encrypt the request with Noise-NK (ignored in base client)
            auth_data: Authentication data (ignored in base client)
            
        Returns:
            Tuple of (recovered_secret, error_message). If successful, error_message is None.
        """
        params = [uid, did, bid, b, guess_num]
        result, error = self._make_plain_request("RecoverSecret", params)
        
        if error:
            return None, error
        
        return result, None
    
    def list_backups(self, uid: str, encrypted: bool = False, auth_data: Optional[Dict] = None) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """
        List backups for a user.
        
        Args:
            uid: User ID
            encrypted: Whether to encrypt the request with Noise-NK (ignored in base client)
            auth_data: Authentication data (ignored in base client)
            
        Returns:
            Tuple of (backup_list, error_message). If successful, error_message is None.
        """
        params = [uid]
        result, error = self._make_plain_request("ListBackups", params)
        
        if error:
            return None, error
        
        return result, None


class EncryptedOpenADPClient(OpenADPClient):
    """Enhanced OpenADP client with Noise-NK encryption support."""
    
    def __init__(self, server_url: str = "http://localhost:8080", server_public_key: Optional[bytes] = None):
        """
        Initialize the encrypted OpenADP client.
        
        Args:
            server_url: URL of the JSON-RPC server
            server_public_key: Server's Noise-NK public key (32 bytes). If None, will auto-discover from server.
        """
        super().__init__(server_url)
        
        # Only override auto-discovered key if explicitly provided
        if server_public_key is not None:
            if len(server_public_key) != 32:
                raise ValueError("Server public key must be exactly 32 bytes")
            self.server_public_key = server_public_key
        
        logger.debug(f"Initialized encrypted client for {server_url}")
        if self.server_public_key:
            logger.debug(f"Server public key: {self.server_public_key.hex()[:32]}...")
        else:
            logger.warning("No server public key available - encryption not supported")
    
    def _make_encrypted_request(self, method: str, params: List[Any], request_id: int, auth_data: Optional[Dict] = None) -> Tuple[Any, Optional[str]]:
        """
        Make an encrypted JSON-RPC request using Noise-NK.
        
        Args:
            method: The RPC method name
            params: List of parameters for the method
            request_id: Request ID for JSON-RPC
            auth_data: Authentication data to include in encrypted payload
            
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
            
            # Add authentication data if provided
            if auth_data:
                # If auth_data contains the raw auth info, we need to sign it with handshake hash
                if "needs_signing" in auth_data:
                    # This is for when we have the raw auth materials and need to create the full payload
                    access_token = auth_data["access_token"]
                    private_key = auth_data["private_key"]
                    public_key_jwk = auth_data["public_key_jwk"]
                    handshake_hash = noise_client.get_handshake_hash()
                    
                    # Create complete auth payload with handshake signature
                    complete_auth = self.create_auth_payload(access_token, private_key, public_key_jwk, handshake_hash)
                    inner_request["auth"] = complete_auth
                else:
                    # Pre-formed auth payload
                    inner_request["auth"] = auth_data
            
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
    
    def create_auth_payload(self, access_token: str, private_key, public_key_jwk: Dict, handshake_hash: bytes) -> Dict:
        """
        Create authentication payload for Noise-NK encrypted authentication.
        
        Args:
            access_token: OAuth access token
            private_key: DPoP private key (cryptography private key object)
            public_key_jwk: DPoP public key as JWK dictionary
            handshake_hash: Noise-NK handshake hash
            
        Returns:
            Complete auth payload dictionary
        """
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            
            # Sign the handshake hash with DPoP private key
            signature = private_key.sign(handshake_hash, ec.ECDSA(hashes.SHA256()))
            
            # Base64url encode the signature
            import base64
            def base64url_encode(data: bytes) -> str:
                return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')
            
            signature_b64 = base64url_encode(signature)
            
            # Create auth payload
            auth_payload = {
                "access_token": access_token,
                "handshake_signature": signature_b64,
                "dpop_public_key": public_key_jwk
            }
            
            return auth_payload
            
        except Exception as e:
            logger.error(f"Error creating auth payload: {e}")
            raise ValueError(f"Failed to create auth payload: {str(e)}")
    
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
    
    def _make_request(self, method: str, params: List[Any], encrypted: bool = False, auth_data: Optional[Dict] = None) -> Tuple[Any, Optional[str]]:
        """
        Make a JSON-RPC request, optionally encrypted.
        
        Args:
            method: The RPC method name
            params: List of parameters for the method
            encrypted: Whether to encrypt the request
            auth_data: Authentication data for encrypted requests
            
        Returns:
            Tuple of (result, error_message). If successful, error_message is None.
        """
        self.request_id += 1
        
        if encrypted:
            return self._make_encrypted_request(method, params, self.request_id, auth_data)
        else:
            # Use parent class implementation for unencrypted calls
            return super()._make_request(method, params)
    
    # Enhanced method signatures with encryption support
    
    def register_secret(self, uid: str, did: str, bid: str, version: int, 
                       x: str, y: str, max_guesses: int, expiration: int, 
                       encrypted: bool = False, auth_data: Optional[Dict] = None) -> Tuple[bool, Optional[str]]:
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
        result, error = self._make_request("RegisterSecret", params, encrypted, auth_data)
        
        if error:
            return False, error
        
        return bool(result), None
    
    def recover_secret(self, uid: str, did: str, bid: str, b: str, guess_num: int,
                      encrypted: bool = False, auth_data: Optional[Dict] = None) -> Tuple[Optional[str], Optional[str]]:
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
        result, error = self._make_request("RecoverSecret", params, encrypted, auth_data)
        
        if error:
            return None, error
        
        return result, None
    
    def list_backups(self, uid: str, encrypted: bool = False, auth_data: Optional[Dict] = None) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """
        List backups for a user.
        
        Args:
            uid: User ID
            encrypted: Whether to encrypt the request with Noise-NK
            
        Returns:
            Tuple of (backup_list, error_message). If successful, error_message is None.
        """
        params = [uid]
        result, error = self._make_request("ListBackups", params, encrypted, auth_data)
        
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
    
    def make_authenticated_request(self, method: str, params: List[Any], access_token: str, private_key, public_key_jwk: Dict) -> Tuple[Any, Optional[str]]:
        """
        Make an authenticated encrypted request using DPoP over Noise-NK.
        
        Args:
            method: The RPC method name
            params: List of parameters for the method
            access_token: OAuth access token
            private_key: DPoP private key (cryptography object)
            public_key_jwk: DPoP public key as JWK dictionary
            
        Returns:
            Tuple of (result, error_message). If successful, error_message is None.
        """
        auth_data = {
            "needs_signing": True,
            "access_token": access_token,
            "private_key": private_key,
            "public_key_jwk": public_key_jwk
        }
        
        return self._make_request(method, params, encrypted=True, auth_data=auth_data)


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


# Convenience functions for backward compatibility
def create_client(server_url: str = "http://localhost:8080") -> EncryptedOpenADPClient:
    """Create and return a new OpenADP client instance."""
    return EncryptedOpenADPClient(server_url)


def register_secret(uid: str, did: str, bid: str, version: int, 
                   x: str, y: str, max_guesses: int, expiration: int,
                   server_url: str = "http://localhost:8080") -> Tuple[bool, Optional[str]]:
    """Register a secret using a one-shot client."""
    client = EncryptedOpenADPClient(server_url)
    return client.register_secret(uid, did, bid, version, x, y, max_guesses, expiration, encrypted=True)


def recover_secret(uid: str, did: str, bid: str, b: str, guess_num: int,
                  server_url: str = "http://localhost:8080") -> Tuple[Optional[str], Optional[str]]:
    """Recover a secret using a one-shot client."""
    client = EncryptedOpenADPClient(server_url)
    return client.recover_secret(uid, did, bid, b, guess_num, encrypted=True)


def list_backups(uid: str, server_url: str = "http://localhost:8080") -> Tuple[Optional[List[Dict]], Optional[str]]:
    """List backups using a one-shot client."""
    client = EncryptedOpenADPClient(server_url)
    return client.list_backups(uid, encrypted=True)


def echo(message: str, server_url: str = "http://localhost:8080") -> Tuple[Optional[str], Optional[str]]:
    """Echo a message using a one-shot client."""
    client = EncryptedOpenADPClient(server_url)
    return client.echo(message) 