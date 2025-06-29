"""
OpenADP Python Client Implementation

This module provides Python client implementations for OpenADP servers,
matching the Go client functionality exactly:

- OpenADPClient: Basic JSON-RPC client (no encryption)
- EncryptedOpenADPClient: JSON-RPC client with Noise-NK encryption
- MultiServerClient: High-level client managing multiple servers

All clients implement standardized interfaces for cross-language compatibility.
"""

import json
import secrets
import time
import base64
import hashlib
import os
import threading
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from enum import IntEnum
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from .debug import debug_log, is_debug_mode_enabled, get_deterministic_ephemeral_secret

# Import cryptographic dependencies
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF  
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Error codes matching Go implementation
class ErrorCode(IntEnum):
    NETWORK_FAILURE = 1001
    AUTHENTICATION_FAILED = 1002
    INVALID_REQUEST = 1003
    SERVER_ERROR = 1004
    ENCRYPTION_FAILED = 1005
    NO_LIVE_SERVERS = 1006
    INVALID_RESPONSE = 1007

class ServerSelectionStrategy(IntEnum):
    FIRST_AVAILABLE = 0
    ROUND_ROBIN = 1
    RANDOM = 2
    LOWEST_LATENCY = 3

@dataclass
class ServerInfo:
    """Server information from registry or configuration."""
    url: str
    public_key: str = ""
    country: str = ""
    remaining_guesses: int = -1  # -1 means unknown, >=0 means known remaining guesses

@dataclass
class RegisterSecretRequest:
    """Standardized request for RegisterSecret operation."""
    auth_code: str
    uid: str
    did: str
    bid: str
    version: int
    x: int
    y: str  # Base64 encoded point
    max_guesses: int
    expiration: int
    encrypted: bool = False
    auth_data: Optional[Dict[str, Any]] = None

@dataclass
class RegisterSecretResponse:
    """Standardized response for RegisterSecret operation."""
    success: bool
    message: str = ""

@dataclass
class RecoverSecretRequest:
    """Standardized request for RecoverSecret operation."""
    auth_code: str
    uid: str
    did: str
    bid: str
    b: str  # Base64 encoded point
    guess_num: int
    encrypted: bool = False
    auth_data: Optional[Dict[str, Any]] = None

@dataclass
class RecoverSecretResponse:
    """Standardized response for RecoverSecret operation."""
    version: int
    x: int
    si_b: str  # Base64 encoded point
    num_guesses: int
    max_guesses: int
    expiration: int

@dataclass
class ListBackupsRequest:
    """Standardized request for ListBackups operation."""
    uid: str
    auth_code: str = ""
    encrypted: bool = False
    auth_data: Optional[Dict[str, Any]] = None

@dataclass
class BackupInfo:
    """Information about a backup."""
    uid: str
    bid: str
    version: int
    num_guesses: int
    max_guesses: int
    expiration: int

@dataclass
class ListBackupsResponse:
    """Standardized response for ListBackups operation."""
    backups: List[BackupInfo]

@dataclass
class ServerInfoResponse:
    """Standardized response for GetServerInfo operation."""
    server_version: str
    noise_nk_public_key: str = ""
    supported_methods: List[str] = None
    max_request_size: int = 0
    rate_limits: Dict[str, Any] = None

    def __post_init__(self):
        if self.supported_methods is None:
            self.supported_methods = []
        if self.rate_limits is None:
            self.rate_limits = {}

class OpenADPError(Exception):
    """OpenADP-specific error with error codes."""
    
    def __init__(self, code: int, message: str, details: str = ""):
        self.code = code
        self.message = message
        self.details = details
        super().__init__(self._format_message())
    
    def _format_message(self) -> str:
        if self.details:
            return f"OpenADP Error {self.code}: {self.message} ({self.details})"
        return f"OpenADP Error {self.code}: {self.message}"

class JSONRPCError:
    """JSON-RPC 2.0 error structure."""
    
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data

class JSONRPCRequest:
    """JSON-RPC 2.0 request structure."""
    
    def __init__(self, method: str, params: Any = None, request_id: int = 1):
        self.jsonrpc = "2.0"
        self.method = method
        self.params = params
        self.id = request_id
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "jsonrpc": self.jsonrpc,
            "method": self.method,
            "id": self.id
        }
        if self.params is not None:
            result["params"] = self.params
        return result

class JSONRPCResponse:
    """JSON-RPC 2.0 response structure."""
    
    def __init__(self, result: Any = None, error: JSONRPCError = None, request_id: int = 1):
        self.jsonrpc = "2.0"
        self.result = result
        self.error = error
        self.id = request_id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'JSONRPCResponse':
        """Parse JSON-RPC response from dictionary, handling both string and structured errors."""
        response = cls()
        response.jsonrpc = data.get("jsonrpc", "2.0")
        response.result = data.get("result")
        response.id = data.get("id", 1)
        
        # Handle error field - can be string or structured
        if "error" in data and data["error"] is not None:
            error_data = data["error"]
            if isinstance(error_data, str):
                # String error (legacy format)
                response.error = JSONRPCError(-32603, error_data)
            elif isinstance(error_data, dict):
                # Structured error
                response.error = JSONRPCError(
                    error_data.get("code", -32603),
                    error_data.get("message", "Unknown error"),
                    error_data.get("data")
                )
        
        return response

class OpenADPClient:
    """
    Basic OpenADP JSON-RPC client without encryption.
    
    This client provides basic connectivity testing and ListBackups functionality.
    For secure operations like RegisterSecret and RecoverSecret, use EncryptedOpenADPClient.
    """
    
    def __init__(self, url: str, timeout: int = 30):
        self.url = url
        self.timeout = timeout
        self.request_id = secrets.randbelow(1000000) + 1  # Random starting ID to avoid collisions
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'OpenADP-Python-Client/1.0'
        })
    
    def _make_request(self, method: str, params: Any = None) -> Any:
        """Make a JSON-RPC request to the server."""
        debug_log(f"Making request to {self.url}")
        debug_log(f"Method: {method}")
        debug_log(f"Parameters: {params}")
        
        request = JSONRPCRequest(method, params, self.request_id)
        self.request_id += 1
        
        debug_log(f"Request ID: {request.id}")
        debug_log(f"📤 PYTHON: Unencrypted JSON request: {json.dumps(request.to_dict(), indent=2)}")
        
        try:
            response = self.session.post(
                self.url,
                json=request.to_dict(),
                timeout=self.timeout
            )
            response.raise_for_status()
        except requests.RequestException as e:
            debug_log(f"HTTP request failed: {e}")
            raise OpenADPError(
                ErrorCode.NETWORK_FAILURE,
                f"HTTP request failed: {str(e)}"
            )
        
        try:
            response_data = response.json()
            debug_log(f"📥 PYTHON: Unencrypted JSON response: {json.dumps(response_data, indent=2)}")
        except json.JSONDecodeError as e:
            debug_log(f"Invalid JSON response: {e}")
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"Invalid JSON response: {str(e)}"
            )
        
        rpc_response = JSONRPCResponse.from_dict(response_data)
        
        if rpc_response.error:
            debug_log(f"JSON-RPC error: {rpc_response.error.code} - {rpc_response.error.message}")
            raise OpenADPError(
                ErrorCode.SERVER_ERROR,
                f"JSON-RPC error {rpc_response.error.code}: {rpc_response.error.message}"
            )
        
        debug_log(f"Request successful, result: {rpc_response.result}")
        return rpc_response.result
    
    def list_backups(self, uid: str) -> List[Dict[str, Any]]:
        """List all backups for a user."""
        result = self._make_request("ListBackups", [uid])
        
        if not isinstance(result, list):
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"Expected list response, got {type(result)}"
            )
        
        return result
    
    def echo(self, message: str) -> str:
        """Test connectivity to the server."""
        result = self._make_request("Echo", [message])
        
        if not isinstance(result, str):
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"Expected string response, got {type(result)}"
            )
        
        if result != message:
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"Echo mismatch: expected {message!r}, got {result!r}"
            )
        
        return result
    
    def ping(self) -> None:
        """Test connectivity (alias for echo with 'ping' message)."""
        self.echo("ping")
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server information."""
        result = self._make_request("GetServerInfo", None)
        
        if not isinstance(result, dict):
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"Expected dict response, got {type(result)}"
            )
        
        return result
    
    # Standardized interface implementation
    def register_secret_standardized(self, request: RegisterSecretRequest) -> RegisterSecretResponse:
        """RegisterSecret not supported by basic client."""
        raise OpenADPError(
            ErrorCode.INVALID_REQUEST,
            "RegisterSecret not supported by basic client - use EncryptedOpenADPClient for secure operations"
        )
    
    def recover_secret_standardized(self, request: RecoverSecretRequest) -> RecoverSecretResponse:
        """RecoverSecret not supported by basic client."""
        raise OpenADPError(
            ErrorCode.INVALID_REQUEST,
            "RecoverSecret not supported by basic client - use EncryptedOpenADPClient for secure operations"
        )
    
    def list_backups_standardized(self, request: ListBackupsRequest) -> ListBackupsResponse:
        """List backups using standardized interface."""
        backups_data = self.list_backups(request.uid)
        
        backups = []
        for backup_data in backups_data:
            backup = BackupInfo(
                uid=backup_data.get("uid", ""),
                bid=backup_data.get("bid", ""),
                version=backup_data.get("version", 0),
                num_guesses=backup_data.get("num_guesses", 0),
                max_guesses=backup_data.get("max_guesses", 0),
                expiration=backup_data.get("expiration", 0)
            )
            backups.append(backup)
        
        return ListBackupsResponse(backups=backups)
    
    def get_server_info_standardized(self) -> ServerInfoResponse:
        """Get server info using standardized interface."""
        info = self.get_server_info()
        
        return ServerInfoResponse(
            server_version=info.get("version", ""),
            noise_nk_public_key="",
            supported_methods=["ListBackups", "Echo", "GetServerInfo"],
            max_request_size=1024 * 1024,  # 1MB default
            rate_limits={}
        )
    
    def test_connection(self) -> None:
        """Test connection to server."""
        self.ping()
    
    def get_server_url(self) -> str:
        """Get server URL."""
        return self.url
    
    def supports_encryption(self) -> bool:
        """Basic client doesn't support encryption."""
        return False 

class NoiseNK:
    """Noise-NK protocol implementation using the noiseprotocol library."""
    
    def __init__(self, remote_static_key=None):
        """Initialize NoiseNK with optional remote static key."""
        self.remote_static_key = remote_static_key
        self.noise = None
        self.is_initiator = False
        self.handshake_complete = False
        
    def initialize_as_initiator(self, remote_static_key):
        """Initialize as initiator with remote static key."""
        from noise.connection import NoiseConnection, Keypair
        
        debug_log("Initializing NoiseNK as initiator")
        
        self.remote_static_key = remote_static_key
        self.is_initiator = True
        
        # Create NoiseConnection with NK pattern
        # For NK pattern, initiator knows responder's static key
        self.noise = NoiseConnection.from_name(b'Noise_NK_25519_AESGCM_SHA256')
        self.noise.set_as_initiator()
        
        # Set the remote static key (responder's public key)
        # This is required for NK pattern
        self.noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_static_key)
        debug_log(f"Set remote static key: {remote_static_key.hex()}")
        
        # Use deterministic ephemeral key in debug mode
        if is_debug_mode_enabled():
            ephemeral_secret = get_deterministic_ephemeral_secret()
            self.noise.set_keypair_from_private_bytes(Keypair.EPHEMERAL, ephemeral_secret)
            debug_log(f"Using deterministic ephemeral secret: {ephemeral_secret.hex()}")
        
        # Start handshake
        self.noise.start_handshake()
        debug_log("NoiseNK handshake started")
        
    def initialize_as_responder(self, local_static_private_key):
        """Initialize as responder with local static private key."""
        from noise.connection import NoiseConnection, Keypair
        
        self.is_initiator = False
        
        # Create NoiseConnection with NK pattern
        self.noise = NoiseConnection.from_name(b'Noise_NK_25519_AESGCM_SHA256')
        self.noise.set_as_responder()
        
        # Set our static private key
        self.noise.set_keypair_from_private_bytes(Keypair.STATIC, local_static_private_key)
        
        # Start handshake
        self.noise.start_handshake()
        
    def write_message(self, payload=b''):
        """Write a handshake message."""
        if not self.noise:
            raise ValueError("NoiseNK not initialized")
            
        message = self.noise.write_message(payload)
        
        # Check if handshake is complete
        if self.noise.handshake_finished:
            self.handshake_complete = True
            
        return message
        
    def read_message(self, message):
        """Read a handshake message."""
        if not self.noise:
            raise ValueError("NoiseNK not initialized")
            
        payload = self.noise.read_message(message)
        
        # Check if handshake is complete
        if self.noise.handshake_finished:
            self.handshake_complete = True
            
        return payload
        
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt a message using transport mode."""
        if not self.handshake_complete:
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                "Handshake not complete"
            )
        
        debug_log("🔐 TRANSPORT ENCRYPT")
        debug_log(f"  - plaintext length: {len(plaintext)}")
        debug_log(f"  - plaintext hex: {plaintext.hex()}")
        
        # Debug transport keys being used
        try:
            cs1, cs2 = self.split_keys()
            debug_log(f"  - send key (cs1): {cs1.k.hex() if hasattr(cs1, 'k') else 'unknown'}")
            debug_log(f"  - recv key (cs2): {cs2.k.hex() if hasattr(cs2, 'k') else 'unknown'}")
        except Exception as e:
            debug_log(f"  - Failed to extract keys for debug: {e}")
        
        try:
            encrypted = self.noise.encrypt(plaintext)
            debug_log(f"  - encrypted length: {len(encrypted)}")
            debug_log(f"  - encrypted hex: {encrypted.hex()}")
            return encrypted
        except Exception as e:
            debug_log(f"Failed to encrypt: {e}")
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                f"failed to encrypt: {str(e)}"
            )
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt a message using transport mode."""
        if not self.handshake_complete:
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                "Handshake not complete"
            )
        
        debug_log("🔓 TRANSPORT DECRYPT")
        debug_log(f"  - ciphertext length: {len(ciphertext)}")
        debug_log(f"  - ciphertext hex: {ciphertext.hex()}")
        
        try:
            decrypted = self.noise.decrypt(ciphertext)
            debug_log(f"  - decrypted length: {len(decrypted)}")
            debug_log(f"  - decrypted hex: {decrypted.hex()}")
            return decrypted
        except Exception as e:
            debug_log(f"Failed to decrypt: {e}")
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                f"failed to decrypt: {str(e)}"
            )

    def get_handshake_hash(self):
        """Get the handshake hash after handshake is complete."""
        if not self.noise:
            raise ValueError("NoiseNK not initialized")
        return self.noise.get_handshake_hash()

    def split_keys(self):
        """Split final chaining key into transport keys after handshake completion."""
        if not self.handshake_complete:
            raise ValueError("Handshake not complete - cannot split keys")
        
        try:
            # The noise library's split() method returns two CipherState objects
            # Note: Different noise library versions may have different APIs
            if hasattr(self.noise, 'split'):
                cipher1, cipher2 = self.noise.split()
                return cipher1, cipher2
            else:
                # Fallback: return None values to indicate keys not accessible
                return None, None
        except Exception as e:
            # For debugging purposes, don't raise - just return None
            return None, None

def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a new X25519 keypair for Noise-NK."""
    if not CRYPTO_AVAILABLE:
        raise OpenADPError(
            ErrorCode.ENCRYPTION_FAILED,
            "Cryptographic dependencies not available"
        )
    
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return private_bytes, public_bytes

def parse_server_public_key(key_b64: str) -> bytes:
    """Parse a base64-encoded server public key."""
    return base64.b64decode(key_b64)

class EncryptedOpenADPClient:
    """
    OpenADP JSON-RPC client with Noise-NK encryption support.
    
    This client extends the basic client with Noise-NK encryption capabilities,
    matching the Go EncryptedOpenADPClient implementation exactly.
    """
    
    def __init__(self, url: str, server_public_key: Optional[bytes] = None, timeout: int = 30):
        self.url = url
        self.server_public_key = server_public_key
        self.timeout = timeout
        self.request_id = secrets.randbelow(1000000) + 1  # Random starting ID to avoid collisions
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'OpenADP-Python-Client/1.0'
        })
    
    def has_public_key(self) -> bool:
        """Return true if the client has a server public key for encryption."""
        return self.server_public_key is not None and len(self.server_public_key) > 0
    
    def _make_request(self, method: str, params: Any = None, encrypted: bool = False, 
                     auth_data: Optional[Dict[str, Any]] = None) -> Any:
        """Make a JSON-RPC request with optional Noise-NK encryption."""
        if encrypted and not self.has_public_key():
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                "encryption requested but no server public key available"
            )
        
        if encrypted:
            return self._make_encrypted_request(method, params, auth_data)
        else:
            return self._make_unencrypted_request(method, params)
    
    def _make_unencrypted_request(self, method: str, params: Any = None) -> Any:
        """Make a standard JSON-RPC request without encryption."""
        debug_log(f"Making unencrypted request to {self.url}")
        debug_log(f"Method: {method}")
        debug_log(f"Parameters: {params}")
        
        request = JSONRPCRequest(method, params, self.request_id)
        self.request_id += 1
        
        debug_log(f"Request ID: {request.id}")
        
        try:
            response = self.session.post(
                self.url,
                json=request.to_dict(),
                timeout=self.timeout
            )
            response.raise_for_status()
        except requests.RequestException as e:
            debug_log(f"HTTP request failed: {e}")
            raise OpenADPError(
                ErrorCode.NETWORK_FAILURE,
                f"HTTP request failed: {str(e)}"
            )
        
        try:
            response_data = response.json()
            debug_log(f"Response received: {response_data}")
        except json.JSONDecodeError as e:
            debug_log(f"Invalid JSON response: {e}")
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"Invalid JSON response: {str(e)}"
            )
        
        rpc_response = JSONRPCResponse.from_dict(response_data)
        
        if rpc_response.error:
            debug_log(f"JSON-RPC error: {rpc_response.error.code} - {rpc_response.error.message}")
            raise OpenADPError(
                ErrorCode.SERVER_ERROR,
                f"JSON-RPC error {rpc_response.error.code}: {rpc_response.error.message}"
            )
        
        debug_log(f"Request successful, result: {rpc_response.result}")
        return rpc_response.result
    
    def _make_encrypted_request(self, method: str, params: Any = None, 
                               auth_data: Optional[Dict[str, Any]] = None) -> Any:
        """Make a Noise-NK encrypted JSON-RPC request."""
        debug_log(f"Making encrypted request to {self.url}")
        debug_log(f"Method: {method}")
        debug_log(f"Parameters (before encryption): {params}")
        debug_log(f"Auth data: {auth_data}")
        
        # Generate session ID
        session_id = secrets.randbelow(1 << 128).to_bytes(16, 'little').hex()
        debug_log(f"Generated session ID: {session_id}")
        
        # Step 2: Initialize Noise-NK as initiator
        try:
            noise_client = NoiseNK()
            noise_client.initialize_as_initiator(self.server_public_key)
        except Exception as e:
            debug_log(f"Failed to initialize Noise-NK: {e}")
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                f"Failed to initialize Noise-NK: {e}"
            )
        
        # Step 3: Start handshake
        try:
            handshake_msg1 = noise_client.write_message(b"")
            debug_log(f"Created handshake message 1: {len(handshake_msg1)} bytes")
            debug_log(f"Handshake message 1 hex: {handshake_msg1.hex()}")
        except Exception as e:
            debug_log(f"Failed to create handshake message: {e}")
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                f"Failed to create handshake message: {e}"
            )
        
        # Step 4: Send handshake to server
        request_id = self.request_id
        self.request_id += 1
        
        handshake_request = JSONRPCRequest(
            "noise_handshake",
            [{
                "session": session_id,
                "message": base64.b64encode(handshake_msg1).decode('ascii')
            }],
            request_id
        )
        
        debug_log(f"Sending handshake request (ID: {request_id})")
        debug_log(f"📤 PYTHON: Handshake JSON request: {json.dumps(handshake_request.to_dict(), indent=2)}")
        
        try:
            response = self.session.post(
                self.url,
                json=handshake_request.to_dict(),
                timeout=self.timeout
            )
            response.raise_for_status()
        except requests.RequestException as e:
            debug_log(f"Failed to send handshake request: {e}")
            raise OpenADPError(
                ErrorCode.NETWORK_FAILURE,
                f"failed to send handshake request: {str(e)}"
            )
        
        try:
            handshake_resp_data = response.json()
            debug_log(f"📥 PYTHON: Handshake JSON response: {json.dumps(handshake_resp_data, indent=2)}")
        except json.JSONDecodeError as e:
            debug_log(f"Failed to parse handshake response: {e}")
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"failed to parse handshake response: {str(e)}"
            )
        
        handshake_response = JSONRPCResponse.from_dict(handshake_resp_data)
        
        if handshake_response.error:
            debug_log(f"Handshake JSON-RPC error: {handshake_response.error.code} - {handshake_response.error.message}")
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                f"handshake JSON-RPC error {handshake_response.error.code}: {handshake_response.error.message}"
            )
        
        # Step 5: Process server's handshake response
        if not isinstance(handshake_response.result, dict):
            debug_log("Invalid handshake response format")
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                "invalid handshake response format"
            )
        
        handshake_msg_b64 = handshake_response.result.get("message")
        if not handshake_msg_b64:
            debug_log("Handshake response missing message field")
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                "handshake response missing message field"
            )
        
        try:
            handshake_msg2 = base64.b64decode(handshake_msg_b64)
            debug_log(f"Received handshake message 2: {len(handshake_msg2)} bytes")
            debug_log(f"Handshake message 2 hex: {handshake_msg2.hex()}")
        except Exception as e:
            debug_log(f"Failed to decode handshake message: {e}")
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"failed to decode handshake message: {str(e)}"
            )
        
        # Complete handshake
        try:
            noise_client.read_message(handshake_msg2)
            debug_log("Noise-NK handshake completed successfully")
            
            # Debug transport keys after handshake completion
            try:
                cs1, cs2 = noise_client.split_keys()
                
                if cs1 is not None and cs2 is not None:
                    debug_log("🔑 PYTHON INITIATOR: Transport key assignment complete")
                    debug_log("  - send_cipher: cs1 (initiator->responder)")
                    debug_log("  - recv_cipher: cs2 (responder->initiator)")
                    debug_log("  - Python uses cs1 for send, cs2 for recv (initiator)")
                    
                    # Log transport cipher information
                    debug_log("🔑 PYTHON INITIATOR: Transport cipher information")
                    
                    # Extract actual keys from CipherState objects
                    send_key = None
                    recv_key = None
                    
                    # Try different ways to access the key data
                    if hasattr(cs1, 'k') and cs1.k is not None:
                        send_key = cs1.k
                    elif hasattr(cs1, 'cipher') and hasattr(cs1.cipher, 'key'):
                        send_key = cs1.cipher.key
                    elif hasattr(cs1, '_key'):
                        send_key = cs1._key
                    
                    if hasattr(cs2, 'k') and cs2.k is not None:
                        recv_key = cs2.k
                    elif hasattr(cs2, 'cipher') and hasattr(cs2.cipher, 'key'):
                        recv_key = cs2.cipher.key
                    elif hasattr(cs2, '_key'):
                        recv_key = cs2._key
                    
                    # Log the keys
                    if send_key is not None:
                        debug_log(f"  - send key: {send_key.hex()}")
                    else:
                        debug_log("  - send key: not accessible")
                        
                    if recv_key is not None:
                        debug_log(f"  - recv key: {recv_key.hex()}")
                    else:
                        debug_log("  - recv key: not accessible")
                else:
                    debug_log("🔑 PYTHON: Transport keys not accessible")
                    
            except Exception as e:
                debug_log("🔑 PYTHON: Transport keys not accessible")
                
        except Exception as e:
            debug_log(f"Failed to complete handshake: {e}")
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                f"Failed to complete handshake: {e}"
            )
        
        # Step 6: Prepare the actual method call
        method_call = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id
        }
        
        # Add auth data if provided
        if auth_data:
            method_call["auth"] = auth_data
        
        debug_log(f"Method call (before encryption): {method_call}")
        
        # Serialize method call
        try:
            method_call_bytes = json.dumps(method_call).encode('utf-8')
            debug_log(f"Serialized method call: {len(method_call_bytes)} bytes")
        except Exception as e:
            debug_log(f"Failed to serialize method call: {e}")
            raise OpenADPError(
                ErrorCode.INVALID_REQUEST,
                f"failed to serialize method call: {str(e)}"
            )
        
        # Step 7: Encrypt the method call
        try:
            encrypted_call = noise_client.encrypt(method_call_bytes)
            debug_log(f"Encrypted method call: {len(encrypted_call)} bytes")
        except Exception as e:
            debug_log(f"Failed to encrypt method call: {e}")
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                f"failed to encrypt method call: {str(e)}"
            )
        
        # Step 8: Send encrypted call to server
        encrypted_request = JSONRPCRequest(
            "encrypted_call",
            [{
                "session": session_id,
                "data": base64.b64encode(encrypted_call).decode('ascii')
            }],
            self.request_id + 1  # Different ID for second round
        )
        
        debug_log(f"Sending encrypted call (ID: {self.request_id + 1})")
        debug_log(f"📤 PYTHON: Encrypted call JSON request: {json.dumps(encrypted_request.to_dict(), indent=2)}")
        
        try:
            response2 = self.session.post(
                self.url,
                json=encrypted_request.to_dict(),
                timeout=self.timeout
            )
            response2.raise_for_status()
        except requests.RequestException as e:
            debug_log(f"Failed to send encrypted request: {e}")
            raise OpenADPError(
                ErrorCode.NETWORK_FAILURE,
                f"failed to send encrypted request: {str(e)}"
            )
        
        try:
            encrypted_resp_data = response2.json()
            debug_log(f"📥 PYTHON: Encrypted call JSON response: {json.dumps(encrypted_resp_data, indent=2)}")
        except json.JSONDecodeError as e:
            debug_log(f"Failed to parse encrypted response: {e}")
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"failed to parse encrypted response: {str(e)}"
            )
        
        encrypted_response = JSONRPCResponse.from_dict(encrypted_resp_data)
        
        if encrypted_response.error:
            debug_log(f"Encrypted JSON-RPC error: {encrypted_response.error.code} - {encrypted_response.error.message}")
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                f"encrypted JSON-RPC error {encrypted_response.error.code}: {encrypted_response.error.message}"
            )
        
        # Step 9: Decrypt the response
        if not isinstance(encrypted_response.result, dict):
            debug_log("Invalid encrypted response format")
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                "invalid encrypted response format"
            )
        
        encrypted_data_b64 = encrypted_response.result.get("data")
        if not encrypted_data_b64:
            debug_log("Encrypted response missing data field")
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                "encrypted response missing data field"
            )
        
        try:
            encrypted_data = base64.b64decode(encrypted_data_b64)
            debug_log(f"Encrypted data to decrypt: {len(encrypted_data)} bytes")
        except Exception as e:
            debug_log(f"Failed to decode encrypted data: {e}")
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"failed to decode encrypted data: {str(e)}"
            )
        
        try:
            decrypted_data = noise_client.decrypt(encrypted_data)
            debug_log(f"Decrypted data: {len(decrypted_data)} bytes")
        except Exception as e:
            debug_log(f"Failed to decrypt response: {e}")
            raise OpenADPError(
                ErrorCode.ENCRYPTION_FAILED,
                f"failed to decrypt response: {str(e)}"
            )
        
        # Parse decrypted JSON-RPC response
        try:
            decrypted_response_data = json.loads(decrypted_data.decode('utf-8'))
            debug_log(f"Decrypted response (after encryption): {decrypted_response_data}")
        except Exception as e:
            debug_log(f"Failed to parse decrypted response: {e}")
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"failed to parse decrypted response: {str(e)}"
            )
        
        decrypted_response = JSONRPCResponse.from_dict(decrypted_response_data)
        
        if decrypted_response.error:
            debug_log(f"Decrypted JSON-RPC error: {decrypted_response.error.code} - {decrypted_response.error.message}")
            raise OpenADPError(
                ErrorCode.SERVER_ERROR,
                f"decrypted JSON-RPC error {decrypted_response.error.code}: {decrypted_response.error.message}"
            )
        
        debug_log(f"Encrypted request successful, result: {decrypted_response.result}")
        return decrypted_response.result
    
    # Core API methods matching Go implementation
    def register_secret(self, auth_code: str, uid: str, did: str, bid: str, 
                       version: int, x: int, y: str, max_guesses: int, 
                       expiration: int, encrypted: bool = True, 
                       auth_data: Optional[Dict[str, Any]] = None) -> bool:
        """Register a secret share with the server."""
        # Server expects: [auth_code, uid, did, bid, version, x, y, max_guesses, expiration] (9 parameters)
        params = [auth_code, uid, did, bid, version, x, y, max_guesses, expiration]
        
        result = self._make_request("RegisterSecret", params, encrypted, auth_data)
        
        if not isinstance(result, bool):
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"Expected bool response, got {type(result)}"
            )
        
        return result
    
    def recover_secret(self, auth_code: str, uid: str, did: str, bid: str, 
                      b: str, guess_num: int, encrypted: bool = True,
                      auth_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Recover a secret share from the server."""
        # Server expects: [auth_code, uid, did, bid, b, guess_num] (6 parameters)
        params = [auth_code, uid, did, bid, b, guess_num]
        
        result = self._make_request("RecoverSecret", params, encrypted, auth_data)
        
        if not isinstance(result, dict):
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"Expected dict response, got {type(result)}"
            )
        
        return result
    
    def list_backups(self, uid: str, encrypted: bool = False,
                    auth_data: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """List all backups for a user."""
        # Server expects: [uid] (1 parameter)
        params = [uid]
        
        result = self._make_request("ListBackups", params, encrypted, auth_data)
        
        if not isinstance(result, list):
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"Expected list response, got {type(result)}"
            )
        
        return result
    
    def echo(self, message: str, encrypted: bool = False) -> str:
        """Send an echo message with optional encryption."""
        params = [message]
        
        result = self._make_request("Echo", params, encrypted, None)
        
        if not isinstance(result, str):
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"Expected string response, got {type(result)}"
            )
        
        return result
    
    def ping(self) -> None:
        """Test connectivity to the server (alias for echo with 'ping' message)."""
        self.echo("ping", False)
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server information."""
        result = self._make_request("GetServerInfo", None, False, None)
        
        if not isinstance(result, dict):
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"Expected dict response, got {type(result)}"
            )
        
        return result
    
    # Standardized interface implementation
    def register_secret_standardized(self, request: RegisterSecretRequest) -> RegisterSecretResponse:
        """Register secret using standardized interface."""
        success = self.register_secret(
            request.auth_code, request.uid, request.did, request.bid,
            request.version, request.x, request.y,
            request.max_guesses, request.expiration,
            request.encrypted, request.auth_data
        )
        
        return RegisterSecretResponse(success=success, message="")
    
    def recover_secret_standardized(self, request: RecoverSecretRequest) -> RecoverSecretResponse:
        """Recover secret using standardized interface."""
        result = self.recover_secret(
            request.auth_code, request.uid, request.did, request.bid,
            request.b, request.guess_num,
            request.encrypted, request.auth_data
        )
        
        return RecoverSecretResponse(
            version=result.get("version", 0),
            x=result.get("x", 0),
            si_b=result.get("si_b", ""),
            num_guesses=result.get("num_guesses", 0),
            max_guesses=result.get("max_guesses", 0),
            expiration=result.get("expiration", 0)
        )
    
    def list_backups_standardized(self, request: ListBackupsRequest) -> ListBackupsResponse:
        """List backups using standardized interface."""
        backups_data = self.list_backups(request.uid, request.encrypted, request.auth_data)
        
        backups = []
        for backup_data in backups_data:
            backup = BackupInfo(
                uid=backup_data.get("uid", ""),
                bid=backup_data.get("bid", ""),
                version=backup_data.get("version", 0),
                num_guesses=backup_data.get("num_guesses", 0),
                max_guesses=backup_data.get("max_guesses", 0),
                expiration=backup_data.get("expiration", 0)
            )
            backups.append(backup)
        
        return ListBackupsResponse(backups=backups)
    
    def get_server_info_standardized(self) -> ServerInfoResponse:
        """Get server info using standardized interface."""
        info = self.get_server_info()
        
        methods = ["RegisterSecret", "RecoverSecret", "ListBackups", "Echo", "GetServerInfo"]
        noise_key = info.get("noise_nk_public_key", "")
        if noise_key:
            methods.extend(["noise_handshake", "encrypted_call"])
        
        return ServerInfoResponse(
            server_version=info.get("version", ""),
            noise_nk_public_key=noise_key,
            supported_methods=methods,
            max_request_size=1024 * 1024,  # 1MB default
            rate_limits={}
        )
    
    def test_connection(self) -> None:
        """Test connection to server."""
        self.ping()
    
    def get_server_url(self) -> str:
        """Get server URL."""
        return self.url
    
    def supports_encryption(self) -> bool:
        """Return true if client supports encryption."""
        return self.has_public_key()

# Server discovery functionality (matching scrape.go)

@dataclass
class ServersResponse:
    """JSON response from server registry."""
    servers: List[ServerInfo]

def get_servers(registry_url: str = "") -> List[ServerInfo]:
    """Fetch server information from the OpenADP registry."""
    if not registry_url:
        registry_url = "https://servers.openadp.org/api/servers.json"
    
    if registry_url.startswith("file://"):
        # For file URLs, read the file directly
        file_path = registry_url[7:]  # Remove "file://"
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            raise OpenADPError(
                ErrorCode.NETWORK_FAILURE,
                f"failed to read file {file_path}: {str(e)}"
            )
    else:
        # For HTTP URLs, use the URL as-is (like Go and C++ SDKs)
        # Only append /api/servers.json if the URL ends with a domain/base path
        if registry_url.endswith('.json') or '/servers' in registry_url:
            # URL already specifies a file or specific endpoint, use as-is
            api_url = registry_url
        else:
            # URL appears to be a base domain, append the standard API endpoint
            api_url = registry_url.rstrip('/') + "/api/servers.json"
        
        try:
            response = requests.get(
                api_url,
                headers={
                    'User-Agent': 'OpenADP-Client/1.0',
                    'Accept': 'application/json'
                },
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            raise OpenADPError(
                ErrorCode.NETWORK_FAILURE,
                f"failed to fetch servers from {api_url}: {str(e)}"
            )
        except json.JSONDecodeError as e:
            raise OpenADPError(
                ErrorCode.INVALID_RESPONSE,
                f"failed to parse JSON response: {str(e)}"
            )
    
    if "servers" not in data or not isinstance(data["servers"], list):
        raise OpenADPError(
            ErrorCode.INVALID_RESPONSE,
            "no servers found in registry response"
        )
    
    servers = []
    for server_data in data["servers"]:
        server = ServerInfo(
            url=server_data.get("url", ""),
            public_key=server_data.get("public_key", ""),
            country=server_data.get("country", ""),
            remaining_guesses=server_data.get("remaining_guesses", -1)
        )
        servers.append(server)
    
    if not servers:
        raise OpenADPError(
            ErrorCode.INVALID_RESPONSE,
            "no servers found in registry response"
        )
    
    return servers

def get_server_urls(registry_url: str = "") -> List[str]:
    """Get just the server URLs (for backward compatibility)."""
    servers = get_servers(registry_url)
    return [server.url for server in servers]

def scrape_server_urls(registry_url: str = "") -> List[str]:
    """Alias for get_server_urls for backward compatibility."""
    return get_server_urls(registry_url)

def get_servers_by_country(registry_url: str = "") -> Dict[str, List[ServerInfo]]:
    """Group servers by country."""
    servers = get_servers(registry_url)
    
    by_country = {}
    for server in servers:
        country = server.country or "Unknown"
        if country not in by_country:
            by_country[country] = []
        by_country[country].append(server)
    
    return by_country

def get_fallback_servers() -> List[str]:
    """Return a list of hardcoded fallback servers."""
    return [
        "https://xyzzy.openadp.org",
        "https://sky.openadp.org", 
        "https://akash.network"
    ]

def get_fallback_server_info() -> List[ServerInfo]:
    """Return detailed fallback server information."""
    return [
        ServerInfo(
            url="https://xyzzy.openadp.org",
            public_key="ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder1XyzzyServer12345TestKey",
            country="US",
            remaining_guesses=0
        ),
        ServerInfo(
            url="https://sky.openadp.org",
            public_key="ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder2SkyServerTestKey67890Demo",
            country="US",
            remaining_guesses=0
        ),
        ServerInfo(
            url="https://akash.network",
            public_key="ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder3AkashNetworkTestKey111Demo",
            country="CA",
            remaining_guesses=0
        )
    ]

def convert_urls_to_server_info(urls: List[str]) -> List[ServerInfo]:
    """Convert a list of URLs to ServerInfo structs (for backward compatibility)."""
    return [
        ServerInfo(url=url, public_key="", country="Unknown", remaining_guesses=-1)
        for url in urls
    ]

def discover_servers(registry_url: str = "") -> List[ServerInfo]:
    """Attempt to discover servers from registry with fallback."""
    try:
        servers = get_servers(registry_url)
        if servers:
            return servers
    except OpenADPError:
        pass
    
    # Fall back to hardcoded servers
    return get_fallback_server_info()

def discover_server_urls(registry_url: str = "") -> List[str]:
    """Attempt to discover server URLs from registry with fallback."""
    servers = discover_servers(registry_url)
    return [server.url for server in servers]

class MultiServerClient:
    """
    High-level multi-server client for OpenADP operations.
    
    This client manages multiple OpenADP servers with automatic failover,
    matching the Go Client implementation exactly.
    """
    
    def __init__(self, servers_url: str = "", fallback_servers: Optional[List[str]] = None,
                 echo_timeout: int = 10, max_workers: int = 10):
        self.servers_url = servers_url
        self.fallback_servers = fallback_servers or get_fallback_servers()
        self.echo_timeout = echo_timeout
        self.max_workers = max_workers
        self.live_servers: List[EncryptedOpenADPClient] = []
        self.selection_strategy = ServerSelectionStrategy.FIRST_AVAILABLE
        self._lock = threading.RLock()
        
        # Initialize servers
        self._initialize_servers()
    
    @classmethod
    def from_server_info(cls, server_infos: List[ServerInfo], echo_timeout: int = 10, 
                        max_workers: int = 10) -> 'MultiServerClient':
        """Create client with predefined server information."""
        client = cls.__new__(cls)
        client.servers_url = ""
        client.fallback_servers = []
        client.echo_timeout = echo_timeout
        client.max_workers = max_workers
        client.live_servers = []
        client.selection_strategy = ServerSelectionStrategy.FIRST_AVAILABLE
        client._lock = threading.RLock()
        
        # Test servers directly with provided ServerInfo
        client.live_servers = client._test_servers_concurrently(server_infos)
        
        client._log_server_status()
        
        return client
    
    def _initialize_servers(self):
        """Scrape server list and test each server for liveness."""
        if self.servers_url:
            try:
                server_infos = get_servers(self.servers_url)
            except OpenADPError as e:
                server_infos = []
        else:
            server_infos = []
        
        # Add fallback servers if needed
        if not server_infos:
            server_infos = convert_urls_to_server_info(self.fallback_servers)
        
        # Test servers concurrently
        self.live_servers = self._test_servers_concurrently(server_infos)
        
        self._log_server_status()
    
    def _test_servers_concurrently(self, server_infos: List[ServerInfo]) -> List[EncryptedOpenADPClient]:
        """Test servers concurrently for liveness."""
        def test_server(server_info: ServerInfo) -> Optional[EncryptedOpenADPClient]:
            return self._test_single_server_with_info(server_info)
        
        live_servers = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_server = {
                executor.submit(test_server, server_info): server_info
                for server_info in server_infos
            }
            
            for future in as_completed(future_to_server):
                client = future.result()
                if client:
                    live_servers.append(client)
        
        return live_servers
    
    def _test_single_server_with_info(self, server_info: ServerInfo) -> Optional[EncryptedOpenADPClient]:
        """Test a single server for liveness using ServerInfo with public key."""
        
        public_key = None
        if server_info.public_key:
            try:
                public_key = self._parse_public_key(server_info.public_key)
            except Exception as e:
                public_key = None
        
        # Create encrypted client with public key from servers.json (secure)
        client = EncryptedOpenADPClient(server_info.url, public_key, self.echo_timeout)
        
        # Test with echo - use a simple test message
        test_message = f"liveness_test_{int(time.time())}"
        try:
            result = client.echo(test_message, False)
            
            if result != test_message:
                return None
            
            # Check encryption status
            encryption_status = "encrypted" if client.has_public_key() else "unencrypted"
            
            return client
            
        except Exception as e:
            return None
    
    def _parse_public_key(self, public_key: str) -> bytes:
        """Parse a public key in various formats."""
        if public_key.startswith("ed25519:"):
            # Remove ed25519: prefix and decode
            key_b64 = public_key[8:]
            return base64.b64decode(key_b64)
        
        # Assume it's already base64
        return base64.b64decode(public_key)
    
    def _log_server_status(self):
        """Log current server status."""
        with self._lock:
            if self.live_servers:
                for client in self.live_servers:
                    encryption_status = "encrypted" if client.has_public_key() else "unencrypted"
            else:
                pass  # No live servers to log
    
    def get_live_server_count(self) -> int:
        """Return the number of currently live servers."""
        with self._lock:
            return len(self.live_servers)
    
    def get_live_server_urls(self) -> List[str]:
        """Return URLs of all currently live servers."""
        with self._lock:
            return [client.url for client in self.live_servers]
    
    def refresh_servers(self) -> None:
        """Re-scrape and re-test all servers to refresh the live server list."""
        with self._lock:
            self._initialize_servers()
    
    def register_secret(self, uid: str, did: str, bid: str, version: int, 
                       x: int, y: bytes, max_guesses: int, expiration: int,
                       auth_data: Optional[Dict[str, Any]] = None) -> bool:
        """Register a secret across multiple servers with failover."""
        with self._lock:
            live_servers = self.live_servers.copy()
        
        if not live_servers:
            raise OpenADPError(
                ErrorCode.NO_LIVE_SERVERS,
                "No live servers available"
            )
        
        # Convert y bytes to base64 string for JSON-RPC (server expects base64)
        y_str = base64.b64encode(y).decode('ascii')
        
        # Try each server until one succeeds
        last_error = None
        for client in live_servers:
            try:
                success = client.register_secret(
                    "", uid, did, bid, version, x, y_str, max_guesses, expiration, True, auth_data
                )
                if success:
                    return True
            except Exception as e:
                last_error = e
        
        raise OpenADPError(
            ErrorCode.SERVER_ERROR,
            f"all servers failed, last error: {str(last_error)}"
        )
    
    def recover_secret(self, auth_code: str, uid: str, did: str, bid: str, 
                      b: str, guess_num: int,
                      auth_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Recover a secret from servers with failover."""
        with self._lock:
            live_servers = self.live_servers.copy()
        
        if not live_servers:
            raise OpenADPError(
                ErrorCode.NO_LIVE_SERVERS,
                "No live servers available"
            )
        
        # Try each server until one succeeds
        last_error = None
        for client in live_servers:
            try:
                result = client.recover_secret(auth_code, uid, did, bid, b, guess_num, True, auth_data)
                return result
            except Exception as e:
                last_error = e
        
        raise OpenADPError(
            ErrorCode.SERVER_ERROR,
            f"all servers failed, last error: {str(last_error)}"
        )
    
    def list_backups(self, uid: str) -> List[Dict[str, Any]]:
        """List backups for a user from the first available server."""
        with self._lock:
            live_servers = self.live_servers.copy()
        
        if not live_servers:
            raise OpenADPError(
                ErrorCode.NO_LIVE_SERVERS,
                "No live servers available"
            )
        
        # Try each server until one succeeds
        last_error = None
        for client in live_servers:
            try:
                result = client.list_backups(uid, False, None)
                return result
            except Exception as e:
                last_error = e
        
        raise OpenADPError(
            ErrorCode.SERVER_ERROR,
            f"all servers failed, last error: {str(last_error)}"
        )
    
    def echo(self, message: str) -> str:
        """Send an echo message to test connectivity."""
        with self._lock:
            live_servers = self.live_servers.copy()
        
        if not live_servers:
            raise OpenADPError(
                ErrorCode.NO_LIVE_SERVERS,
                "No live servers available"
            )
        
        # Try the first server
        return live_servers[0].echo(message, False)
    
    def ping(self) -> None:
        """Test connectivity to servers."""
        self.echo("ping")
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get information from the first available server."""
        with self._lock:
            live_servers = self.live_servers.copy()
        
        if not live_servers:
            raise OpenADPError(
                ErrorCode.NO_LIVE_SERVERS,
                "No live servers available"
            )
        
        return live_servers[0].get_server_info()
    
    # Standardized interface implementation
    def register_secret_standardized(self, request: RegisterSecretRequest) -> RegisterSecretResponse:
        """Register secret using standardized interface."""
        # Convert Y from base64 string to bytes for legacy method
        try:
            y_bytes = base64.b64decode(request.y)
        except Exception as e:
            raise OpenADPError(
                ErrorCode.INVALID_REQUEST,
                f"invalid Y coordinate: {str(e)}"
            )
        
        success = self.register_secret(
            request.uid, request.did, request.bid,
            request.version, request.x, y_bytes,
            request.max_guesses, request.expiration,
            request.auth_data
        )
        
        return RegisterSecretResponse(success=success, message="")
    
    def recover_secret_standardized(self, request: RecoverSecretRequest) -> RecoverSecretResponse:
        """Recover secret using standardized interface."""
        result = self.recover_secret(
            request.auth_code, request.uid, request.did, request.bid,
            request.b, request.guess_num, request.auth_data
        )
        
        return RecoverSecretResponse(
            version=result.get("version", 0),
            x=result.get("x", 0),
            si_b=result.get("si_b", ""),
            num_guesses=result.get("num_guesses", 0),
            max_guesses=result.get("max_guesses", 0),
            expiration=result.get("expiration", 0)
        )
    
    def list_backups_standardized(self, request: ListBackupsRequest) -> ListBackupsResponse:
        """List backups using standardized interface."""
        backups_data = self.list_backups(request.uid)
        
        backups = []
        for backup_data in backups_data:
            backup = BackupInfo(
                uid=backup_data.get("uid", ""),
                bid=backup_data.get("bid", ""),
                version=backup_data.get("version", 0),
                num_guesses=backup_data.get("num_guesses", 0),
                max_guesses=backup_data.get("max_guesses", 0),
                expiration=backup_data.get("expiration", 0)
            )
            backups.append(backup)
        
        return ListBackupsResponse(backups=backups)
    
    def get_server_info_standardized(self) -> ServerInfoResponse:
        """Get server info using standardized interface."""
        info = self.get_server_info()
        
        methods = ["RegisterSecret", "RecoverSecret", "ListBackups", "Echo", "GetServerInfo"]
        noise_key = info.get("noise_nk_public_key", "")
        if noise_key:
            methods.extend(["noise_handshake", "encrypted_call"])
        
        return ServerInfoResponse(
            server_version=info.get("version", ""),
            noise_nk_public_key=noise_key,
            supported_methods=methods,
            max_request_size=1024 * 1024,  # 1MB default
            rate_limits={}
        )
    
    def test_connection(self) -> None:
        """Test connection to servers."""
        self.ping()
    
    def get_server_url(self) -> str:
        """Get first server URL."""
        with self._lock:
            if self.live_servers:
                return self.live_servers[0].url
            return ""
    
    def supports_encryption(self) -> bool:
        """Return true if any live server supports encryption."""
        with self._lock:
            for server in self.live_servers:
                if server.supports_encryption():
                    return True
            return False
    
    def set_server_selection_strategy(self, strategy: ServerSelectionStrategy) -> None:
        """Set server selection strategy."""
        with self._lock:
            self.selection_strategy = strategy 
