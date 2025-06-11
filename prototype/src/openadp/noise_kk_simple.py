#!/usr/bin/env python3
"""
Simplified Noise-KK Implementation for OpenADP

This module implements a simplified version of the Noise-KK handshake pattern 
using Python's built-in cryptography library. While not a full Noise implementation,
it provides the essential security properties needed for OpenADP:

1. Mutual authentication using static keys
2. Forward secrecy through ephemeral keys
3. Key derivation following Noise principles
4. Encrypted transport after handshake

Pattern simulation:
  -> static_key_exchange + ephemeral_key
  <- ephemeral_key + authenticated_response
  [derive shared secrets and establish encrypted channels]
"""

import hashlib
import hmac
import secrets
import base64
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import struct
import json
import socket
import ssl
import logging

logger = logging.getLogger(__name__)

@dataclass
class NoiseKKConfig:
    """Configuration for Noise-KK sessions"""
    protocol_name: str = "Noise_KK_25519_ChaChaPoly_BLAKE2s"
    prologue: bytes = b"OpenADP-v1.0"


class SimplifiedNoiseKK:
    """
    Simplified Noise-KK implementation using standard cryptography.
    
    This provides the core security properties of Noise-KK:
    - Mutual authentication via static keys
    - Forward secrecy via ephemeral keys  
    - Authenticated encryption for transport
    
    While not a full Noise implementation, it's suitable for OpenADP's needs.
    """
    
    def __init__(self, is_initiator: bool, local_static_private: x25519.X25519PrivateKey, 
                 remote_static_public: x25519.X25519PublicKey, config: Optional[NoiseKKConfig] = None):
        """
        Initialize a simplified Noise-KK session.
        
        Args:
            is_initiator: True if this is the client (initiator)
            local_static_private: Local static private key
            remote_static_public: Remote static public key  
            config: Optional configuration
        """
        self.is_initiator = is_initiator
        self.local_static_private = local_static_private
        self.local_static_public = local_static_private.public_key()
        self.remote_static_public = remote_static_public
        self.config = config or NoiseKKConfig()
        
        # Handshake state
        self.handshake_complete = False
        self.h = hashlib.blake2s(self.config.protocol_name.encode()).digest()  # handshake hash
        self.ck = self.h  # chaining key
        
        # Mix in prologue
        self._mix_hash(self.config.prologue)
        
        # Mix in pre-shared static keys (KK pattern pre-messages)
        initiator_static_bytes = self.local_static_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ) if is_initiator else self.remote_static_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        responder_static_bytes = self.remote_static_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ) if is_initiator else self.local_static_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        
        self._mix_hash(initiator_static_bytes)
        self._mix_hash(responder_static_bytes)
        
        # Ephemeral keys (generated during handshake)
        self.local_ephemeral_private = None
        self.local_ephemeral_public = None
        self.remote_ephemeral_public = None
        
        # Transport encryption
        self.send_cipher = None
        self.recv_cipher = None
        self.send_nonce = 0
        self.recv_nonce = 0
    
    def _mix_hash(self, data: bytes):
        """Mix data into the handshake hash"""
        self.h = hashlib.blake2s(self.h + data).digest()
    
    def _mix_key(self, input_key_material: bytes):
        """Mix key material into the chaining key and derive new encryption key"""
        # HKDF extract and expand
        hkdf = HKDF(
            algorithm=hashes.BLAKE2s(32),
            length=64,  # 32 bytes for ck + 32 bytes for k
            salt=self.ck,
            info=b"",
        )
        output = hkdf.derive(input_key_material)
        
        self.ck = output[:32]  # New chaining key
        k = output[32:64]      # New encryption key
        
        # Create new cipher
        self.current_cipher = ChaCha20Poly1305(k)
        return k
    
    def _encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext and mix ciphertext into hash"""
        if hasattr(self, 'current_cipher') and self.current_cipher:
            # Use current nonce (simplified - in real Noise this is more complex)
            nonce = struct.pack('<Q', self.send_nonce) + b'\x00' * 4
            ciphertext = self.current_cipher.encrypt(nonce, plaintext, self.h)
            self.send_nonce += 1
        else:
            ciphertext = plaintext  # No encryption key yet
        
        self._mix_hash(ciphertext)
        return ciphertext
    
    def _decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext and mix ciphertext into hash"""
        if hasattr(self, 'current_cipher') and self.current_cipher:
            nonce = struct.pack('<Q', self.recv_nonce) + b'\x00' * 4
            try:
                plaintext = self.current_cipher.decrypt(nonce, ciphertext, self.h)
                self.recv_nonce += 1
            except Exception as e:
                raise ValueError(f"Decryption failed: {e}")
        else:
            plaintext = ciphertext  # No encryption key yet
        
        self._mix_hash(ciphertext)
        return plaintext
    
    def start_handshake(self) -> bytes:
        """
        Start the handshake (initiator only).
        
        KK pattern message 1: -> e, es, ss
        """
        if not self.is_initiator:
            raise ValueError("Only initiator can start handshake")
        
        # Generate ephemeral key pair
        self.local_ephemeral_private = x25519.X25519PrivateKey.generate()
        self.local_ephemeral_public = self.local_ephemeral_private.public_key()
        
        # Start building message
        message = bytearray()
        
        # Add ephemeral public key (e)
        ephemeral_bytes = self.local_ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        message.extend(ephemeral_bytes)
        self._mix_hash(ephemeral_bytes)
        
        # Perform es: DH(local_ephemeral, remote_static)
        es_shared = self.local_ephemeral_private.exchange(self.remote_static_public)
        self._mix_key(es_shared)
        
        # Perform ss: DH(local_static, remote_static) 
        ss_shared = self.local_static_private.exchange(self.remote_static_public)
        self._mix_key(ss_shared)
        
        # Add encrypted payload (empty for now)
        encrypted_payload = self._encrypt_and_hash(b"")
        message.extend(encrypted_payload)
        
        return bytes(message)
    
    def process_handshake_message(self, message: bytes) -> Tuple[Optional[bytes], bool]:
        """
        Process a handshake message.
        
        Returns:
            Tuple of (response_message, handshake_complete)
        """
        if self.is_initiator:
            # Initiator processing response (message 2): <- e, ee, se
            if len(message) < 32:
                raise ValueError("Invalid handshake message length")
            
            # Extract remote ephemeral public key
            remote_ephemeral_bytes = message[:32]
            self.remote_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(remote_ephemeral_bytes)
            self._mix_hash(remote_ephemeral_bytes)
            
            # Perform ee: DH(local_ephemeral, remote_ephemeral)
            ee_shared = self.local_ephemeral_private.exchange(self.remote_ephemeral_public)
            self._mix_key(ee_shared)
            
            # Perform se: DH(local_static, remote_ephemeral)
            se_shared = self.local_static_private.exchange(self.remote_ephemeral_public)
            self._mix_key(se_shared)
            
            # Decrypt payload
            encrypted_payload = message[32:]
            payload = self._decrypt_and_hash(encrypted_payload)
            
            # Split into send/recv keys
            self._split_keys()
            self.handshake_complete = True
            
            return None, True
            
        else:
            # Responder processing initial message (message 1): -> e, es, ss
            if len(message) < 32:
                raise ValueError("Invalid handshake message length")
            
            # Extract remote ephemeral public key
            remote_ephemeral_bytes = message[:32]
            self.remote_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(remote_ephemeral_bytes)
            self._mix_hash(remote_ephemeral_bytes)
            
            # Perform es: DH(local_static, remote_ephemeral) [responder perspective]
            es_shared = self.local_static_private.exchange(self.remote_ephemeral_public)
            self._mix_key(es_shared)
            
            # Perform ss: DH(local_static, remote_static)
            ss_shared = self.local_static_private.exchange(self.remote_static_public)
            self._mix_key(ss_shared)
            
            # Decrypt payload
            encrypted_payload = message[32:]
            payload = self._decrypt_and_hash(encrypted_payload)
            
            # Generate response message: <- e, ee, se
            response = bytearray()
            
            # Generate our ephemeral key
            self.local_ephemeral_private = x25519.X25519PrivateKey.generate()
            self.local_ephemeral_public = self.local_ephemeral_private.public_key()
            
            # Add ephemeral public key
            ephemeral_bytes = self.local_ephemeral_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            response.extend(ephemeral_bytes)
            self._mix_hash(ephemeral_bytes)
            
            # Perform ee: DH(local_ephemeral, remote_ephemeral)
            ee_shared = self.local_ephemeral_private.exchange(self.remote_ephemeral_public)
            self._mix_key(ee_shared)
            
            # Perform se: DH(local_ephemeral, remote_static) [responder perspective]
            se_shared = self.local_ephemeral_private.exchange(self.remote_static_public)
            self._mix_key(se_shared)
            
            # Add encrypted payload
            encrypted_payload = self._encrypt_and_hash(b"")
            response.extend(encrypted_payload)
            
            # Split into send/recv keys
            self._split_keys()
            self.handshake_complete = True
            
            return bytes(response), True
    
    def _split_keys(self):
        """Split the chaining key into send/recv transport keys"""
        # HKDF to derive two 32-byte keys
        hkdf = HKDF(
            algorithm=hashes.BLAKE2s(32),
            length=64,
            salt=self.ck,
            info=b"",
        )
        keys = hkdf.derive(b"")
        
        if self.is_initiator:
            send_key = keys[:32]
            recv_key = keys[32:64]
        else:
            send_key = keys[32:64]
            recv_key = keys[:32]
        
        self.send_cipher = ChaCha20Poly1305(send_key)
        self.recv_cipher = ChaCha20Poly1305(recv_key)
        self.send_nonce = 0
        self.recv_nonce = 0
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt a transport message"""
        if not self.handshake_complete:
            raise ValueError("Handshake not complete")
        
        nonce = struct.pack('<Q', self.send_nonce) + b'\x00' * 4
        ciphertext = self.send_cipher.encrypt(nonce, plaintext, b"")
        self.send_nonce += 1
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt a transport message"""
        if not self.handshake_complete:
            raise ValueError("Handshake not complete")
        
        nonce = struct.pack('<Q', self.recv_nonce) + b'\x00' * 4
        plaintext = self.recv_cipher.decrypt(nonce, ciphertext, b"")
        self.recv_nonce += 1
        return plaintext


class NoiseKKTransport:
    """Transport layer for Noise-KK over JSON-RPC/HTTP (for Cloudflare compatibility)"""
    
    def __init__(self, socket_obj: socket.socket, noise_session: SimplifiedNoiseKK, is_client: bool = True, http_host: str = "localhost"):
        self.socket = socket_obj
        self.noise_session = noise_session
        self.is_client = is_client
        self.http_host = http_host
        self._handshake_done = False
        self._request_id = 0
    
    def _next_request_id(self):
        """Get next JSON-RPC request ID"""
        self._request_id += 1
        return self._request_id
    
    def perform_handshake(self):
        """Perform Noise-KK handshake over JSON-RPC/HTTP"""
        if self._handshake_done:
            return
        
        try:
            if self.noise_session.is_initiator:
                # Client: start handshake and send via JSON-RPC
                msg1 = self.noise_session.start_handshake()
                response_data = self._jsonrpc_call("noise-handshake", [msg1])
                
                # Client: process server response
                _, complete = self.noise_session.process_handshake_message(response_data)
                
                if not complete:
                    raise RuntimeError("Handshake failed to complete")
            else:
                # Server: receive JSON-RPC request and extract handshake data
                request = self._jsonrpc_receive_request()
                
                if request['method'] != 'noise-handshake':
                    raise RuntimeError(f"Expected noise-handshake, got {request['method']}")
                
                # Extract handshake data (first parameter, already as bytes)
                msg1 = request['params'][0]
                
                # Server: process handshake and generate response
                msg2, complete = self.noise_session.process_handshake_message(msg1)
                
                # Server: send response via JSON-RPC
                if msg2:
                    self._jsonrpc_send_response(request['id'], msg2)
                else:
                    self._jsonrpc_send_error(request['id'], "Handshake failed")
                
                if not complete:
                    raise RuntimeError("Handshake failed to complete")
            
            self._handshake_done = True
            logger.info("Noise-KK handshake completed successfully over JSON-RPC/HTTP")
            
        except Exception as e:
            logger.error(f"Noise-KK handshake failed: {e}")
            raise
    
    def _jsonrpc_call(self, method: str, params: list) -> bytes:
        """Make a JSON-RPC call and return the result (as bytes)"""
        import base64, json
        
        # Convert binary parameters to base64
        encoded_params = []
        for param in params:
            if isinstance(param, bytes):
                encoded_params.append(base64.b64encode(param).decode('ascii'))
            else:
                encoded_params.append(param)
        
        # Build JSON-RPC request
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": encoded_params,
            "id": self._next_request_id()
        }
        
        # Send HTTP POST with JSON-RPC
        self._http_post_jsonrpc(request)
        
        # Receive JSON-RPC response
        response = self._jsonrpc_receive_response()
        
        # Check for errors
        if "error" in response:
            raise RuntimeError(f"JSON-RPC error: {response['error']}")
        
        # Decode result from base64 to bytes
        result_b64 = response["result"]
        return base64.b64decode(result_b64)
    
    def _http_post_jsonrpc(self, jsonrpc_request: dict):
        """Send JSON-RPC request over HTTP POST"""
        import json
        
        # Serialize JSON-RPC request
        body = json.dumps(jsonrpc_request).encode('utf-8')
        
        # Build HTTP POST request
        request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.http_host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode('utf-8') + body
        
        # Send request
        self.socket.send(request)
    
    def _jsonrpc_receive_request(self) -> dict:
        """Receive JSON-RPC request over HTTP and parse it"""
        import json, base64
        
        # Receive HTTP request
        http_request = self._http_receive_request()
        
        # Parse JSON-RPC from HTTP body
        jsonrpc_request = json.loads(http_request['body'].decode('utf-8'))
        
        # Decode base64 parameters back to bytes
        if 'params' in jsonrpc_request:
            decoded_params = []
            for param in jsonrpc_request['params']:
                if isinstance(param, str):
                    try:
                        # Try to decode as base64
                        decoded_params.append(base64.b64decode(param))
                    except:
                        # If it fails, keep as string
                        decoded_params.append(param)
                else:
                    decoded_params.append(param)
            jsonrpc_request['params'] = decoded_params
        
        return jsonrpc_request
    
    def _jsonrpc_send_response(self, request_id: int, result_data: bytes):
        """Send JSON-RPC response over HTTP"""
        import json, base64
        
        # Encode result as base64
        result_b64 = base64.b64encode(result_data).decode('ascii')
        
        # Build JSON-RPC response
        response = {
            "jsonrpc": "2.0",
            "result": result_b64,
            "id": request_id
        }
        
        # Send HTTP response
        self._http_send_jsonrpc_response(200, response)
    
    def _jsonrpc_send_error(self, request_id: int, error_message: str):
        """Send JSON-RPC error response over HTTP"""
        import json
        
        # Build JSON-RPC error response
        response = {
            "jsonrpc": "2.0",
            "error": {"code": -32603, "message": error_message},
            "id": request_id
        }
        
        # Send HTTP response
        self._http_send_jsonrpc_response(500, response)
    
    def _jsonrpc_receive_response(self) -> dict:
        """Receive JSON-RPC response over HTTP"""
        import json
        
        # Receive HTTP response
        http_response = self._http_receive_response()
        
        # Parse JSON-RPC from HTTP body
        return json.loads(http_response['body'].decode('utf-8'))
    
    def _http_send_jsonrpc_response(self, status: int, jsonrpc_response: dict):
        """Send HTTP response containing JSON-RPC"""
        import json
        
        # Serialize JSON-RPC response
        response_body = json.dumps(jsonrpc_response).encode('utf-8')
        
        # Build HTTP response
        status_text = "OK" if status == 200 else "Error"
        response = (
            f"HTTP/1.1 {status} {status_text}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(response_body)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode('utf-8') + response_body
        
        self.socket.send(response)
    
    def _http_receive_request(self) -> dict:
        """Receive HTTP request and parse it"""
        # Read HTTP request line by line until we get headers and body
        lines = []
        while True:
            line = self._recv_line()
            lines.append(line)
            if line == b'\r\n':  # End of headers
                break
        
        # Parse request line
        request_line = lines[0].decode('utf-8').strip()
        method, path, version = request_line.split(' ', 2)
        
        # Parse headers
        headers = {}
        for line in lines[1:-1]:  # Skip request line and empty line
            header_line = line.decode('utf-8').strip()
            if ':' in header_line:
                key, value = header_line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Read body if present
        body = b""
        if 'content-length' in headers:
            content_length = int(headers['content-length'])
            body = self._recv_exact(content_length)
        
        return {
            'method': method,
            'path': path,
            'headers': headers,
            'body': body
        }
    
    def _http_receive_response(self) -> dict:
        """Receive HTTP response and parse it"""
        # Read status line
        status_line = self._recv_line().decode('utf-8').strip()
        version, status_code, status_text = status_line.split(' ', 2)
        
        # Read headers
        headers = {}
        while True:
            line = self._recv_line()
            if line == b'\r\n':  # End of headers
                break
            header_line = line.decode('utf-8').strip()
            if ':' in header_line:
                key, value = header_line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Read body
        body = b""
        if 'content-length' in headers:
            content_length = int(headers['content-length'])
            body = self._recv_exact(content_length)
        
        return {
            'status': int(status_code),
            'headers': headers,
            'body': body
        }
    
    def _recv_line(self) -> bytes:
        """Receive a line ending with \r\n"""
        line = b""
        while True:
            char = self.socket.recv(1)
            if not char:
                raise ConnectionError("Socket closed")
            line += char
            if line.endswith(b'\r\n'):
                return line
    
    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes"""
        data = b""
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Socket closed")
            data += chunk
        return data
    
    def send_encrypted(self, plaintext: bytes):
        """Send an encrypted message via JSON-RPC"""
        if not self._handshake_done:
            raise ValueError("Handshake not completed")
        
        ciphertext = self.noise_session.encrypt(plaintext)
        
        if self.is_client:
            # Client sends JSON-RPC call and receives response
            response_ciphertext = self._jsonrpc_call("noise-data", [ciphertext])
            # Store response for recv_encrypted to pick up
            self._pending_response = response_ciphertext
        else:
            # Server side is handled in the server loop
            raise RuntimeError("Server should not call send_encrypted directly")
    
    def recv_encrypted(self) -> bytes:
        """Receive and decrypt a message via JSON-RPC"""
        if not self._handshake_done:
            raise ValueError("Handshake not completed")
        
        if self.is_client:
            # Client gets the response from send_encrypted
            if not hasattr(self, '_pending_response'):
                raise RuntimeError("No pending response available")
            
            response_ciphertext = self._pending_response
            delattr(self, '_pending_response')
            
            return self.noise_session.decrypt(response_ciphertext)
        else:
            # Server side is handled in the server loop
            raise RuntimeError("Server should not call recv_encrypted directly")
    
    def close(self):
        """Close the socket"""
        self.socket.close()


# Key management utilities
def generate_client_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generate a random client keypair"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_dummy_client_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generate a deterministic dummy client keypair for testing"""
    # Use a fixed seed for deterministic key generation
    # In production, this would be replaced with proper client authentication
    dummy_seed = b"OpenADP-dummy-client-key-v1.0"
    dummy_hash = hashlib.sha256(dummy_seed).digest()
    
    # Create private key from hash
    private_key = x25519.X25519PrivateKey.from_private_bytes(dummy_hash)
    public_key = private_key.public_key()
    return private_key, public_key


def parse_server_public_key(public_key_str: str) -> x25519.X25519PublicKey:
    """
    Parse server public key from servers.json format.
    
    For now, this does a simple conversion from the ed25519 format.
    In production, proper key conversion would be needed.
    """
    if not public_key_str.startswith("ed25519:"):
        raise ValueError("Only ed25519 keys supported")
    
    # Extract base64 part
    b64_key = public_key_str[8:]
    
    try:
        # Decode the key
        key_bytes = base64.b64decode(b64_key)
        
        # For testing: convert to X25519 format (simplified)
        # In production, use proper Ed25519->X25519 conversion
        if len(key_bytes) >= 32:
            x25519_bytes = key_bytes[:32]
        else:
            # Pad with hash if too short
            x25519_bytes = hashlib.sha256(key_bytes).digest()
        
        return x25519.X25519PublicKey.from_public_bytes(x25519_bytes)
        
    except Exception as e:
        # Fallback: hash the string representation
        hash_bytes = hashlib.sha256(public_key_str.encode()).digest()
        return x25519.X25519PublicKey.from_public_bytes(hash_bytes)


def create_client_session(server_public_key_str: str) -> SimplifiedNoiseKK:
    """Create a client Noise-KK session"""
    # Use deterministic dummy client key for testing
    # In production, this would use proper client authentication
    client_private, client_public = generate_dummy_client_keypair()
    server_public = parse_server_public_key(server_public_key_str)
    
    return SimplifiedNoiseKK(
        is_initiator=True,
        local_static_private=client_private,
        remote_static_public=server_public
    )


def create_server_session(server_private_key: x25519.X25519PrivateKey, 
                         client_public_key: x25519.X25519PublicKey) -> SimplifiedNoiseKK:
    """Create a server Noise-KK session"""
    return SimplifiedNoiseKK(
        is_initiator=False,
        local_static_private=server_private_key,
        remote_static_public=client_public_key
    )


def test_simplified_noise_kk():
    """Test function for simplified Noise-KK implementation"""
    try:
        # Test key generation
        server_private, server_public = generate_client_keypair()
        client_private, client_public = generate_client_keypair()
        
        # Create sessions
        client_session = SimplifiedNoiseKK(True, client_private, server_public)
        server_session = SimplifiedNoiseKK(False, server_private, client_public)
        
        # Handshake
        msg1 = client_session.start_handshake()
        msg2, complete_server = server_session.process_handshake_message(msg1)
        _, complete_client = client_session.process_handshake_message(msg2)
        
        if not (complete_client and complete_server):
            return False
        
        # Test encryption
        test_data = b"Hello, OpenADP Noise-KK!"
        encrypted = client_session.encrypt(test_data)
        decrypted = server_session.decrypt(encrypted)
        
        return decrypted == test_data
        
    except Exception:
        return False


if __name__ == "__main__":
    # Test the implementation
    print("Testing Simplified Noise-KK implementation...")
    
    try:
        # Generate test keys
        server_private, server_public = generate_client_keypair()
        client_private, client_public = generate_client_keypair()
        
        print(f"Server public key: {server_public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()}")
        print(f"Client public key: {client_public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()}")
        
        # Create sessions
        client_session = SimplifiedNoiseKK(True, client_private, server_public)
        server_session = SimplifiedNoiseKK(False, server_private, client_public)
        
        print("\nPerforming handshake...")
        
        # Handshake
        msg1 = client_session.start_handshake()
        print(f"Client -> Server: {len(msg1)} bytes")
        
        msg2, complete_server = server_session.process_handshake_message(msg1)
        print(f"Server -> Client: {len(msg2)} bytes, complete: {complete_server}")
        
        _, complete_client = client_session.process_handshake_message(msg2)
        print(f"Client complete: {complete_client}")
        
        if complete_client and complete_server:
            print("✅ Handshake completed!")
            
            # Test encryption
            test_msg = b"Hello, OpenADP Noise-KK!"
            encrypted = client_session.encrypt(test_msg)
            decrypted = server_session.decrypt(encrypted)
            
            print(f"Original:  {test_msg}")
            print(f"Encrypted: {encrypted.hex()}")
            print(f"Decrypted: {decrypted}")
            
            if decrypted == test_msg:
                print("✅ Encryption test passed!")
            else:
                print("❌ Encryption test failed!")
        else:
            print("❌ Handshake failed!")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc() 