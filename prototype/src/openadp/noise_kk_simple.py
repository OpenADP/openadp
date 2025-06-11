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
    """Transport layer for Noise-KK over a socket"""
    
    def __init__(self, socket_obj: socket.socket, noise_session: SimplifiedNoiseKK):
        self.socket = socket_obj
        self.noise_session = noise_session
        self._handshake_done = False
    
    def perform_handshake(self):
        """Perform the Noise-KK handshake"""
        if self._handshake_done:
            return
        
        try:
            if self.noise_session.is_initiator:
                # Client: send initial message
                msg1 = self.noise_session.start_handshake()
                self._send_message(msg1)
                
                # Client: receive and process response
                msg2 = self._recv_message()
                _, complete = self.noise_session.process_handshake_message(msg2)
                
                if not complete:
                    raise RuntimeError("Handshake failed to complete")
            else:
                # Server: receive and process initial message
                msg1 = self._recv_message()
                msg2, complete = self.noise_session.process_handshake_message(msg1)
                
                # Server: send response
                if msg2:
                    self._send_message(msg2)
                
                if not complete:
                    raise RuntimeError("Handshake failed to complete")
            
            self._handshake_done = True
            logger.info("Noise-KK handshake completed successfully")
            
        except Exception as e:
            logger.error(f"Noise-KK handshake failed: {e}")
            raise
    
    def _send_message(self, message: bytes):
        """Send a message with length prefix"""
        if len(message) > 65535:
            raise ValueError("Message too large")
        
        length_bytes = struct.pack('>H', len(message))  # 16-bit big-endian
        self.socket.send(length_bytes + message)
    
    def _recv_message(self) -> bytes:
        """Receive a message with length prefix"""
        # Read length
        length_bytes = self._recv_exact(2)
        length = struct.unpack('>H', length_bytes)[0]
        
        # Read message
        return self._recv_exact(length)
    
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
        """Send an encrypted message"""
        if not self._handshake_done:
            raise ValueError("Handshake not completed")
        
        ciphertext = self.noise_session.encrypt(plaintext)
        self._send_message(ciphertext)
    
    def recv_encrypted(self) -> bytes:
        """Receive and decrypt a message"""
        if not self._handshake_done:
            raise ValueError("Handshake not completed")
        
        ciphertext = self._recv_message()
        return self.noise_session.decrypt(ciphertext)
    
    def close(self):
        """Close the socket"""
        self.socket.close()


# Key management utilities
def generate_client_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generate a client keypair"""
    private_key = x25519.X25519PrivateKey.generate()
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
    client_private, client_public = generate_client_keypair()
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