#!/usr/bin/env python3
"""
Noise-KK Implementation for OpenADP

This module implements the Noise-KK handshake pattern for secure communication
between OpenADP clients and servers. The Noise-KK pattern provides mutual
authentication where both parties have known static keys.

Pattern: KK
  -> s
  <- s
  ...
  -> e, es, ss
  <- e, ee, se

The implementation uses the dissononce library for Noise protocol operations.
"""

import base64
import hashlib
import secrets
from typing import Tuple, Optional, Dict, Any
import json
import socket
import ssl
from dataclasses import dataclass

try:
    from dissononce.processing.impl.handshakestate import HandshakeState
    from dissononce.processing.impl.symmetricstate import SymmetricState
    from dissononce.processing.impl.cipherstate import CipherState
    from dissononce.cipher.chachapoly import ChaChaPolyCipher
    from dissononce.dh.curve25519 import Curve25519DH
    from dissononce.hash.blake2s import Blake2sHash
    from dissononce.processing.handshakepatterns import HandshakePattern
    NOISE_AVAILABLE = True
except ImportError:
    print("Warning: dissononce library not found. Install with: pip install dissononce")
    NOISE_AVAILABLE = False

# Fallback minimal implementation for testing
class NoiseKKDummy:
    """Dummy implementation when dissononce is not available"""
    def __init__(self, is_initiator: bool, local_static_private: bytes, 
                 remote_static_public: bytes):
        self.is_initiator = is_initiator
        self.local_static_private = local_static_private
        self.remote_static_public = remote_static_public
        self.handshake_complete = False
        self.send_cipher = None
        self.recv_cipher = None
    
    def start_handshake(self) -> bytes:
        return b"DUMMY_HANDSHAKE_MESSAGE"
    
    def process_handshake_message(self, message: bytes) -> Tuple[Optional[bytes], bool]:
        self.handshake_complete = True
        return None, True
    
    def encrypt(self, plaintext: bytes) -> bytes:
        return b"ENCRYPTED:" + plaintext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        if ciphertext.startswith(b"ENCRYPTED:"):
            return ciphertext[10:]
        return ciphertext

@dataclass
class NoiseKKConfig:
    """Configuration for Noise-KK sessions"""
    protocol_name: str = "Noise_KK_25519_ChaChaPoly_BLAKE2s"
    dh_class = Curve25519DH if NOISE_AVAILABLE else None
    cipher_class = ChaChaPolyCipher if NOISE_AVAILABLE else None
    hash_class = Blake2sHash if NOISE_AVAILABLE else None


class NoiseKKSession:
    """
    Manages a Noise-KK session between client and server.
    
    The KK pattern assumes both parties have pre-shared static keys.
    Server static keys are distributed via servers.json.
    Client static keys are generated locally (dummy keys for now).
    """
    
    def __init__(self, is_initiator: bool, local_static_private: bytes, 
                 remote_static_public: bytes, config: Optional[NoiseKKConfig] = None):
        """
        Initialize a Noise-KK session.
        
        Args:
            is_initiator: True if this is the client (initiator), False if server (responder)
            local_static_private: Local static private key (32 bytes)
            remote_static_public: Remote static public key (32 bytes)
            config: Optional configuration parameters
        """
        self.is_initiator = is_initiator
        self.local_static_private = local_static_private
        self.remote_static_public = remote_static_public
        self.config = config or NoiseKKConfig()
        self.handshake_complete = False
        self.send_cipher = None
        self.recv_cipher = None
        
        if not NOISE_AVAILABLE:
            print("Warning: Using dummy Noise-KK implementation")
            self._noise_impl = NoiseKKDummy(is_initiator, local_static_private, remote_static_public)
            return
            
        # Initialize the Noise handshake state
        self._initialize_noise_state()
    
    def _initialize_noise_state(self):
        """Initialize the Noise-KK handshake state"""
        if not NOISE_AVAILABLE:
            return
            
        # Create the handshake pattern
        # KK pattern: -> s <- s ... -> e, es, ss <- e, ee, se
        pattern = HandshakePattern("KK", 
                                 [["s"], ["s"]], # pre-messages
                                 [["e", "es", "ss"], ["e", "ee", "se"]]) # message patterns
        
        # Initialize handshake state
        self.handshake_state = HandshakeState.initialize_handshake_state(
            handshake_pattern=pattern,
            initiator=self.is_initiator,
            prologue=b"OpenADP-v1.0",
            s=self.local_static_private,
            rs=self.remote_static_public,
            dh=self.config.dh_class(),
            cipher=self.config.cipher_class(),
            hashfn=self.config.hash_class()
        )
    
    def start_handshake(self) -> bytes:
        """
        Start the handshake by generating the initial message.
        Only called by the initiator.
        
        Returns:
            The initial handshake message bytes
        """
        if not self.is_initiator:
            raise ValueError("Only initiator can start handshake")
            
        if not NOISE_AVAILABLE:
            return self._noise_impl.start_handshake()
        
        message_buffer = bytearray()
        self.handshake_state.write_message(b"", message_buffer)
        return bytes(message_buffer)
    
    def process_handshake_message(self, message: bytes) -> Tuple[Optional[bytes], bool]:
        """
        Process a received handshake message.
        
        Args:
            message: The received handshake message
            
        Returns:
            Tuple of (response_message, handshake_complete)
            response_message is None if no response needed
            handshake_complete is True when handshake is finished
        """
        if not NOISE_AVAILABLE:
            return self._noise_impl.process_handshake_message(message)
        
        payload_buffer = bytearray()
        cipherstate_send, cipherstate_recv = self.handshake_state.read_message(message, payload_buffer)
        
        if cipherstate_send is not None and cipherstate_recv is not None:
            # Handshake complete
            self.handshake_complete = True
            if self.is_initiator:
                self.send_cipher = cipherstate_send
                self.recv_cipher = cipherstate_recv
            else:
                self.send_cipher = cipherstate_recv
                self.recv_cipher = cipherstate_send
            return None, True
        
        # Generate response message if we're the responder and haven't completed
        if not self.is_initiator and not self.handshake_complete:
            response_buffer = bytearray()
            self.handshake_state.write_message(b"", response_buffer)
            return bytes(response_buffer), False
        
        return None, False
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt a message using the established Noise channel.
        
        Args:
            plaintext: The message to encrypt
            
        Returns:
            The encrypted message
        """
        if not self.handshake_complete:
            raise ValueError("Handshake not complete")
            
        if not NOISE_AVAILABLE:
            return self._noise_impl.encrypt(plaintext)
        
        return self.send_cipher.encrypt_with_ad(b"", plaintext)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt a message using the established Noise channel.
        
        Args:
            ciphertext: The message to decrypt
            
        Returns:
            The decrypted message
        """
        if not self.handshake_complete:
            raise ValueError("Handshake not complete")
            
        if not NOISE_AVAILABLE:
            return self._noise_impl.decrypt(ciphertext)
        
        return self.recv_cipher.decrypt_with_ad(b"", ciphertext)


class NoiseKKTransport:
    """
    Provides a socket-like interface for Noise-KK encrypted communication.
    Handles the handshake and subsequent encrypted messaging.
    """
    
    def __init__(self, socket_obj: socket.socket, noise_session: NoiseKKSession):
        """
        Initialize the Noise-KK transport.
        
        Args:
            socket_obj: The underlying socket (should be TLS-wrapped)
            noise_session: The Noise-KK session manager
        """
        self.socket = socket_obj
        self.noise_session = noise_session
        self._handshake_done = False
    
    def perform_handshake(self):
        """Perform the Noise-KK handshake over the socket"""
        if self._handshake_done:
            return
            
        if self.noise_session.is_initiator:
            # Client sends first message
            initial_message = self.noise_session.start_handshake()
            self._send_noise_message(initial_message)
            
            # Wait for server response
            response = self._recv_noise_message()
            _, complete = self.noise_session.process_handshake_message(response)
            
            if not complete:
                raise RuntimeError("Handshake not completed after response")
        else:
            # Server waits for client message
            client_message = self._recv_noise_message()
            response, complete = self.noise_session.process_handshake_message(client_message)
            
            if response:
                self._send_noise_message(response)
            
            if not complete:
                raise RuntimeError("Handshake not completed after processing client message")
        
        self._handshake_done = True
    
    def _send_noise_message(self, message: bytes):
        """Send a Noise message with length prefix"""
        length = len(message)
        length_bytes = length.to_bytes(2, 'big')  # 16-bit big-endian length
        self.socket.send(length_bytes + message)
    
    def _recv_noise_message(self) -> bytes:
        """Receive a Noise message with length prefix"""
        # Read 2-byte length prefix
        length_bytes = self._recv_exact(2)
        length = int.from_bytes(length_bytes, 'big')
        
        # Read the message
        return self._recv_exact(length)
    
    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes from the socket"""
        data = b""
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Socket closed during receive")
            data += chunk
        return data
    
    def send_encrypted(self, plaintext: bytes):
        """Send an encrypted message"""
        if not self._handshake_done:
            raise ValueError("Handshake not completed")
        
        ciphertext = self.noise_session.encrypt(plaintext)
        self._send_noise_message(ciphertext)
    
    def recv_encrypted(self) -> bytes:
        """Receive and decrypt a message"""
        if not self._handshake_done:
            raise ValueError("Handshake not completed")
        
        ciphertext = self._recv_noise_message()
        return self.noise_session.decrypt(ciphertext)
    
    def close(self):
        """Close the underlying socket"""
        self.socket.close()


def generate_client_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a new client keypair for Noise-KK.
    
    Returns:
        Tuple of (private_key, public_key) as 32-byte values
    """
    if NOISE_AVAILABLE:
        dh = Curve25519DH()
        keypair = dh.generate_keypair()
        return keypair.private_bytes, keypair.public_bytes
    else:
        # Dummy implementation
        private_key = secrets.token_bytes(32)
        public_key = hashlib.sha256(private_key).digest()
        return private_key, public_key


def parse_server_public_key(public_key_str: str) -> bytes:
    """
    Parse a server public key from the servers.json format.
    
    Args:
        public_key_str: Public key in format "ed25519:base64data"
        
    Returns:
        32-byte public key
    """
    if not public_key_str.startswith("ed25519:"):
        raise ValueError("Only ed25519 keys are supported")
    
    # For now, we'll convert Ed25519 key to Curve25519 format
    # In a real implementation, you'd need proper key conversion
    ed25519_b64 = public_key_str[8:]  # Remove "ed25519:" prefix
    
    try:
        key_bytes = base64.b64decode(ed25519_b64)
        # Pad or truncate to 32 bytes (dummy conversion for now)
        if len(key_bytes) > 32:
            return key_bytes[:32]
        elif len(key_bytes) < 32:
            return key_bytes + b'\x00' * (32 - len(key_bytes))
        return key_bytes
    except Exception as e:
        # Fallback to hash of the key string for testing
        return hashlib.sha256(public_key_str.encode()).digest()


# Example usage functions for testing
def create_client_session(server_public_key_str: str) -> NoiseKKSession:
    """Create a client-side Noise-KK session"""
    client_private, client_public = generate_client_keypair()
    server_public = parse_server_public_key(server_public_key_str)
    
    return NoiseKKSession(
        is_initiator=True,
        local_static_private=client_private,
        remote_static_public=server_public
    )


def create_server_session(server_private_key: bytes, client_public_key: bytes) -> NoiseKKSession:
    """Create a server-side Noise-KK session"""
    return NoiseKKSession(
        is_initiator=False,
        local_static_private=server_private_key,
        remote_static_public=client_public_key
    )


if __name__ == "__main__":
    # Basic test of the Noise-KK implementation
    print("Testing Noise-KK implementation...")
    
    # Generate test keys
    server_private = secrets.token_bytes(32)
    server_public = hashlib.sha256(server_private).digest()
    client_private, client_public = generate_client_keypair()
    
    print(f"Generated client keypair")
    print(f"Client public key: {client_public.hex()}")
    print(f"Server public key: {server_public.hex()}")
    
    # Create sessions
    client_session = NoiseKKSession(True, client_private, server_public)
    server_session = NoiseKKSession(False, server_private, client_public)
    
    print("\nPerforming handshake...")
    
    # Handshake
    try:
        msg1 = client_session.start_handshake()
        print(f"Client -> Server: {len(msg1)} bytes")
        
        msg2, complete = server_session.process_handshake_message(msg1)
        print(f"Server -> Client: {len(msg2) if msg2 else 0} bytes, complete: {complete}")
        
        if msg2:
            _, complete = client_session.process_handshake_message(msg2)
            print(f"Client processed response, complete: {complete}")
        
        if client_session.handshake_complete and server_session.handshake_complete:
            print("✅ Handshake completed successfully!")
            
            # Test encryption
            test_message = b"Hello, Noise-KK World!"
            encrypted = client_session.encrypt(test_message)
            decrypted = server_session.decrypt(encrypted)
            
            print(f"Test message: {test_message}")
            print(f"Encrypted: {encrypted.hex()}")
            print(f"Decrypted: {decrypted}")
            
            if decrypted == test_message:
                print("✅ Encryption test passed!")
            else:
                print("❌ Encryption test failed!")
        else:
            print("❌ Handshake failed!")
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc() 