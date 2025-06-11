#!/usr/bin/env python3
"""
Professional Noise-KK Implementation for OpenADP using DissoNonce

This module implements the Noise-KK handshake pattern using the proper DissoNonce
library for secure communication between OpenADP clients and servers.

Features:
- Proper Noise Protocol Framework implementation
- Mutual authentication with static keys  
- Forward secrecy via ephemeral keys
- ChaCha20-Poly1305 encryption
- X25519 ECDH key exchange
- SHA256 hashing

Pattern: KK
  -> s
  <- s
  ...
  -> e, es, ss
  <- e, ee, se
"""

import base64
import hashlib
import secrets
import socket
import ssl
import logging
import struct
from typing import Tuple, Optional, Dict, Any, Union

# Import DissoNonce components
try:
    from dissononce.processing.impl.handshakestate import HandshakeState
    from dissononce.processing.impl.symmetricstate import SymmetricState  
    from dissononce.processing.impl.cipherstate import CipherState
    from dissononce.processing.handshakepatterns.interactive.KK import KKHandshakePattern
    from dissononce.cipher.chachapoly import ChaChaPolyCipher
    from dissononce.dh.x25519 import X25519DH
    from dissononce.hash.sha256 import SHA256Hash
    from dissononce.processing.impl.keypair import KeyPair
    DISSONONCE_AVAILABLE = True
except ImportError as e:
    DISSONONCE_AVAILABLE = False
    print(f"Warning: DissoNonce not available: {e}")
    print("Falling back to simplified implementation")

# Import for Ed25519 key parsing compatibility
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


class NoiseKKSession:
    """
    Professional Noise-KK session using DissoNonce library.
    
    Implements the full Noise Protocol Framework KK pattern with proper
    cryptographic primitives and state management.
    """
    
    def __init__(self, is_initiator: bool, local_static_keypair: KeyPair, 
                 remote_static_public: bytes):
        """
        Initialize Noise-KK session.
        
        Args:
            is_initiator: True for client (initiator), False for server (responder)
            local_static_keypair: Local static key pair (DissoNonce KeyPair)
            remote_static_public: Remote party's static public key (32 bytes)
        """
        if not DISSONONCE_AVAILABLE:
            raise RuntimeError("DissoNonce library required for this implementation")
            
        self.is_initiator = is_initiator
        self.local_static = local_static_keypair
        self.remote_static_public = remote_static_public
        self.handshake_complete = False
        self.send_cipher = None
        self.recv_cipher = None
        
        # Initialize the handshake state
        self._initialize_handshake()
    
    def _initialize_handshake(self):
        """Initialize the Noise-KK handshake state"""
        # Create DH, cipher, and hash objects
        dh = X25519DH()
        cipher = ChaChaPolyCipher()
        hashfn = SHA256Hash()
        
        # Get the KK handshake pattern
        pattern = KKHandshakePattern()
        
        # Initialize handshake state
        self.handshake_state = HandshakeState.initialize_handshake_state(
            handshake_pattern=pattern,
            initiator=self.is_initiator,
            prologue=b"OpenADP-v1.0",  # Protocol identifier
            s=self.local_static,
            rs=self.remote_static_public,
            dh=dh,
            cipher=cipher, 
            hashfn=hashfn
        )
        
        logger.debug(f"Initialized Noise-KK {'initiator' if self.is_initiator else 'responder'}")
    
    def start_handshake(self) -> bytes:
        """
        Start handshake (initiator only).
        
        Returns:
            First handshake message bytes
        """
        if not self.is_initiator:
            raise ValueError("Only initiator can start handshake")
        
        message_buffer = bytearray()
        # Write first message: -> e, es, ss
        self.handshake_state.write_message(b"", message_buffer)
        
        logger.debug(f"Generated handshake message 1: {len(message_buffer)} bytes")
        return bytes(message_buffer)
    
    def process_handshake_message(self, message: bytes) -> Tuple[Optional[bytes], bool]:
        """
        Process received handshake message.
        
        Args:
            message: Received handshake message
            
        Returns:
            Tuple of (response_message, is_complete)
        """
        logger.debug(f"Processing handshake message: {len(message)} bytes")
        
        # Read the message
        payload_buffer = bytearray()
        result = self.handshake_state.read_message(message, payload_buffer)
        
        # Check if handshake is complete
        if result is not None and len(result) == 2:
            # Handshake complete - we have cipher states
            send_cipher, recv_cipher = result
            self.handshake_complete = True
            
            # Assign cipher states based on role
            if self.is_initiator:
                self.send_cipher = send_cipher
                self.recv_cipher = recv_cipher
            else:
                self.send_cipher = recv_cipher  # Swapped for responder
                self.recv_cipher = send_cipher
            
            logger.debug("Handshake completed successfully")
            return None, True
        
        # Generate response if we're responder and haven't finished
        if not self.is_initiator and not self.handshake_complete:
            response_buffer = bytearray()
            # Write second message: <- e, ee, se  
            result = self.handshake_state.write_message(b"", response_buffer)
            
            # Check if this completes the handshake
            if result is not None and len(result) == 2:
                send_cipher, recv_cipher = result
                self.handshake_complete = True
                self.send_cipher = recv_cipher  # Swapped for responder
                self.recv_cipher = send_cipher
                logger.debug("Handshake completed (responder)")
            
            logger.debug(f"Generated handshake response: {len(response_buffer)} bytes")
            return bytes(response_buffer), self.handshake_complete
        
        return None, self.handshake_complete
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt message using established channel.
        
        Args:
            plaintext: Message to encrypt
            
        Returns:
            Encrypted message bytes
        """
        if not self.handshake_complete:
            raise RuntimeError("Handshake not complete")
        
        if self.send_cipher is None:
            raise RuntimeError("Send cipher not initialized")
        
        # Encrypt the message
        ciphertext = self.send_cipher.encrypt_with_ad(b"", plaintext)
        logger.debug(f"Encrypted {len(plaintext)} -> {len(ciphertext)} bytes")
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt message using established channel.
        
        Args:
            ciphertext: Encrypted message
            
        Returns:
            Decrypted plaintext bytes
        """
        if not self.handshake_complete:
            raise RuntimeError("Handshake not complete")
        
        if self.recv_cipher is None:
            raise RuntimeError("Receive cipher not initialized")
        
        # Decrypt the message
        plaintext = self.recv_cipher.decrypt_with_ad(b"", ciphertext)
        logger.debug(f"Decrypted {len(ciphertext)} -> {len(plaintext)} bytes")
        return plaintext


class NoiseKKTransport:
    """
    Transport layer for Noise-KK encrypted communication.
    
    Handles message framing and socket I/O over the encrypted channel.
    """
    
    def __init__(self, socket_obj: socket.socket, noise_session: NoiseKKSession):
        """
        Initialize transport.
        
        Args:
            socket_obj: Connected socket (typically TLS-wrapped)
            noise_session: Initialized Noise-KK session
        """
        self.socket = socket_obj
        self.noise_session = noise_session
        self.closed = False
    
    def perform_handshake(self):
        """Perform the complete Noise-KK handshake"""
        if self.noise_session.is_initiator:
            # Client: Send first message
            msg1 = self.noise_session.start_handshake()
            self._send_message(msg1)
            
            # Client: Receive and process response
            msg2 = self._recv_message()
            response, complete = self.noise_session.process_handshake_message(msg2)
            
            if not complete:
                raise RuntimeError("Handshake did not complete")
            
            logger.info("Client handshake completed")
            
        else:
            # Server: Receive first message
            msg1 = self._recv_message()
            response, complete = self.noise_session.process_handshake_message(msg1)
            
            if response is None:
                raise RuntimeError("Server should generate response")
            
            # Server: Send response
            self._send_message(response)
            
            if not complete:
                raise RuntimeError("Handshake did not complete")
            
            logger.info("Server handshake completed")
    
    def _send_message(self, message: bytes):
        """Send a length-prefixed message"""
        # Send length (2 bytes, big-endian) then message
        length = struct.pack(">H", len(message))
        self.socket.sendall(length + message)
        logger.debug(f"Sent message: {len(message)} bytes")
    
    def _recv_message(self) -> bytes:
        """Receive a length-prefixed message"""
        # Receive length (2 bytes)
        length_data = self._recv_exact(2)
        length = struct.unpack(">H", length_data)[0]
        
        # Receive message
        message = self._recv_exact(length)
        logger.debug(f"Received message: {len(message)} bytes")
        return message
    
    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes"""
        data = b""
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Socket closed unexpectedly")
            data += chunk
        return data
    
    def send_encrypted(self, plaintext: bytes):
        """Send encrypted application data"""
        if self.closed:
            raise RuntimeError("Transport is closed")
        
        # Encrypt and send
        ciphertext = self.noise_session.encrypt(plaintext)
        self._send_message(ciphertext)
    
    def recv_encrypted(self) -> bytes:
        """Receive and decrypt application data"""
        if self.closed:
            raise RuntimeError("Transport is closed")
        
        # Receive and decrypt
        ciphertext = self._recv_message()
        plaintext = self.noise_session.decrypt(ciphertext)
        return plaintext
    
    def close(self):
        """Close the transport"""
        self.closed = True
        if self.socket:
            self.socket.close()


# Utility functions for key management

def generate_keypair() -> Tuple[KeyPair, bytes]:
    """
    Generate a new X25519 keypair for Noise-KK.
    
    Returns:
        Tuple of (DissoNonce KeyPair, public_key_bytes)
    """
    if not DISSONONCE_AVAILABLE:
        raise RuntimeError("DissoNonce required")
    
    # Generate X25519 keypair  
    dh = X25519DH()
    keypair = dh.generate_keypair()
    
    # Extract public key bytes
    public_bytes = keypair.public
    
    return keypair, public_bytes


def keypair_from_private_bytes(private_bytes: bytes) -> KeyPair:
    """
    Create DissoNonce KeyPair from private key bytes.
    
    Args:
        private_bytes: 32-byte private key
        
    Returns:
        DissoNonce KeyPair object
    """
    if not DISSONONCE_AVAILABLE:
        raise RuntimeError("DissoNonce required")
    
    if len(private_bytes) != 32:
        raise ValueError("Private key must be 32 bytes")
    
    # Create X25519 keypair from private bytes
    dh = X25519DH()
    return dh.generate_keypair(private_bytes)


def parse_server_public_key(public_key_str: str) -> bytes:
    """
    Parse server public key from servers.json format.
    
    Args:
        public_key_str: Key in "ed25519:base64" format
        
    Returns:
        32-byte public key for Noise-KK
    """
    if not public_key_str.startswith("ed25519:"):
        raise ValueError("Expected ed25519: prefix")
    
    # Extract base64 part
    b64_key = public_key_str[8:]
    key_bytes = base64.b64decode(b64_key)
    
    # For compatibility, hash the Ed25519 key to get X25519 key
    # In production, servers should provide X25519 keys directly
    if len(key_bytes) == 32:
        # Hash to derive X25519-compatible key
        x25519_bytes = hashlib.sha256(key_bytes).digest()
        return x25519_bytes
    
    raise ValueError(f"Invalid key length: {len(key_bytes)}")


def create_client_session(server_public_key_str: str) -> NoiseKKSession:
    """
    Create client-side Noise-KK session.
    
    Args:
        server_public_key_str: Server public key from servers.json
        
    Returns:
        Configured NoiseKKSession as initiator
    """
    # Generate client keypair (dummy key for now)
    client_keypair, _ = generate_keypair()
    
    # Parse server public key
    server_public_bytes = parse_server_public_key(server_public_key_str)
    
    # Create session
    return NoiseKKSession(
        is_initiator=True,
        local_static_keypair=client_keypair,
        remote_static_public=server_public_bytes
    )


def create_server_session(server_private_key: Union[bytes, KeyPair], 
                         client_public_key: bytes) -> NoiseKKSession:
    """
    Create server-side Noise-KK session.
    
    Args:
        server_private_key: Server's private key (bytes or KeyPair)
        client_public_key: Client's public key bytes
        
    Returns:
        Configured NoiseKKSession as responder
    """
    # Convert private key to KeyPair if needed
    if isinstance(server_private_key, bytes):
        server_keypair = keypair_from_private_bytes(server_private_key)
    else:
        server_keypair = server_private_key
    
    # Create session
    return NoiseKKSession(
        is_initiator=False,
        local_static_keypair=server_keypair,
        remote_static_public=client_public_key
    )


# Test function
def test_noise_kk():
    """Test the DissoNonce Noise-KK implementation"""
    if not DISSONONCE_AVAILABLE:
        print("❌ DissoNonce not available")
        return False
    
    try:
        print("🔧 Testing DissoNonce Noise-KK implementation...")
        
        # Generate keypairs
        client_keypair, client_pub = generate_keypair()
        server_keypair, server_pub = generate_keypair()
        
        print(f"✅ Generated keypairs")
        
        # Create sessions
        client_session = NoiseKKSession(True, client_keypair, server_pub)
        server_session = NoiseKKSession(False, server_keypair, client_pub)
        
        print(f"✅ Created sessions")
        
        # Perform handshake
        msg1 = client_session.start_handshake()
        print(f"✅ Client started handshake: {len(msg1)} bytes")
        
        msg2, complete = server_session.process_handshake_message(msg1)
        print(f"✅ Server processed message: response={len(msg2) if msg2 else 0} bytes, complete={complete}")
        
        if msg2:
            _, complete = client_session.process_handshake_message(msg2)
            print(f"✅ Client processed response: complete={complete}")
        
        if not (client_session.handshake_complete and server_session.handshake_complete):
            print("❌ Handshake incomplete")
            return False
        
        # Test encryption
        test_message = b"Hello, DissoNonce Noise-KK!"
        encrypted = client_session.encrypt(test_message)
        decrypted = server_session.decrypt(encrypted)
        
        if decrypted == test_message:
            print(f"✅ Encryption test passed: {test_message}")
            return True
        else:
            print(f"❌ Encryption test failed")
            return False
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_noise_kk()
    if success:
        print("🎉 DissoNonce Noise-KK implementation working correctly!")
    else:
        print("💥 DissoNonce implementation test failed!") 