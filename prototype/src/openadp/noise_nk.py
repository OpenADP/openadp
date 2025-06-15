#!/usr/bin/env python3
"""
Simple Noise-NK Implementation

A clean, easy-to-use wrapper around dissononce that implements just the
Noise-NK handshake pattern with a straightforward API.

Usage:
    # Initialize parties - only responder needs static key known to initiator
    client = NoiseNK(role='initiator', remote_static_key=server_key)
    server = NoiseNK(role='responder', local_static_key=server_key)
    
    # Perform handshake
    msg1 = client.write_handshake_message(b"Hello Server")
    response1 = server.read_handshake_message(msg1)
    
    msg2 = server.write_handshake_message(b"Hello Client") 
    response2 = client.read_handshake_message(msg2)
    
    # Now both parties can encrypt/decrypt messages
    encrypted = client.encrypt(b"Secret message")
    decrypted = server.decrypt(encrypted)
"""

from typing import Optional, Tuple, Union
from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
from dissononce.processing.handshakepatterns.interactive.NK import NKHandshakePattern


class NoiseNK:
    """
    Simple Noise-NK implementation with clean API.
    
    The NK pattern provides responder authentication where the initiator
    has pre-shared knowledge of the responder's static public key.
    """
    
    def __init__(self, role: str, local_static_key=None, remote_static_key=None, prologue: bytes = b''):
        """
        Initialize a Noise-NK endpoint.
        
        Args:
            role: Either 'initiator' or 'responder'
            local_static_key: Responder's static keypair (None for initiator)
            remote_static_key: Responder's static public key (for initiator only)
            prologue: Optional prologue data (defaults to empty)
        """
        if role not in ['initiator', 'responder']:
            raise ValueError("Role must be 'initiator' or 'responder'")
        
        self.role = role
        self.is_initiator = (role == 'initiator')
        self.prologue = prologue
        self.handshake_complete = False
        
        # Create protocol factory and handshake state
        factory = NoiseProtocolFactory()
        protocol = factory.get_noise_protocol('Noise_NK_25519_AESGCM_SHA256')
        self.handshake_state = protocol.create_handshakestate()
        self.dh = protocol.dh
        
        # In NK pattern, only responder has a static key
        if self.is_initiator:
            # Initiator has no static key, only needs responder's public key
            self.local_static_key = None
            if remote_static_key is None:
                raise ValueError("Initiator must provide responder's static public key")
            self.remote_static_key = remote_static_key
        else:
            # Responder must have a static key
            if local_static_key is None:
                self.local_static_key = self.dh.generate_keypair()
            else:
                self.local_static_key = local_static_key
            self.remote_static_key = None
            
        # Initialize handshake
        self._initialize_handshake()
    
    def _initialize_handshake(self):
        """Initialize the handshake state with NK pattern."""
        pattern = NKHandshakePattern()
        self.handshake_state.initialize(
            handshake_pattern=pattern,
            initiator=self.is_initiator,
            prologue=self.prologue,
            s=self.local_static_key,
            rs=self.remote_static_key
        )
    
    def get_public_key(self) -> bytes:
        """Get this party's static public key as bytes."""
        return self.local_static_key.public.data
    
    def set_remote_public_key(self, remote_public_key: bytes):
        """
        Set the remote party's static public key and initialize handshake.
        
        Args:
            remote_public_key: The other party's static public key as bytes
        """
        # Convert bytes to public key object
        self.remote_static_key = self.dh.create_public(remote_public_key)
        self._initialize_handshake()
    
    def write_handshake_message(self, payload: bytes = b'') -> bytes:
        """
        Write the next handshake message.
        
        Args:
            payload: Optional payload to include in the handshake message
            
        Returns:
            The handshake message bytes to send to the other party
        """
        if self.handshake_complete:
            raise RuntimeError("Handshake is already complete")
        
        message_buffer = bytearray()
        self.handshake_state.write_message(payload, message_buffer)
        
        # Track that we wrote a message
        self._wrote_message = True
        
        # Check if handshake is complete (both messages exchanged)
        if hasattr(self, '_read_message') and hasattr(self, '_wrote_message'):
            self._finalize_handshake()
        
        return bytes(message_buffer)
    
    def read_handshake_message(self, message: bytes) -> bytes:
        """
        Read and process a handshake message from the other party.
        
        Args:
            message: The handshake message bytes received
            
        Returns:
            The payload that was included in the handshake message
        """
        if self.handshake_complete:
            raise RuntimeError("Handshake is already complete")
        
        payload_buffer = bytearray()
        self.handshake_state.read_message(message, payload_buffer)
        
        # Track that we read a message
        self._read_message = True
        
        # Check if handshake is complete (both messages exchanged)
        if hasattr(self, '_read_message') and hasattr(self, '_wrote_message'):
            self._finalize_handshake()
        
        return bytes(payload_buffer)
    
    def _finalize_handshake(self):
        """Finalize the handshake and extract cipher states."""
        cipher1, cipher2 = self.handshake_state.symmetricstate.split()
        
        # The cipher pairing depends on role:
        # Initiator: cipher1 for sending, cipher2 for receiving  
        # Responder: cipher1 for receiving, cipher2 for sending
        if self.is_initiator:
            self.send_cipher = cipher1
            self.recv_cipher = cipher2
        else:
            self.send_cipher = cipher2  
            self.recv_cipher = cipher1
            
        self.handshake_complete = True
        self.handshake_hash = self.handshake_state.symmetricstate.get_handshake_hash()
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = b'') -> bytes:
        """
        Encrypt a message (post-handshake).
        
        Args:
            plaintext: The message to encrypt
            associated_data: Optional associated data for AEAD
            
        Returns:
            The encrypted message
        """
        if not self.handshake_complete:
            raise RuntimeError("Handshake must be completed before encrypting messages")
        
        return self.send_cipher.encrypt_with_ad(associated_data, plaintext)
    
    def decrypt(self, ciphertext: bytes, associated_data: bytes = b'') -> bytes:
        """
        Decrypt a message (post-handshake).
        
        Args:
            ciphertext: The encrypted message to decrypt
            associated_data: Optional associated data for AEAD
            
        Returns:
            The decrypted message
        """
        if not self.handshake_complete:
            raise RuntimeError("Handshake must be completed before decrypting messages")
        
        return self.recv_cipher.decrypt_with_ad(associated_data, ciphertext)
    
    def get_handshake_hash(self) -> bytes:
        """
        Get the handshake hash for channel binding.
        
        Returns:
            The handshake hash bytes
        """
        if not self.handshake_complete:
            raise RuntimeError("Handshake must be completed to get handshake hash")
        
        return self.handshake_hash
    
    def is_handshake_complete(self) -> bool:
        """Check if the handshake is complete."""
        return self.handshake_complete


def generate_keypair():
    """
    Generate a new X25519 keypair for use with NoiseNK.
    
    Returns:
        A keypair object that can be used as local_static_key
    """
    factory = NoiseProtocolFactory()
    protocol = factory.get_noise_protocol('Noise_NK_25519_AESGCM_SHA256')
    return protocol.dh.generate_keypair()


# Example usage and test
if __name__ == "__main__":
    def test_noise_nk():
        """Test the NoiseNK implementation with bidirectional communication."""
        print("=== Testing Simple NoiseNK Implementation ===\n")
        
        # 1. Generate keypair for responder only (NK pattern)
        print("1. Generating server keypair...")
        server_keypair = generate_keypair()
        
        print(f"Server public key: {server_keypair.public.data.hex()}")
        
        # 2. Initialize both parties - only server has static key
        print("\n2. Initializing NoiseNK endpoints...")
        client = NoiseNK(
            role='initiator',
            remote_static_key=server_keypair.public
        )
        
        server = NoiseNK(
            role='responder', 
            local_static_key=server_keypair
        )
        
        # 3. Perform NK handshake
        print("\n3. Performing NK handshake...")
        
        # Message 1: Client -> Server
        print("   Client sending handshake message 1...")
        msg1 = client.write_handshake_message(b"Hello from client!")
        print(f"   Message 1: {len(msg1)} bytes")
        
        payload1 = server.read_handshake_message(msg1)
        print(f"   Server received: '{payload1.decode()}'")
        
        # Message 2: Server -> Client  
        print("   Server sending handshake message 2...")
        msg2 = server.write_handshake_message(b"Hello from server!")
        print(f"   Message 2: {len(msg2)} bytes")
        
        payload2 = client.read_handshake_message(msg2)
        print(f"   Client received: '{payload2.decode()}'")
        
        print(f"\n✅ Handshake complete!")
        print(f"   Client handshake status: {client.is_handshake_complete()}")
        print(f"   Server handshake status: {server.is_handshake_complete()}")
        print(f"   Handshake hash: {client.get_handshake_hash().hex()[:32]}...")
        
        # 4. Test post-handshake encrypted communication
        print("\n4. Testing encrypted communication...")
        
        # Client -> Server
        secret_msg = b"This is a secret message from client to server!"
        print(f"   Client encrypting: '{secret_msg.decode()}'")
        encrypted = client.encrypt(secret_msg)
        print(f"   Encrypted: {encrypted.hex()[:64]}...")
        
        decrypted = server.decrypt(encrypted)
        print(f"   Server decrypted: '{decrypted.decode()}'")
        print(f"   ✅ Encryption successful: {decrypted == secret_msg}")
        
        # Server -> Client
        response_msg = b"Server's secret response back to client!"
        print(f"\n   Server encrypting: '{response_msg.decode()}'")
        encrypted_response = server.encrypt(response_msg)
        print(f"   Encrypted: {encrypted_response.hex()[:64]}...")
        
        decrypted_response = client.decrypt(encrypted_response)
        print(f"   Client decrypted: '{decrypted_response.decode()}'")
        print(f"   ✅ Encryption successful: {decrypted_response == response_msg}")
        
        # 5. Test multiple message exchange
        print("\n5. Testing multiple message exchange...")
        messages = [
            (b"Message 1", "Client -> Server"),
            (b"ACK 1", "Server -> Client"),
            (b"Message 2 with more data", "Client -> Server"),
            (b"Final ACK", "Server -> Client")
        ]
        
        for msg, direction in messages:
            if "Client -> Server" in direction:
                encrypted = client.encrypt(msg)
                decrypted = server.decrypt(encrypted)
            else:
                encrypted = server.encrypt(msg)
                decrypted = client.decrypt(encrypted)
            
            print(f"   {direction}: '{msg.decode()}' -> '{decrypted.decode()}' ✅")
        
        print("\n🎉 All tests passed! NoiseNK implementation working perfectly!")
    
    test_noise_nk() 