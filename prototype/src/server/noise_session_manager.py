#!/usr/bin/env python3
"""
Noise-NK Session Manager for OpenADP Server

This module manages ephemeral Noise-NK encryption sessions for the JSON-RPC server.
Each session is used for exactly one encrypted method call and then destroyed.

Design:
- Sessions are identified by 16-byte random session IDs  
- Server maintains a static keypair for NK pattern (responder role)
- Each session uses fresh ephemeral keys for perfect forward secrecy
- Sessions are automatically cleaned up after single use
"""

import base64
import json
import logging
import os
import secrets
import threading
import time
from typing import Dict, Optional, Tuple, Any

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'openadp'))

from noise_nk import NoiseNK, generate_keypair

logger = logging.getLogger(__name__)


class NoiseSessionManager:
    """
    Manages Noise-NK encryption sessions for the JSON-RPC server.
    
    This class handles:
    - Server static key management (NK responder)
    - Ephemeral session creation and cleanup
    - Handshake processing
    - Message encryption/decryption
    """
    
    def __init__(self, server_static_key=None):
        """
        Initialize the session manager.
        
        Args:
            server_static_key: Server's static keypair. If None, generates a new one.
        """
        self._sessions: Dict[str, NoiseNK] = {}
        self._session_lock = threading.RLock()
        self._cleanup_thread = None
        
        # Initialize server static key
        if server_static_key is None:
            logger.info("Generating new server static key for Noise-NK")
            self._server_key = generate_keypair()
        else:
            self._server_key = server_static_key
            
        logger.info(f"Noise-NK server initialized with public key: {self.get_server_public_key().hex()[:32]}...")
    
    def get_server_public_key(self) -> bytes:
        """Get the server's static public key for distribution to clients."""
        return self._server_key.public.data
    
    def start_handshake(self, session_id: str, client_handshake_message: bytes) -> Tuple[bytes, Optional[str]]:
        """
        Start a Noise-NK handshake for a new session.
        
        Args:
            session_id: Base64-encoded session identifier
            client_handshake_message: First handshake message from client
            
        Returns:
            Tuple of (server_handshake_response, error_message)
        """
        try:
            with self._session_lock:
                # Check if session already exists
                if session_id in self._sessions:
                    return b"", "Session ID already in use"
                
                # Create new Noise-NK session (server = responder)
                noise_session = NoiseNK(
                    role='responder',
                    local_static_key=self._server_key
                )
                
                # Process client's handshake message
                try:
                    server_payload = noise_session.read_handshake_message(client_handshake_message)
                    logger.debug(f"Received handshake payload from client: {server_payload}")
                except Exception as e:
                    logger.error(f"Failed to process client handshake: {e}")
                    return b"", f"Invalid handshake message: {str(e)}"
                
                # Send server's handshake response
                try:
                    server_response = noise_session.write_handshake_message(b"Server handshake response")
                except Exception as e:
                    logger.error(f"Failed to create server handshake response: {e}")
                    return b"", f"Failed to create handshake response: {str(e)}"
                
                # Store session for later use
                self._sessions[session_id] = noise_session
                
                logger.info(f"Handshake completed for session {session_id[:16]}...")
                return server_response, None
                
        except Exception as e:
            logger.error(f"Unexpected error in handshake: {e}")
            return b"", f"Internal error during handshake: {str(e)}"
    
    def decrypt_call(self, session_id: str, encrypted_data: bytes) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Decrypt an encrypted JSON-RPC call and clean up the session.
        
        Args:
            session_id: Session identifier
            encrypted_data: Encrypted JSON-RPC request
            
        Returns:
            Tuple of (decrypted_request_dict, error_message)
        """
        try:
            with self._session_lock:
                # Get session
                noise_session = self._sessions.get(session_id)
                if noise_session is None:
                    return None, "Session not found or expired"
                
                # Check if handshake is complete
                if not noise_session.is_handshake_complete():
                    return None, "Handshake not completed"
                
                # Decrypt the message
                try:
                    decrypted_json = noise_session.decrypt(encrypted_data)
                except Exception as e:
                    logger.error(f"Decryption failed for session {session_id[:16]}...: {e}")
                    # Clean up failed session
                    del self._sessions[session_id]
                    return None, f"Decryption failed: {str(e)}"
                
                # Parse JSON
                try:
                    request_dict = json.loads(decrypted_json.decode('utf-8'))
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in decrypted message: {e}")
                    # Clean up session
                    del self._sessions[session_id]
                    return None, f"Invalid JSON in encrypted message: {str(e)}"
                
                logger.debug(f"Successfully decrypted call for session {session_id[:16]}...")
                # Note: Session is kept alive for encrypt_response
                return request_dict, None
                
        except Exception as e:
            logger.error(f"Unexpected error in decrypt_call: {e}")
            return None, f"Internal error during decryption: {str(e)}"
    
    def encrypt_response(self, session_id: str, response_dict: Dict) -> Tuple[Optional[bytes], Optional[str]]:
        """
        Encrypt a JSON-RPC response and clean up the session.
        
        Args:
            session_id: Session identifier
            response_dict: JSON-RPC response dictionary
            
        Returns:
            Tuple of (encrypted_response, error_message)
        """
        try:
            with self._session_lock:
                # Get session
                noise_session = self._sessions.get(session_id)
                if noise_session is None:
                    return None, "Session not found or expired"
                
                # Serialize response to JSON
                try:
                    response_json = json.dumps(response_dict).encode('utf-8')
                except (TypeError, ValueError) as e:
                    logger.error(f"Failed to serialize response: {e}")
                    # Clean up session
                    del self._sessions[session_id]
                    return None, f"Failed to serialize response: {str(e)}"
                
                # Encrypt the response
                try:
                    encrypted_response = noise_session.encrypt(response_json)
                except Exception as e:
                    logger.error(f"Encryption failed for session {session_id[:16]}...: {e}")
                    # Clean up session
                    del self._sessions[session_id]
                    return None, f"Encryption failed: {str(e)}"
                
                # Clean up session (single use)
                del self._sessions[session_id]
                
                logger.debug(f"Successfully encrypted response and cleaned up session {session_id[:16]}...")
                return encrypted_response, None
                
        except Exception as e:
            logger.error(f"Unexpected error in encrypt_response: {e}")
            # Try to clean up session
            with self._session_lock:
                self._sessions.pop(session_id, None)
            return None, f"Internal error during encryption: {str(e)}"
    
    def cleanup_expired_sessions(self, max_age_seconds: int = 300):
        """
        Clean up sessions that have been around too long (fallback safety).
        
        Args:
            max_age_seconds: Maximum age for sessions in seconds
        """
        # For now, we don't track creation time, but we could add that
        # Sessions should be short-lived anyway (single use)
        current_count = len(self._sessions)
        if current_count > 100:  # Arbitrary threshold
            logger.warning(f"High number of active sessions: {current_count}")
    
    def get_session_count(self) -> int:
        """Get the current number of active sessions (for monitoring)."""
        with self._session_lock:
            return len(self._sessions)


# Global session manager instance
_session_manager: Optional[NoiseSessionManager] = None


def get_session_manager() -> NoiseSessionManager:
    """Get the global session manager instance, creating it if necessary."""
    global _session_manager
    if _session_manager is None:
        _session_manager = NoiseSessionManager()
    return _session_manager


def initialize_session_manager(server_static_key=None) -> NoiseSessionManager:
    """Initialize the global session manager with a specific key."""
    global _session_manager
    _session_manager = NoiseSessionManager(server_static_key)
    return _session_manager


# Utility functions for session ID generation
def generate_session_id() -> str:
    """Generate a secure random session ID."""
    return base64.b64encode(secrets.token_bytes(16)).decode('ascii')


def validate_session_id(session_id: str) -> bool:
    """Validate that a session ID has the correct format."""
    try:
        if len(session_id) != 24:  # Base64 encoding of 16 bytes
            return False
        decoded = base64.b64decode(session_id)
        return len(decoded) == 16
    except Exception:
        return False


if __name__ == "__main__":
    # Simple test
    import sys
    logging.basicConfig(level=logging.DEBUG)
    
    print("Testing Noise Session Manager...")
    
    # Create session manager
    manager = NoiseSessionManager()
    print(f"Server public key: {manager.get_server_public_key().hex()}")
    
    # Simulate a handshake (this would normally come from a client)
    session_id = generate_session_id()
    print(f"Generated session ID: {session_id}")
    
    # Create a client to test with
    from noise_nk import NoiseNK
    client = NoiseNK(role='initiator', remote_static_key=manager._server_key.public)
    
    # Client creates handshake message
    client_msg = client.write_handshake_message(b"Hello from client")
    print(f"Client handshake message: {len(client_msg)} bytes")
    
    # Server processes handshake
    server_response, error = manager.start_handshake(session_id, client_msg)
    if error:
        print(f"Handshake error: {error}")
        sys.exit(1)
    
    print(f"Server handshake response: {len(server_response)} bytes")
    
    # Client completes handshake
    client_payload = client.read_handshake_message(server_response)
    print(f"Client received: {client_payload}")
    
    # Test encryption/decryption
    test_request = {"jsonrpc": "2.0", "method": "echo", "params": ["test message"], "id": 1}
    encrypted_request = client.encrypt(json.dumps(test_request).encode('utf-8'))
    print(f"Encrypted request: {len(encrypted_request)} bytes")
    
    # Server decrypts
    decrypted_request, error = manager.decrypt_call(session_id, encrypted_request)
    if error:
        print(f"Decryption error: {error}")
        sys.exit(1)
    
    print(f"Decrypted request: {decrypted_request}")
    
    # Server encrypts response
    test_response = {"jsonrpc": "2.0", "result": "test message", "id": 1}
    encrypted_response, error = manager.encrypt_response(session_id, test_response)
    if error:
        print(f"Encryption error: {error}")
        sys.exit(1)
    
    print(f"Encrypted response: {len(encrypted_response)} bytes")
    
    # Client decrypts response
    decrypted_response = client.decrypt(encrypted_response)
    final_response = json.loads(decrypted_response.decode('utf-8'))
    print(f"Final response: {final_response}")
    
    print("✅ Session manager test completed successfully!") 