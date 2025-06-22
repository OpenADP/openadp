#!/usr/bin/env python3
"""
Debug version of NoiseNK client using local debug noise library
"""

import sys
import os

# Import our debug version of the noise library instead of the installed one
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'debug_noise'))

from noise.connection import NoiseConnection
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import json

def generate_keypair():
    """Generate X25519 key pair for Noise protocol"""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Convert to raw bytes (32 bytes each)
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

class DebugNoiseNK:
    """Debug version of NoiseNK using local debug noise library"""
    
    def __init__(self):
        self.noise = None
        self.handshake_complete = False
        
    def initialize_as_initiator(self, responder_static_pubkey):
        """Initialize as initiator with responder's static public key"""
        print(f"🔍 [PYTHON DEBUG] DebugNoiseNK initializing as initiator")
        print(f"🔍 [PYTHON DEBUG] Responder static pubkey: {responder_static_pubkey.hex()}")
        
        from noise.connection import Keypair
        self.noise = NoiseConnection.from_name(b'Noise_NK_25519_AESGCM_SHA256')
        self.noise.set_as_initiator()
        self.noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, responder_static_pubkey)
        self.noise.start_handshake()
        self.handshake_complete = False
        
        print(f"🔍 [PYTHON DEBUG] Initiator initialized")
        print(f"🔍 [PYTHON DEBUG] ---")
        
    def initialize_as_responder(self, static_private_key):
        """Initialize as responder with own static private key"""
        print(f"🔍 [PYTHON DEBUG] DebugNoiseNK initializing as responder")
        print(f"🔍 [PYTHON DEBUG] Static private key: {static_private_key.hex()}")
        
        from noise.connection import Keypair
        self.noise = NoiseConnection.from_name(b'Noise_NK_25519_AESGCM_SHA256')
        self.noise.set_as_responder()
        self.noise.set_keypair_from_private_bytes(Keypair.STATIC, static_private_key)
        self.noise.start_handshake()
        self.handshake_complete = False
        
        print(f"🔍 [PYTHON DEBUG] Responder initialized")
        print(f"🔍 [PYTHON DEBUG] ---")
        
    def write_message(self, payload=b''):
        """Write handshake message"""
        print(f"🔍 [PYTHON DEBUG] write_message called")
        print(f"🔍 [PYTHON DEBUG] Payload: {payload.hex() if payload else '(empty)'}")
        print(f"🔍 [PYTHON DEBUG] Payload length: {len(payload)}")
        
        message = self.noise.write_message(payload)
        
        print(f"🔍 [PYTHON DEBUG] Generated message: {message.hex()}")
        print(f"🔍 [PYTHON DEBUG] Message length: {len(message)}")
        print(f"🔍 [PYTHON DEBUG] Handshake complete: {self.noise.handshake_finished}")
        
        if self.noise.handshake_finished:
            self.handshake_complete = True
            
        print(f"🔍 [PYTHON DEBUG] ---")
        return message
        
    def read_message(self, message):
        """Read handshake message"""
        print(f"🔍 [PYTHON DEBUG] read_message called")
        print(f"🔍 [PYTHON DEBUG] Message: {message.hex()}")
        print(f"🔍 [PYTHON DEBUG] Message length: {len(message)}")
        
        payload = self.noise.read_message(message)
        
        print(f"🔍 [PYTHON DEBUG] Extracted payload: {payload.hex() if payload else '(empty)'}")
        print(f"🔍 [PYTHON DEBUG] Payload length: {len(payload)}")
        print(f"🔍 [PYTHON DEBUG] Handshake complete: {self.noise.handshake_finished}")
        
        if self.noise.handshake_finished:
            self.handshake_complete = True
            
        print(f"🔍 [PYTHON DEBUG] ---")
        return payload
        
    def get_handshake_hash(self):
        """Get current handshake hash"""
        if not self.noise:
            return None
        try:
            return self.noise.noise_protocol.handshake_state.symmetric_state.h
        except:
            return None

def debug_step_by_step():
    """Step-by-step debug comparison with fixed server key"""
    print("🔍 Starting step-by-step debug with local noise library...")
    
    # Use the same server key as JavaScript for comparison
    server_pubkey_hex = "0b6853e9bfa19e74b117ab40d2e1bea675415f15a15c18ef7ec2b02dcf9d1400"
    server_pubkey = bytes.fromhex(server_pubkey_hex)
    
    print(f"📋 Using fixed server public key: {server_pubkey_hex}")
    print()
    
    # Create debug client
    client = DebugNoiseNK()
    client.initialize_as_initiator(server_pubkey)
    
    # Write first message
    print("=== WRITING FIRST MESSAGE ===")
    message1 = client.write_message(b'')
    
    # Get final handshake hash
    final_hash = client.get_handshake_hash()
    if final_hash:
        print(f"🔑 Final Python handshake hash: {final_hash.hex()}")
    else:
        print(f"⚠️ Could not get handshake hash")
    
    print()
    print("=== COMPARISON WITH JAVASCRIPT ===")
    print("Expected JavaScript hash: a7cdbeb46b11401643ec94323123c66922f19d10f899333b20d749dfb8539d6c")
    print(f"Actual Python hash:       {final_hash.hex() if final_hash else 'unknown'}")
    
    if final_hash:
        js_hash = "a7cdbeb46b11401643ec94323123c66922f19d10f899333b20d749dfb8539d6c"
        py_hash = final_hash.hex()
        print(f"Hashes match: {js_hash == py_hash}")

if __name__ == "__main__":
    debug_step_by_step() 