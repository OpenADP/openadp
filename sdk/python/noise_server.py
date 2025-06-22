#!/usr/bin/env python3
"""
Noise-NK TCP Server

A Python server that uses Noise-NK protocol for secure communication.
This server will accept connections from JavaScript clients and demonstrate
cross-platform compatibility.
"""

import sys
import os
import socket
import threading
import json
import time
from typing import Optional

# Add Python SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'openadp'))

from openadp.client import NoiseNK, generate_keypair

class NoiseNKServer:
    """TCP server using Noise-NK protocol for secure communication."""
    
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
        # Generate server static key pair
        self.server_private, self.server_public = generate_keypair()
        
        print(f"🔐 Server static public key: {self.server_public.hex()}")
        print(f"🔐 Clients should use this key to connect")
        
    def start(self):
        """Start the server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"🚀 Noise-NK server listening on {self.host}:{self.port}")
            print(f"📡 Waiting for JavaScript clients...")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"📞 New connection from {address}")
                    
                    # Handle client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        print(f"❌ Socket error: {e}")
                    break
                    
        except Exception as e:
            print(f"❌ Server error: {e}")
        finally:
            self.stop()
    
    def handle_client(self, client_socket: socket.socket, address):
        """Handle a client connection with Noise-NK protocol."""
        try:
            print(f"🔒 Starting Noise-NK handshake with {address}")
            
            # Debug: Print the server's static key info
            print(f"🔑 Server private key: {self.server_private.hex()}")
            print(f"🔑 Server public key: {self.server_public.hex()}")
            
            # Initialize Noise-NK as responder
            noise = NoiseNK()
            noise.initialize_as_responder(self.server_private)
            
            # Debug: Check what key the noise instance is actually using
            try:
                # Let's see if we can get the static key from the noise instance
                if hasattr(noise.noise, 'handshake_state') and hasattr(noise.noise.handshake_state, 's'):
                    actual_key = noise.noise.handshake_state.s.public_bytes
                    print(f"🔍 Noise library is using static public key: {actual_key.hex()}")
                else:
                    print(f"🔍 Cannot inspect noise library's static key")
            except Exception as debug_e:
                print(f"🔍 Debug error: {debug_e}")
            
            # Receive first handshake message from client
            message1_data = self.receive_message(client_socket)
            if not message1_data:
                print(f"❌ Failed to receive handshake message 1 from {address}")
                return
                
            print(f"📨 Received handshake message 1: {len(message1_data)} bytes")
            print(f"🔍 Raw message 1 hex: {message1_data.hex()}")
            
            # Print handshake hash before reading first message (to compare with JS)
            try:
                hash_before = noise.get_handshake_hash()
                print(f"🔑 Python handshake hash BEFORE reading message 1: {hash_before.hex()}")
            except Exception as hash_e:
                print(f"⚠️ Could not get handshake hash before message 1: {hash_e}")
            
            # Process first handshake message
            try:
                payload1 = noise.read_message(message1_data)
                print(f"📝 Client payload 1: {payload1}")
                
                # Print handshake hash after reading first message
                try:
                    hash1 = noise.get_handshake_hash()
                    print(f"🔑 Python handshake hash AFTER reading message 1: {hash1.hex()}")
                except Exception as hash_e:
                    print(f"⚠️ Could not get handshake hash after message 1: {hash_e}")
            except Exception as e:
                print(f"❌ Failed to process handshake message 1: {e}")
                print(f"🔍 This might be due to payload encryption mismatch")
                import traceback
                traceback.print_exc()
                return
            
            # Send second handshake message (no payload to avoid AES-GCM issues)
            message2 = noise.write_message()
            
            if not self.send_message(client_socket, message2):
                print(f"❌ Failed to send handshake message 2 to {address}")
                return
                
            print(f"📤 Sent handshake message 2: {len(message2)} bytes")
            
            if not noise.handshake_complete:
                print(f"❌ Handshake not complete after message 2")
                return
                
            # Print final handshake hash
            try:
                final_hash = noise.get_handshake_hash()
                print(f"🔑 Python final handshake hash: {final_hash.hex()}")
            except Exception as hash_e:
                print(f"⚠️ Could not get final handshake hash: {hash_e}")
                
            print(f"✅ Noise-NK handshake completed with {address}")
            
            # Now handle secure messages
            self.handle_secure_communication(client_socket, address, noise)
            
        except Exception as e:
            print(f"❌ Error handling client {address}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            client_socket.close()
            print(f"🔌 Disconnected from {address}")
    
    def handle_secure_communication(self, client_socket: socket.socket, address, noise: NoiseNK):
        """Handle secure communication after handshake completion."""
        print(f"🔐 Secure channel established with {address}")
        
        try:
            while True:
                # Receive encrypted message from client
                encrypted_data = self.receive_message(client_socket)
                if not encrypted_data:
                    print(f"📡 Client {address} disconnected")
                    break
                
                # Decrypt message
                try:
                    plaintext = noise.decrypt(encrypted_data)
                    if plaintext is None:
                        print(f"❌ Decryption returned None from {address}")
                        break
                    
                    message = plaintext.decode('utf-8')
                    print(f"📨 Received from {address}: {message}")
                    
                    # Send encrypted response
                    response = f"Echo: {message} (from Python server)"
                    encrypted_response = noise.encrypt(response.encode('utf-8'))
                    
                    if self.send_message(client_socket, encrypted_response):
                        print(f"📤 Sent response to {address}: {response}")
                    else:
                        print(f"❌ Failed to send response to {address}")
                        break
                        
                except Exception as e:
                    print(f"❌ Error processing encrypted message from {address}: {e}")
                    import traceback
                    traceback.print_exc()
                    break
                    
        except Exception as e:
            print(f"❌ Error in secure communication with {address}: {e}")
    
    def send_message(self, sock: socket.socket, data: bytes) -> bool:
        """Send a message with length prefix."""
        try:
            # Send length first (4 bytes, big-endian)
            length = len(data)
            length_bytes = length.to_bytes(4, 'big')
            sock.sendall(length_bytes)
            
            # Send data
            sock.sendall(data)
            return True
        except Exception as e:
            print(f"❌ Send error: {e}")
            return False
    
    def receive_message(self, sock: socket.socket) -> Optional[bytes]:
        """Receive a message with length prefix."""
        try:
            # Receive length first (4 bytes, big-endian)
            length_bytes = self.receive_exact(sock, 4)
            if not length_bytes:
                return None
                
            length = int.from_bytes(length_bytes, 'big')
            
            # Receive data
            data = self.receive_exact(sock, length)
            return data
            
        except Exception as e:
            print(f"❌ Receive error: {e}")
            return None
    
    def receive_exact(self, sock: socket.socket, length: int) -> Optional[bytes]:
        """Receive exactly the specified number of bytes."""
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("🛑 Server stopped")
    
    def get_server_info(self) -> dict:
        """Get server information for clients."""
        return {
            "host": self.host,
            "port": self.port,
            "public_key": self.server_public.hex(),
            "protocol": "Noise_NK_25519_AESGCM_SHA256"
        }

def main():
    """Run the Noise-NK server."""
    print("🔐 Noise-NK TCP Server")
    print("=====================")
    
    server = NoiseNKServer()
    
    # Save server info for clients
    server_info = server.get_server_info()
    with open('server_info.json', 'w') as f:
        json.dump(server_info, f, indent=2)
    
    print(f"💾 Server info saved to server_info.json")
    print(f"📋 Server info: {json.dumps(server_info, indent=2)}")
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down server...")
        server.stop()

if __name__ == "__main__":
    main() 
