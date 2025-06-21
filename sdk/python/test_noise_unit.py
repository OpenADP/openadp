#!/usr/bin/env python3
"""
Unit test for Noise-NK protocol using noiseprotocol library.
Tests client-server communication with both sides using the same library.
"""

import os
import sys
import threading
import time
import socket
from itertools import cycle

# Add the parent directory to the path so we can import openadp
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from noise.connection import NoiseConnection, Keypair
from openadp.client import generate_keypair


def create_noise_server(server_static_key, port=0):
    """Create a simple Noise-NK server for testing."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', port))
    server_socket.listen(1)
    
    actual_port = server_socket.getsockname()[1]
    print(f"Test server listening on port {actual_port}")
    
    def server_handler():
        try:
            conn, addr = server_socket.accept()
            print(f"Server: Accepted connection from {addr}")
            
            # Create Noise-NK responder
            noise = NoiseConnection.from_name(b'Noise_NK_25519_ChaChaPoly_SHA256')
            noise.set_as_responder()
            
            # Set server's static key
            noise.set_keypair_from_private_bytes(Keypair.STATIC, server_static_key)
            
            # Start handshake
            noise.start_handshake()
            
            # Perform handshake
            for action in cycle(['receive', 'send']):
                if noise.handshake_finished:
                    break
                elif action == 'receive':
                    data = conn.recv(2048)
                    if not data:
                        break
                    print(f"Server: Received {len(data)} bytes")
                    plaintext = noise.read_message(data)
                    print(f"Server: Handshake payload: {plaintext}")
                elif action == 'send':
                    message = noise.write_message(b"server handshake payload")
                    print(f"Server: Sending {len(message)} bytes")
                    conn.sendall(message)
            
            print("Server: Handshake completed")
            
            # Handle one encrypted message
            encrypted_data = conn.recv(2048)
            if encrypted_data:
                decrypted = noise.decrypt(encrypted_data)
                print(f"Server: Decrypted message: {decrypted}")
                
                # Send encrypted response
                response = noise.encrypt(b"Hello from server!")
                conn.sendall(response)
                print("Server: Sent encrypted response")
            
        except Exception as e:
            print(f"Server error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                conn.close()
            except:
                pass
            server_socket.close()
    
    # Start server in background thread
    server_thread = threading.Thread(target=server_handler, daemon=True)
    server_thread.start()
    
    return actual_port, server_thread


def test_noise_nk_communication():
    """Test Noise-NK communication between Python client and server."""
    print("=== Testing Noise-NK Communication ===")
    
    # Generate server static key pair
    server_private_key, server_public_key = generate_keypair()
    print(f"Server public key: {server_public_key.hex()}")
    
    # Start test server
    server_port, server_thread = create_noise_server(server_private_key)
    
    # Give server time to start
    time.sleep(0.1)
    
    try:
        # Create client connection
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', server_port))
        print("Client: Connected to server")
        
        # Create Noise-NK initiator
        noise = NoiseConnection.from_name(b'Noise_NK_25519_ChaChaPoly_SHA256')
        noise.set_as_initiator()
        
        # Set remote static key (server's public key)
        noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, server_public_key)
        
        # Start handshake
        noise.start_handshake()
        
        # Perform handshake
        for action in cycle(['send', 'receive']):
            if noise.handshake_finished:
                break
            elif action == 'send':
                message = noise.write_message(b"client handshake payload")
                print(f"Client: Sending {len(message)} bytes")
                client_socket.sendall(message)
            elif action == 'receive':
                data = client_socket.recv(2048)
                if not data:
                    break
                print(f"Client: Received {len(data)} bytes")
                plaintext = noise.read_message(data)
                print(f"Client: Handshake payload: {plaintext}")
        
        print("Client: Handshake completed")
        
        # Send encrypted message
        encrypted_message = noise.encrypt(b"Hello from client!")
        client_socket.sendall(encrypted_message)
        print("Client: Sent encrypted message")
        
        # Receive encrypted response
        encrypted_response = client_socket.recv(2048)
        if encrypted_response:
            decrypted_response = noise.decrypt(encrypted_response)
            print(f"Client: Decrypted response: {decrypted_response}")
        
        print("✅ Noise-NK communication test PASSED")
        return True
        
    except Exception as e:
        print(f"❌ Client error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        try:
            client_socket.close()
        except:
            pass


if __name__ == "__main__":
    success = test_noise_nk_communication()
    if success:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n💥 Tests failed!")
        sys.exit(1) 