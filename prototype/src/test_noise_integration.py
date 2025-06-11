#!/usr/bin/env python3
"""
Test script for OpenADP Noise-KK integration

This script demonstrates the complete Noise-KK integration by:
1. Starting a test server with Noise-KK support
2. Creating a client that connects with Noise-KK
3. Testing the encrypted communication
"""

import time
import threading
import socket
import ssl
import tempfile
import os
from typing import Optional

from openadp.noise_kk_simple import SimplifiedNoiseKK, NoiseKKTransport, generate_client_keypair
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import json


class SimpleNoiseKKServer:
    """Simple test server for Noise-KK"""
    
    def __init__(self, port: int = 0):
        self.port = port
        self.server_socket = None
        self.running = False
        
        # Generate server keypair
        self.server_private = x25519.X25519PrivateKey.generate()
        self.server_public = self.server_private.public_key()
        
    def start(self) -> int:
        """Start the server and return the actual port"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('localhost', self.port))
        self.server_socket.listen(1)
        
        # Get actual port if we used 0
        actual_port = self.server_socket.getsockname()[1]
        self.port = actual_port
        
        self.running = True
        self.server_thread = threading.Thread(target=self._server_loop)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        return actual_port
    
    def _server_loop(self):
        """Main server loop"""
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                print(f"Server: Connection from {addr}")
                
                # Handle in a separate thread
                thread = threading.Thread(target=self._handle_client, args=(client_sock,))
                thread.daemon = True
                thread.start()
                
            except Exception as e:
                if self.running:
                    print(f"Server error: {e}")
                break
    
    def _handle_client(self, client_sock: socket.socket):
        """Handle a client connection"""
        try:
            # For demo: We need to know the client's public key
            # In the test, we'll use a shared reference
            if hasattr(self, 'expected_client_public'):
                client_public = self.expected_client_public
            else:
                # Fallback: generate dummy key
                dummy_client_private, client_public = generate_client_keypair()
            
            # Create server-side Noise session
            noise_session = SimplifiedNoiseKK(
                is_initiator=False,
                local_static_private=self.server_private,
                remote_static_public=client_public
            )
            
            # Create transport and perform handshake
            transport = NoiseKKTransport(client_sock, noise_session)
            transport.perform_handshake()
            
            print("Server: Noise-KK handshake completed")
            
            # Echo server - receive message and send it back
            while True:
                try:
                    request_data = transport.recv_encrypted()
                    request = json.loads(request_data.decode('utf-8'))
                    
                    print(f"Server: Received request: {request}")
                    
                    # Simple echo response
                    if request.get("method") == "Echo":
                        response = {
                            "jsonrpc": "2.0",
                            "result": request["params"][0],
                            "id": request["id"]
                        }
                    else:
                        response = {
                            "jsonrpc": "2.0",
                            "error": {"code": -32601, "message": "Method not found"},
                            "id": request.get("id")
                        }
                    
                    response_data = json.dumps(response).encode('utf-8')
                    transport.send_encrypted(response_data)
                    
                except Exception as e:
                    print(f"Server: Error handling request: {e}")
                    break
                    
        except Exception as e:
            print(f"Server: Error handling client: {e}")
        finally:
            client_sock.close()
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
    
    def get_public_key_string(self) -> str:
        """Get public key in servers.json format"""
        import base64
        pub_bytes = self.server_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pub_b64 = base64.b64encode(pub_bytes).decode('ascii')
        return f"ed25519:{pub_b64}"


def test_noise_kk_integration():
    """Test the complete Noise-KK integration"""
    print("🔧 Testing OpenADP Noise-KK Integration")
    print("=" * 50)
    
    # Start test server
    print("1. Starting test server...")
    server = SimpleNoiseKKServer()
    port = server.start()
    print(f"   ✅ Server started on port {port}")
    
    time.sleep(0.1)  # Give server time to start
    
    try:
        # Create client
        print("2. Creating Noise-KK client...")
        server_public_key = server.get_public_key_string()
        print(f"   Server public key: {server_public_key}")
        
        # Generate client keypair
        client_private, client_public = generate_client_keypair()
        
        # Tell the server what client key to expect
        server.expected_client_public = client_public
        
        # Create client-side Noise session
        client_session = SimplifiedNoiseKK(
            is_initiator=True,
            local_static_private=client_private,
            remote_static_public=server.server_public
        )
        
        # Connect to server
        print("3. Connecting to server...")
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(('localhost', port))
        
        # Create transport and perform handshake
        client_transport = NoiseKKTransport(client_sock, client_session)
        client_transport.perform_handshake()
        print("   ✅ Noise-KK handshake completed")
        
        # Test encrypted communication
        print("4. Testing encrypted communication...")
        
        test_message = "Hello, Noise-KK World! 🚀"
        request = {
            "jsonrpc": "2.0",
            "method": "Echo",
            "params": [test_message],
            "id": 1
        }
        
        # Send encrypted request
        request_data = json.dumps(request).encode('utf-8')
        client_transport.send_encrypted(request_data)
        print(f"   📤 Sent: {test_message}")
        
        # Receive encrypted response
        response_data = client_transport.recv_encrypted()
        response = json.loads(response_data.decode('utf-8'))
        print(f"   📥 Received: {response}")
        
        # Verify response
        if response.get("result") == test_message:
            print("   ✅ Encrypted communication successful!")
        else:
            print("   ❌ Communication failed!")
            return False
        
        # Test multiple messages
        print("5. Testing multiple encrypted messages...")
        for i in range(3):
            test_msg = f"Message #{i+1}"
            request = {
                "jsonrpc": "2.0",
                "method": "Echo", 
                "params": [test_msg],
                "id": i+2
            }
            
            request_data = json.dumps(request).encode('utf-8')
            client_transport.send_encrypted(request_data)
            
            response_data = client_transport.recv_encrypted()
            response = json.loads(response_data.decode('utf-8'))
            
            if response.get("result") == test_msg:
                print(f"   ✅ Message {i+1}: OK")
            else:
                print(f"   ❌ Message {i+1}: Failed")
                return False
        
        client_transport.close()
        print("6. ✅ All tests passed!")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        print("7. Cleaning up...")
        server.stop()
        print("   ✅ Server stopped")


def test_noise_kk_security_properties():
    """Test the security properties of Noise-KK"""
    print("\n🔒 Testing Noise-KK Security Properties")
    print("=" * 50)
    
    try:
        # Generate keys for Alice and Bob
        alice_private, alice_public = generate_client_keypair()
        bob_private, bob_public = generate_client_keypair()
        
        print("1. Testing mutual authentication...")
        
        # Create sessions
        alice_session = SimplifiedNoiseKK(True, alice_private, bob_public)
        bob_session = SimplifiedNoiseKK(False, bob_private, alice_public)
        
        # Perform handshake
        msg1 = alice_session.start_handshake()
        msg2, complete_bob = bob_session.process_handshake_message(msg1)
        _, complete_alice = alice_session.process_handshake_message(msg2)
        
        if complete_alice and complete_bob:
            print("   ✅ Mutual authentication successful")
        else:
            print("   ❌ Mutual authentication failed")
            return False
        
        print("2. Testing forward secrecy...")
        # Each session should have different ephemeral keys
        alice_session2 = SimplifiedNoiseKK(True, alice_private, bob_public)
        bob_session2 = SimplifiedNoiseKK(False, bob_private, alice_public)
        
        msg1_2 = alice_session2.start_handshake()
        # The ephemeral components should be different
        if msg1 != msg1_2:
            print("   ✅ Forward secrecy: Different ephemeral keys")
        else:
            print("   ❌ Forward secrecy: Same ephemeral keys")
            return False
        
        print("3. Testing encryption/decryption...")
        test_data = b"Secret message for testing encryption"
        
        # Encrypt with Alice, decrypt with Bob
        encrypted = alice_session.encrypt(test_data)
        decrypted = bob_session.decrypt(encrypted)
        
        if decrypted == test_data:
            print("   ✅ Encryption/decryption successful")
        else:
            print("   ❌ Encryption/decryption failed")
            return False
        
        print("4. Testing nonce progression...")
        # Multiple messages should use different nonces
        msg1_enc = alice_session.encrypt(b"Message 1")
        msg2_enc = alice_session.encrypt(b"Message 2")
        
        if msg1_enc != msg2_enc:
            print("   ✅ Nonce progression working")
        else:
            print("   ❌ Nonce progression not working")
            return False
        
        print("5. ✅ All security tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Security test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("🎯 OpenADP Noise-KK Integration Tests")
    print("=" * 60)
    
    success = True
    
    # Test basic integration
    if not test_noise_kk_integration():
        success = False
    
    # Test security properties
    if not test_noise_kk_security_properties():
        success = False
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 All tests passed! Noise-KK integration is working correctly.")
        print("\nNext steps:")
        print("- Update client code to use Noise-KK by default")
        print("- Deploy servers with Noise-KK support")
        print("- Update servers.json with server public keys")
    else:
        print("❌ Some tests failed. Please check the implementation.")
    
    print("=" * 60) 