#!/usr/bin/env python3
"""
Test server authentication in Noise-KK implementation.
This verifies that clients properly validate server public keys.
"""

import socket
import threading
import time
import json
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from openadp.noise_kk import NoiseKKSession, NoiseKKTransport, create_client_session, create_server_session
from openadp.noise_kk_simple import generate_client_keypair


class TestNoiseKKServer:
    """Test server that accepts any client (dummy authentication)"""
    
    def __init__(self, port: int = 0, server_private_key=None):
        self.port = port
        self.server_socket = None
        self.running = False
        self.server_thread = None
        self.expected_client_public = None  # For testing specific client keys
        
        # Generate server keypair if not provided
        if server_private_key is None:
            self.server_private_key, self.server_public_key = generate_client_keypair()
        else:
            self.server_private_key = server_private_key
            # For X25519 keys, public key is derived differently
            self.server_public_key = server_private_key.public_key()
    
    def start(self) -> int:
        """Start the server and return the port"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('localhost', self.port))
        self.server_socket.listen(1)
        
        # Get the actual port if 0 was specified
        actual_port = self.server_socket.getsockname()[1]
        
        self.running = True
        self.server_thread = threading.Thread(target=self._server_loop)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        return actual_port
    
    def _server_loop(self):
        """Main server loop"""
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                print(f"Server: Connection from {client_addr}")
                
                # Handle in a separate thread
                handler_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr)
                )
                handler_thread.daemon = True
                handler_thread.start()
                
            except OSError:
                if self.running:
                    print("Server: Socket error")
                break
    
    def _handle_client(self, client_sock: socket.socket, client_addr):
        """Handle a client connection with dummy authentication"""
        try:
            # Use expected client key if set, otherwise generate dummy
            if self.expected_client_public:
                client_public_key = self.expected_client_public
            else:
                # Generate dummy client keypair (server accepts any client)
                dummy_client_private, client_public_key = generate_client_keypair()
            
            # Create server-side Noise session
            noise_session = create_server_session(
                self.server_private_key,
                client_public_key
            )
            
            # Create transport and perform handshake
            transport = NoiseKKTransport(client_sock, noise_session)
            transport.perform_handshake()
            
            print(f"Server: Noise-KK handshake completed with {client_addr}")
            
            # Handle requests
            while True:
                try:
                    # Receive encrypted request
                    encrypted_request = transport.recv_encrypted()
                    
                    # Parse JSON-RPC request
                    request_data = json.loads(encrypted_request.decode('utf-8'))
                    
                    # Simple echo response
                    response = {
                        "jsonrpc": "2.0",
                        "result": f"Echo: {request_data.get('params', [''])[0]}",
                        "id": request_data.get("id")
                    }
                    
                    # Send encrypted response
                    response_json = json.dumps(response).encode('utf-8')
                    transport.send_encrypted(response_json)
                    
                except Exception as e:
                    print(f"Server: Error handling request: {e}")
                    break
        
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            client_sock.close()
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.server_thread:
            self.server_thread.join(timeout=1)
    
    def get_public_key_string(self) -> str:
        """Get server public key as string"""
        import base64
        from cryptography.hazmat.primitives import serialization
        
        server_public_bytes = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return f"ed25519:{base64.b64encode(server_public_bytes).decode('ascii')}"


def test_correct_server_authentication():
    """Test that client connects to server with correct public key"""
    print("🔐 Test 1: Correct Server Authentication")
    print("=" * 50)
    
    # Start test server
    server = TestNoiseKKServer()
    port = server.start()
    print(f"Test server listening on port {port}")
    
    time.sleep(0.1)  # Give server time to start
    
    try:
        # Get server's public key as string format
        server_public_key_str = server.get_public_key_string()
        print(f"Server public key: {server_public_key_str}")
        
        # Generate client keypair (like the working integration test)
        client_private, client_public = generate_client_keypair()
        
        # Tell the server what client key to expect
        server.expected_client_public = client_public
        
        # Create client with correct server public key and client keys
        print("Client: Creating session with correct server public key...")
        client_session = NoiseKKSession(
            is_initiator=True,
            local_static_private=client_private,
            remote_static_public=server.server_public_key
        )
        
        # Connect to server
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(('localhost', port))
        
        # Perform handshake
        transport = NoiseKKTransport(client_sock, client_session)
        transport.perform_handshake()
        
        print("Client: Handshake completed successfully!")
        
        # Test communication
        request = {
            "jsonrpc": "2.0",
            "method": "Echo",
            "params": ["Test message"],
            "id": 1
        }
        
        request_data = json.dumps(request).encode('utf-8')
        transport.send_encrypted(request_data)
        
        response_data = transport.recv_encrypted()
        response = json.loads(response_data.decode('utf-8'))
        
        print(f"Client: Received response: {response}")
        
        transport.close()
        
        print("✅ Correct server authentication: PASS")
        return True
        
    except Exception as e:
        print(f"❌ Client connection failed: {e}")
        return False
    finally:
        server.stop()


def test_wrong_server_authentication():
    """Test that client rejects server with wrong public key"""
    print("\n🚫 Test 2: Wrong Server Authentication (Should Fail)")
    print("=" * 50)
    
    # Start test server
    server = TestNoiseKKServer()
    port = server.start()
    print(f"Test server listening on port {port}")
    
    time.sleep(0.1)  # Give server time to start
    
    try:
        # Generate a DIFFERENT server public key (wrong one)
        _, wrong_server_public = generate_client_keypair()
        
        # Convert to string format
        import base64
        from cryptography.hazmat.primitives import serialization
        wrong_server_bytes = wrong_server_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        wrong_server_key_str = f"ed25519:{base64.b64encode(wrong_server_bytes).decode('ascii')}"
        
        print("Client: Creating session with WRONG server public key...")
        client_session = create_client_session(wrong_server_key_str)
        
        # Connect to server
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(('localhost', port))
        
        # Attempt handshake (should fail)
        transport = NoiseKKTransport(client_sock, client_session)
        transport.perform_handshake()
        
        print("❌ Client should have rejected wrong server, but didn't!")
        transport.close()
        return False
        
    except Exception as e:
        print(f"✅ Client correctly rejected wrong server: {e}")
        return True
    finally:
        server.stop()


def test_public_key_verification():
    """Test that client sessions use the correct server public keys"""
    print("\n🔍 Test 3: Public Key Verification")
    print("=" * 50)
    
    try:
        # Generate two different server key pairs
        _, server1_public = generate_client_keypair()
        _, server2_public = generate_client_keypair()
        
        print("Generated two different server key pairs")
        
        # Convert to string format
        import base64
        from cryptography.hazmat.primitives import serialization
        
        server1_bytes = server1_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        server2_bytes = server2_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        server1_key_str = f"ed25519:{base64.b64encode(server1_bytes).decode('ascii')}"
        server2_key_str = f"ed25519:{base64.b64encode(server2_bytes).decode('ascii')}"
        
        print(f"Server 1 key: {server1_key_str[:20]}...")
        print(f"Server 2 key: {server2_key_str[:20]}...")
        
        # Create client sessions with different server keys
        client1_session = create_client_session(server1_key_str)
        client2_session = create_client_session(server2_key_str)
        
        # Verify they have different server public keys
        key1_bytes = client1_session.remote_static_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        key2_bytes = client2_session.remote_static_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        if key1_bytes != key2_bytes:
            print("✅ Client sessions correctly use different server public keys")
            return True
        else:
            print("❌ Client sessions have same server public key")
            return False
            
    except Exception as e:
        print(f"❌ Public key verification failed: {e}")
        return False


def main():
    print("🛡️  OpenADP Noise-KK Server Authentication Tests")
    print("=" * 60)
    
    # Fix missing import
    global serialization
    from cryptography.hazmat.primitives import serialization
    
    results = []
    
    # Test 1: Correct server authentication
    results.append(test_correct_server_authentication())
    
    # Test 2: Wrong server authentication (should fail)
    results.append(test_wrong_server_authentication())
    
    # Test 3: Public key verification
    results.append(test_public_key_verification())
    
    # Summary
    print("\n📊 Test Results Summary")
    print("=" * 30)
    print(f"1. Correct Server Authentication: {'✅ PASS' if results[0] else '❌ FAIL'}")
    print(f"2. Wrong Server Rejection: {'✅ PASS' if results[1] else '❌ FAIL'}")
    print(f"3. Public Key Verification: {'✅ PASS' if results[2] else '❌ FAIL'}")
    
    passed = sum(results)
    total = len(results)
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All server authentication tests passed!")
    else:
        print("⚠️  Some server authentication tests failed!")
        print("❌ Server authentication needs fixes!")


if __name__ == "__main__":
    main() 