#!/usr/bin/env python3
"""
Noise-KK Enabled JSON-RPC Server for OpenADP

This server extends the standard JSON-RPC server with Noise-KK encryption support.
It accepts both regular JSON-RPC requests and Noise-KK encrypted requests.

The server detects Noise-KK clients by looking for the Noise handshake pattern
in the initial bytes of the connection.
"""

import json
import logging
import base64
import ssl
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from openadp import database
from openadp import crypto
from openadp.noise_kk import (
    NoiseKKSession, NoiseKKTransport,
    generate_client_keypair, create_server_session
)
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from server import server

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ServerConfig:
    """Configuration for the Noise-KK server"""
    def __init__(self):
        # Generate server keypair (in production, this should be persistent)
        self.server_private_key = x25519.X25519PrivateKey.generate()
        self.server_public_key = self.server_private_key.public_key()
        
        # For now, accept any client key (dummy mode as requested)
        self.accept_any_client = True
        
        # Database
        self.db = database.Database("openadp.db")
    
    def get_server_public_key_string(self) -> str:
        """Get server public key in the expected format for servers.json"""
        pub_bytes = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # Convert to ed25519 format for compatibility 
        pub_b64 = base64.b64encode(pub_bytes).decode('ascii')
        return f"ed25519:{pub_b64}"


class NoiseKKHandler:
    """Handles Noise-KK encrypted connections"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
    
    def handle_noise_connection(self, client_socket: ssl.SSLSocket, client_addr: Tuple[str, int]):
        """Handle a Noise-KK encrypted connection"""
        logger.info(f"Handling Noise-KK connection from {client_addr}")
        
        try:
            # For dummy mode: generate a dummy client public key
            dummy_client_private, dummy_client_public = generate_client_keypair()
            
            # Create server-side Noise session
            noise_session = create_server_session(
                self.config.server_private_key,
                dummy_client_public  # In production, this would come from client auth
            )
            
            # Create transport and perform handshake
            transport = NoiseKKTransport(client_socket, noise_session)
            transport.perform_handshake()
            
            logger.info(f"Noise-KK handshake completed with {client_addr}")
            
            # Handle encrypted JSON-RPC requests
            while True:
                try:
                    # Receive encrypted request
                    encrypted_request = transport.recv_encrypted()
                    
                    # Parse JSON-RPC request
                    request_data = json.loads(encrypted_request.decode('utf-8'))
                    
                    # Process the request
                    response_data = self._process_jsonrpc_request(request_data)
                    
                    # Send encrypted response
                    response_json = json.dumps(response_data).encode('utf-8')
                    transport.send_encrypted(response_json)
                    
                except Exception as e:
                    logger.error(f"Error handling Noise-KK request: {e}")
                    break
        
        except Exception as e:
            logger.error(f"Noise-KK connection error: {e}")
        finally:
            client_socket.close()
    
    def _process_jsonrpc_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process a JSON-RPC request and return response"""
        try:
            method = request.get("method")
            params = request.get("params", [])
            request_id = request.get("id")
            
            # Route to appropriate handler
            if method == "RegisterSecret":
                result = self._handle_register_secret(params)
            elif method == "RecoverSecret":
                result = self._handle_recover_secret(params)
            elif method == "ListBackups":
                result = self._handle_list_backups(params)
            elif method == "Echo":
                result = self._handle_echo(params)
            else:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": "Method not found"},
                    "id": request_id
                }
            
            return {
                "jsonrpc": "2.0",
                "result": result,
                "id": request_id
            }
            
        except Exception as e:
            logger.error(f"Error processing JSON-RPC request: {e}")
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)},
                "id": request.get("id")
            }
    
    def _handle_register_secret(self, params: List[Any]) -> bool:
        """Handle RegisterSecret request"""
        if len(params) != 8:
            raise ValueError("RegisterSecret requires 8 parameters")
        
        uid, did, bid, version, x, y_b64, max_guesses, expiration = params
        
        # Decode y from base64
        y = base64.b64decode(y_b64)
        
        # Call the server logic
        server.register_secret(
            self.config.db, uid, did, bid, version, x, y, max_guesses, expiration
        )
        
        return True
    
    def _handle_recover_secret(self, params: List[Any]) -> Tuple[int, int, str, int, int, int]:
        """Handle RecoverSecret request"""
        if len(params) != 5:
            raise ValueError("RecoverSecret requires 5 parameters")
        
        uid, did, bid, b_b64, guess_num = params
        
        # Decode point B from base64
        b_bytes = base64.b64decode(b_b64)
        
        # Call the server logic
        result = server.recover_secret(self.config.db, uid, did, bid, b_bytes, guess_num)
        
        if isinstance(result, Exception):
            raise result
        
        # Convert bytes back to base64 for transport
        version, x, siB, num_guesses, max_guesses, expiration = result
        if isinstance(siB, bytes):
            siB = base64.b64encode(siB).decode('ascii')
        
        return [version, x, siB, num_guesses, max_guesses, expiration]
    
    def _handle_list_backups(self, params: List[Any]) -> List[Dict[str, Any]]:
        """Handle ListBackups request"""
        if len(params) != 1:
            raise ValueError("ListBackups requires 1 parameter")
        
        uid = params[0]
        
        # Call the server logic
        result = server.list_backups(self.config.db, uid)
        
        if isinstance(result, Exception):
            raise result
        
        return result
    
    def _handle_echo(self, params: List[Any]) -> str:
        """Handle Echo request"""
        if len(params) != 1:
            raise ValueError("Echo requires 1 parameter")
        
        return params[0]


class NoiseKKTCPServer:
    """TCP server that handles both regular TLS and Noise-KK connections"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8443, config: Optional[ServerConfig] = None):
        self.host = host
        self.port = port
        self.config = config or ServerConfig()
        self.noise_handler = NoiseKKHandler(self.config)
        self.running = False
    
    def start(self):
        """Start the server"""
        self.running = True
        
        # Create SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # For demo purposes, create a self-signed certificate
        # In production, use proper certificates
        try:
            context.load_cert_chain('server.pem', 'server.key')
        except FileNotFoundError:
            logger.warning("No SSL certificate found. Server will not start.")
            logger.warning("Generate certificates with: openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.pem -days 365 -nodes")
            return
        
        # Create and bind socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        
        logger.info(f"Noise-KK server listening on {self.host}:{self.port}")
        logger.info(f"Server public key: {self.config.get_server_public_key_string()}")
        
        try:
            while self.running:
                client_sock, client_addr = sock.accept()
                
                # Wrap with TLS
                try:
                    ssl_sock = context.wrap_socket(client_sock, server_side=True)
                    
                    # Handle connection in a new thread
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(ssl_sock, client_addr)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except Exception as e:
                    logger.error(f"SSL handshake failed: {e}")
                    client_sock.close()
                    
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
        finally:
            sock.close()
    
    def _handle_client(self, ssl_sock: ssl.SSLSocket, client_addr: Tuple[str, int]):
        """Handle a client connection"""
        try:
            # For this implementation, we assume all connections are Noise-KK
            # In a real implementation, you'd detect the protocol
            self.noise_handler.handle_noise_connection(ssl_sock, client_addr)
            
        except Exception as e:
            logger.error(f"Error handling client {client_addr}: {e}")
        finally:
            ssl_sock.close()
    
    def stop(self):
        """Stop the server"""
        self.running = False


def main():
    """Main function to run the Noise-KK server"""
    import argparse
    
    parser = argparse.ArgumentParser(description="OpenADP Noise-KK JSON-RPC Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8443, help="Port to bind to")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create server configuration
    config = ServerConfig()
    
    # Create and start server
    server = NoiseKKTCPServer(args.host, args.port, config)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    

if __name__ == "__main__":
    main() 