#!/usr/bin/env python3
"""
Noise-KK Enabled JSON-RPC Server for OpenADP (HTTP Version)

This server provides JSON-RPC over HTTP with optional Noise-KK encryption.
It's designed to work with Cloudflare reverse proxy setups.

The server accepts HTTP POST requests with JSON-RPC payloads and handles:
- noise-handshake: Noise-KK handshake initiation
- noise-data: Encrypted JSON-RPC requests (inner layer)
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
from openadp.noise_kk_simple import (
    generate_dummy_client_keypair, create_server_session
)
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from server import server

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ServerConfig:
    """Server configuration with persistent key storage"""
    
    def __init__(self):
        # Database
        self.db = database.Database("openadp.db")
        
        # Load or generate server keypair (persistent)
        self.server_private_key = self._load_or_generate_keypair()
        
        # Compute public key from private key
        self.server_public_key = self.server_private_key.public_key()
    
    def _load_or_generate_keypair(self):
        """Load persistent server keypair from database or generate new one"""
        key_id = "noise_kk_server_key"
        
        # Try to load existing key from database
        stored_key = self.db.get_server_key(key_id)
        if stored_key:
            try:
                # Deserialize private key from stored bytes
                private_key = x25519.X25519PrivateKey.from_private_bytes(stored_key)
                logger.info(f"Loaded persistent server key from database")
                return private_key
            except Exception as e:
                logger.warning(f"Failed to load stored key: {e}")
                # Fall through to generate new key
        
        # Generate new keypair and store it
        logger.info("Generating new server keypair...")
        return self._generate_and_store_new_key(key_id)
    
    def _generate_and_store_new_key(self, key_id: str):
        """Generate new keypair and store in database"""
        # Generate new X25519 private key
        private_key = x25519.X25519PrivateKey.generate()
        
        # Serialize to bytes for storage
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Store in database
        self.db.store_server_key(key_id, private_bytes)
        
        logger.info(f"Generated and stored new server keypair")
        return private_key
    
    def get_server_public_key_string(self) -> str:
        """Get public key in servers.json format"""
        pub_bytes = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pub_b64 = base64.b64encode(pub_bytes).decode('ascii')
        return f"ed25519:{pub_b64}"


class NoiseKKHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler with Noise-KK support"""
    
    def __init__(self, config: ServerConfig, *args, **kwargs):
        self.config = config
        self.noise_sessions = {}  # Track noise sessions by client
        
        # Generate a consistent dummy client key for all connections
        # In production, this would be replaced with proper client authentication
        self.dummy_client_private, self.dummy_client_public = generate_dummy_client_keypair()
        
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.info(f"{self.address_string()} - {format % args}")
    
    def do_POST(self):
        """Handle POST requests with JSON-RPC"""
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "Empty request body")
                return
            
            request_body = self.rfile.read(content_length)
            
            # Parse JSON-RPC request
            try:
                jsonrpc_request = json.loads(request_body.decode('utf-8'))
            except json.JSONDecodeError as e:
                self.send_error(400, f"Invalid JSON: {e}")
                return
            
            # Validate JSON-RPC format
            if not isinstance(jsonrpc_request, dict) or jsonrpc_request.get("jsonrpc") != "2.0":
                self.send_error(400, "Invalid JSON-RPC format")
                return
            
            # Route based on method
            method = jsonrpc_request.get("method")
            if method == "noise-handshake":
                response = self._handle_noise_handshake(jsonrpc_request)
            elif method == "noise-data":
                response = self._handle_noise_data(jsonrpc_request)
            else:
                response = {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                    "id": jsonrpc_request.get("id")
                }
            
            # Send JSON-RPC response
            self._send_jsonrpc_response(response)
            
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self.send_error(500, str(e))
    
    def _handle_noise_handshake(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Noise-KK handshake initiation"""
        try:
            params = request.get("params", [])
            if len(params) != 1:
                return self._error_response(request.get("id"), -32602, "Invalid params for noise-handshake")
            
            # Decode client handshake message
            client_msg_b64 = params[0]
            client_msg = base64.b64decode(client_msg_b64)
            
            # Create server-side Noise session using consistent dummy client key
            # In production, this would use proper client authentication
            noise_session = create_server_session(
                self.config.server_private_key,
                self.dummy_client_public
            )
            
            # Process client handshake message
            server_msg, handshake_complete = noise_session.process_handshake_message(client_msg)
            
            if not server_msg:
                return self._error_response(request.get("id"), -32603, "Handshake failed")
            
            # Store session for this client (use client address as key)
            client_key = f"{self.client_address[0]}:{self.client_address[1]}"
            self.noise_sessions[client_key] = noise_session
            
            logger.info(f"Noise-KK handshake completed with {self.client_address}")
            
            # Return server response
            server_msg_b64 = base64.b64encode(server_msg).decode('ascii')
            return {
                "jsonrpc": "2.0",
                "result": server_msg_b64,
                "id": request.get("id")
            }
            
        except Exception as e:
            logger.error(f"Noise handshake error: {e}")
            return self._error_response(request.get("id"), -32603, f"Handshake failed: {e}")
    
    def _handle_noise_data(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle encrypted JSON-RPC request"""
        try:
            # Get noise session for this client
            client_key = f"{self.client_address[0]}:{self.client_address[1]}"
            noise_session = self.noise_sessions.get(client_key)
            
            if not noise_session:
                return self._error_response(request.get("id"), -32603, "No handshake session found")
            
            params = request.get("params", [])
            if len(params) != 1:
                return self._error_response(request.get("id"), -32602, "Invalid params for noise-data")
            
            # Decode and decrypt inner request
            encrypted_b64 = params[0]
            encrypted_data = base64.b64decode(encrypted_b64)
            decrypted_data = noise_session.decrypt(encrypted_data)
            
            # Parse inner JSON-RPC request
            inner_request = json.loads(decrypted_data.decode('utf-8'))
            
            # Process inner request
            inner_response = self._process_inner_jsonrpc(inner_request)
            
            # Encrypt inner response
            response_data = json.dumps(inner_response).encode('utf-8')
            encrypted_response = noise_session.encrypt(response_data)
            encrypted_response_b64 = base64.b64encode(encrypted_response).decode('ascii')
            
            return {
                "jsonrpc": "2.0",
                "result": encrypted_response_b64,
                "id": request.get("id")
            }
            
        except Exception as e:
            logger.error(f"Noise data error: {e}")
            return self._error_response(request.get("id"), -32603, f"Encrypted request failed: {e}")
    
    def _process_inner_jsonrpc(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process the inner (decrypted) JSON-RPC request"""
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
            logger.error(f"Error processing inner JSON-RPC request: {e}")
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
        result = server.register_secret(
            self.config.db, uid, did, bid, version, x, y, max_guesses, expiration
        )
        
        if isinstance(result, Exception):
            raise result
        
        return True
    
    def _handle_recover_secret(self, params: List[Any]) -> List[Any]:
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
    
    def _error_response(self, request_id: Any, code: int, message: str) -> Dict[str, Any]:
        """Create JSON-RPC error response"""
        return {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": request_id
        }
    
    def _send_jsonrpc_response(self, response: Dict[str, Any]):
        """Send JSON-RPC response over HTTP"""
        response_data = json.dumps(response).encode('utf-8')
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_data)))
        self.send_header('Connection', 'keep-alive')
        self.end_headers()
        
        self.wfile.write(response_data)


class NoiseKKHTTPServer:
    """HTTP server with Noise-KK support"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, config: Optional[ServerConfig] = None):
        self.host = host
        self.port = port
        self.config = config or ServerConfig()
        self.server = None
    
    def start(self):
        """Start the HTTP server"""
        # Create handler class with config
        def handler_factory(*args, **kwargs):
            return NoiseKKHTTPHandler(self.config, *args, **kwargs)
        
        # Create HTTP server
        self.server = HTTPServer((self.host, self.port), handler_factory)
        
        logger.info(f"Noise-KK HTTP server listening on {self.host}:{self.port}")
        logger.info(f"Server public key: {self.config.get_server_public_key_string()}")
        
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
        finally:
            if self.server:
                self.server.shutdown()
    
    def stop(self):
        """Stop the server"""
        if self.server:
            self.server.shutdown()


def main():
    """Main function to run the Noise-KK HTTP server"""
    import argparse
    
    parser = argparse.ArgumentParser(description="OpenADP Noise-KK JSON-RPC HTTP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create server configuration
    config = ServerConfig()
    
    # Create and start server
    server = NoiseKKHTTPServer(args.host, args.port, config)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")


if __name__ == "__main__":
    main() 