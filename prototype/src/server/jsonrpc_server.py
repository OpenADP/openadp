#!/usr/bin/env python3
"""
OpenADP JSON-RPC Server

This module implements a JSON-RPC server for the OpenADP (Open Asynchronous 
Distributed Password) system. It provides endpoints for:
- RegisterSecret: Register a secret share with the server
- RecoverSecret: Recover a secret share from the server
- ListBackups: List all backups for a user
- Echo: Test connectivity

Example curl command to test:
    $ curl -H "Content-Type: application/json" -d \
      '{"jsonrpc":"2.0","method":"Echo","params":["Hello, World!"],"id":1}' \
      https://xyzzybill.openadp.org

Note: HTTPS is required for production servers.
"""

import json
import logging
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple, Union

import sys
import os

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from openadp import database
from openadp import crypto
from server import server

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global server state
db_connection = None
noise_private_key = None


class RPCRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for JSON-RPC 2.0 requests.
    
    Handles POST requests containing JSON-RPC method calls and routes them
    to appropriate server functions.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize the request handler with a database connection."""
        self.db = db_connection
        self.noise_sk = noise_private_key
        super().__init__(*args, **kwargs)

    def do_POST(self) -> None:
        """
        Handle POST requests containing JSON-RPC calls.
        
        Parses the JSON-RPC request, routes it to the appropriate method,
        and returns a JSON-RPC response.
        """
        try:
            # Read request data
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            # Parse JSON-RPC request
            request = json.loads(post_data.decode('utf-8'))
            method = request.get('method')
            params = request.get('params', [])
            request_id = request.get('id')
            
            # Route to appropriate method
            result, error = self._route_method(method, params)
            
            # Build response
            if error is None:
                response = {'jsonrpc': '2.0', 'result': result, 'id': request_id}
            else:
                response = {'jsonrpc': '2.0', 'error': error, 'id': request_id}

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            response = {
                'jsonrpc': '2.0', 
                'error': {'code': -32700, 'message': 'Parse error'}, 
                'id': None
            }
        except Exception as e:
            logger.error(f"Unexpected error in POST handler: {e}")
            response = {
                'jsonrpc': '2.0',
                'error': {'code': -32603, 'message': 'Internal error'},
                'id': None
            }

        # Send response
        self._send_json_response(response)

    def _route_method(self, method: str, params: List[Any]) -> Tuple[Any, Optional[Dict]]:
        """
        Route a JSON-RPC method call to the appropriate handler.
        
        Args:
            method: The RPC method name
            params: List of parameters for the method
            
        Returns:
            Tuple of (result, error_dict). If successful, error_dict is None.
        """
        if method == 'RegisterSecret':
            return self._register_secret(params)
        elif method == 'RecoverSecret':
            return self._recover_secret(params)
        elif method == 'ListBackups':
            return self._list_backups(params)
        elif method == 'Echo':
            return self._echo(params)
        else:
            error = {'code': -32601, 'message': 'Method not found'}
            return None, error

    def _send_json_response(self, response: Dict) -> None:
        """
        Send a JSON response back to the client.
        
        Args:
            response: Dictionary containing the JSON-RPC response
        """
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')  # CORS support
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('utf-8'))

    def _register_secret(self, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Handle RegisterSecret RPC method.
        
        Args:
            params: List containing [uid, did, bid, version, x, y_str, max_guesses, expiration]
            
        Returns:
            Tuple of (result, error_message)
        """
        try:
            if len(params) != 8:
                return None, "INVALID_ARGUMENT: RegisterSecret expects exactly 8 parameters"
            
            uid, did, bid, version, x, y_str, max_guesses, expiration = params
            
            # Convert y from string to bytes (x is already an integer from JSON)
            try:
                y_int = int(y_str)
                # Validate that the integer can fit in 32 bytes before conversion
                if y_int.bit_length() > 256:
                    return None, f"INVALID_ARGUMENT: Y integer too large ({y_int.bit_length()} bits, max 256)"
                
                y = int.to_bytes(y_int, 32, "little")  # Convert integer to bytes for server
                logger.info(f"Converted y_str (len={len(y_str)}) to {len(y)} bytes, {y_int.bit_length()} bits")
                
            except ValueError as e:
                return None, f"INVALID_ARGUMENT: Invalid integer conversion for y: {str(e)}"
            except OverflowError as e:
                return None, f"INVALID_ARGUMENT: Y integer too large for 32 bytes: {str(e)}"
            
            # Call server function
            result = server.register_secret(self.db, uid, did, bid, version, x, y, max_guesses, expiration)
            
            if isinstance(result, Exception):
                return None, f"INVALID_ARGUMENT: {str(result)}"
            
            return True, None
            
        except Exception as e:
            logger.error(f"Error in register_secret: {e}")
            return None, f"INTERNAL_ERROR: {str(e)}"

    def _recover_secret(self, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Handle RecoverSecret RPC method.
        
        Args:
            params: List containing [uid, did, bid, b_unexpanded, guess_num]
            
        Returns:
            Tuple of (result, error_message)
        """
        try:
            if len(params) != 5:
                return None, "INVALID_ARGUMENT: RecoverSecret expects exactly 5 parameters"
            
            uid, did, bid, b_unexpanded, guess_num = params
            
            # Convert b from JSON representation back to cryptographic point
            try:
                b = crypto.expand(b_unexpanded)
                logger.info(f"Converted b_unexpanded to cryptographic point")
            except Exception as e:
                return None, f"INVALID_ARGUMENT: Invalid point b: {str(e)}"
            
            # Call server function
            result = server.recover_secret(self.db, uid, did, bid, b, guess_num)
            
            if isinstance(result, Exception):
                return None, f"INVALID_ARGUMENT: {str(result)}"
            
            return result, None
            
        except Exception as e:
            logger.error(f"Error in recover_secret: {e}")
            return None, f"INTERNAL_ERROR: {str(e)}"

    def _list_backups(self, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Handle ListBackups RPC method.
        
        Args:
            params: List containing [uid]
            
        Returns:
            Tuple of (result, error_message)
        """
        try:
            if len(params) != 1:
                return None, "INVALID_ARGUMENT: ListBackups expects exactly 1 parameter"
            
            uid = params[0]
            
            # Call server function
            result = server.list_backups(self.db, uid)
            
            if isinstance(result, Exception):
                return None, f"INVALID_ARGUMENT: {str(result)}"
            
            return result, None
            
        except Exception as e:
            logger.error(f"Error in list_backups: {e}")
            return None, f"INTERNAL_ERROR: {str(e)}"

    def _echo(self, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Handle Echo RPC method for connectivity testing.
        
        Args:
            params: List containing [message]
            
        Returns:
            Tuple of (echoed_message, error_message)
        """
        if len(params) != 1:
            return None, "INVALID_ARGUMENT: Echo expects exactly 1 parameter"
        
        return params[0], None

    def log_message(self, format: str, *args) -> None:
        """Override to use proper logging instead of printing to stderr."""
        logger.info(f"{self.address_string()} - {format % args}")


def main():
    """Main function to run the JSON-RPC server."""
    global db_connection, noise_private_key
    
    # Initialize database
    db_path = "openadp.db"
    db_connection = database.Database(db_path)
    logger.info(f"Database initialized at {db_path}")

    # Load or generate Noise server key
    noise_private_key = db_connection.get_server_config("noise_sk")
    if noise_private_key is None:
        logger.info("No Noise key found, generating a new one...")
        priv_key, pub_key = crypto.x25519_generate_keypair()
        db_connection.set_server_config("noise_sk", priv_key)
        noise_private_key = priv_key
        logger.info("New key saved to database.")
    else:
        logger.info("Loaded existing Noise server key from database.")

    # Always log the public key on startup
    public_key = crypto.x25519_public_key_from_private(noise_private_key)
    pub_key_b64 = base64.b64encode(public_key).decode('utf-8')
    logger.info("="*60)
    logger.info("SERVER NOISE PUBLIC KEY")
    logger.info(f"Public Key (Base64): {pub_key_b64}")
    logger.info("="*60)

    # Run the server
    server_address = ('', 4433)
    httpd = HTTPServer(server_address, RPCRequestHandler)
    
    logger.info(f"Starting JSON-RPC server on port {server_address[1]}...")
    httpd.serve_forever()


if __name__ == '__main__':
    main()
