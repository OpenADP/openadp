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
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple, Union
from collections import defaultdict

import sys
import os

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import modules directly to avoid dependency issues
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'openadp'))
import database
import crypto
from server import server
from server.noise_session_manager import get_session_manager, validate_session_id
from server.auth_middleware import validate_auth, get_auth_stats

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global server state
db_connection = None

# Rate limiting configuration
MAX_REQUESTS_PER_USER_PER_MINUTE = int(os.getenv('OPENADP_MAX_USER_RPM', '60'))  # 60 requests per minute per user
MAX_REQUESTS_PER_IP_PER_MINUTE = int(os.getenv('OPENADP_MAX_IP_RPM', '120'))    # 120 requests per minute per IP

# Rate limiting storage (in production, use Redis)
user_request_counts = defaultdict(list)  # user_id -> [timestamp, timestamp, ...]
ip_request_counts = defaultdict(list)    # ip_address -> [timestamp, timestamp, ...]


def check_rate_limit(user_id: Optional[str], client_ip: str) -> Optional[str]:
    """
    Check if request should be rate limited.
    
    Args:
        user_id: Authenticated user ID (None for unauthenticated requests)
        client_ip: Client IP address
        
    Returns:
        Error message if rate limited, None if allowed
    """
    current_time = time.time()
    one_minute_ago = current_time - 60
    
    # Clean old entries and check IP rate limit
    ip_request_counts[client_ip] = [t for t in ip_request_counts[client_ip] if t > one_minute_ago]
    if len(ip_request_counts[client_ip]) >= MAX_REQUESTS_PER_IP_PER_MINUTE:
        return f"Rate limit exceeded: IP {client_ip} has made {len(ip_request_counts[client_ip])} requests in the last minute (max: {MAX_REQUESTS_PER_IP_PER_MINUTE})"
    
    # Check user rate limit (if authenticated)
    if user_id is not None:
        user_request_counts[user_id] = [t for t in user_request_counts[user_id] if t > one_minute_ago]
        if len(user_request_counts[user_id]) >= MAX_REQUESTS_PER_USER_PER_MINUTE:
            return f"Rate limit exceeded: User {user_id} has made {len(user_request_counts[user_id])} requests in the last minute (max: {MAX_REQUESTS_PER_USER_PER_MINUTE})"
    
    # Record this request
    ip_request_counts[client_ip].append(current_time)
    if user_id is not None:
        user_request_counts[user_id].append(current_time)
    
    return None  # Not rate limited


class RPCRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler for JSON-RPC 2.0 requests.
    
    Handles POST requests containing JSON-RPC method calls and routes them
    to appropriate server functions.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize the request handler with a database connection."""
        self.db = db_connection
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
            
            # Parse JSON-RPC request first to check if auth is needed
            request = json.loads(post_data.decode('utf-8'))
            method = request.get('method')
            params = request.get('params', [])
            request_id = request.get('id')
            
            # Check if this method requires authentication
            auth_required_methods = {'RegisterSecret', 'RecoverSecret', 'ListBackups'}
            
            # Perform authentication for state-changing methods
            user_id = None
            if method in auth_required_methods:
                # Build full request URL for DPoP validation
                host = self.headers.get('Host', 'localhost:8080')
                scheme = 'https' if self.headers.get('X-Forwarded-Proto') == 'https' else 'http'
                request_url = f"{scheme}://{host}{self.path}"
                
                user_id, auth_error = validate_auth(post_data, dict(self.headers), "POST", request_url)
                
                if auth_error:
                    logger.warning(f"Authentication failed for {method}: {auth_error}")
                    response = {
                        'jsonrpc': '2.0',
                        'error': {'code': -32001, 'message': f'Unauthorized: {auth_error}'},
                        'id': request_id
                    }
                    self._send_json_response(response)
                    return
                
                logger.info(f"Authenticated user {user_id} for method {method}")
            
            # Store user context for handlers
            self.user_id = user_id
            
            # Rate limiting check
            client_ip = self.client_address[0]
            rate_limit_error = check_rate_limit(user_id, client_ip)
            if rate_limit_error:
                logger.warning(f"Rate limit exceeded for user {user_id}, IP {client_ip}: {rate_limit_error}")
                response = {
                    'jsonrpc': '2.0',
                    'error': {'code': -32002, 'message': f'Rate limit exceeded: {rate_limit_error}'},
                    'id': request_id
                }
                self._send_json_response(response)
                return
            
            # Route the method call
            result, error_dict = self._route_method(method, params)
            
            if error_dict:
                response = {
                    'jsonrpc': '2.0',
                    'error': error_dict,
                    'id': request_id
                }
            else:
                response = {
                    'jsonrpc': '2.0',
                    'result': result,
                    'id': request_id
                }

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in request: {e}")
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
        elif method == 'GetServerInfo':
            return self._get_server_info(params)
        elif method == 'noise_handshake':
            return self._noise_handshake(params)
        elif method == 'encrypted_call':
            return self._encrypted_call(params)
        elif method == 'GetAuthStatus':
            return self._get_auth_status(params)
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
            
            # Require authentication for this method
            if not hasattr(self, 'user_id') or self.user_id is None:
                return None, "UNAUTHORIZED: Authentication required for RegisterSecret"
            
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
            
            # Call server function with authenticated user's owner_sub
            result = server.register_secret(self.db, uid, did, bid, version, x, y, max_guesses, expiration, self.user_id)
            
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
            
            # Require authentication for this method
            if not hasattr(self, 'user_id') or self.user_id is None:
                return None, "UNAUTHORIZED: Authentication required for RecoverSecret"
            
            # Convert b from JSON representation back to cryptographic point
            try:
                b = crypto.expand(b_unexpanded)
                logger.info(f"Converted b_unexpanded to cryptographic point")
            except Exception as e:
                return None, f"INVALID_ARGUMENT: Invalid point b: {str(e)}"
            
            # Call server function with authenticated user's owner_sub
            result = server.recover_secret(self.db, uid, did, bid, b, guess_num, self.user_id)
            
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
            
            # Require authentication for this method
            if not hasattr(self, 'user_id') or self.user_id is None:
                return None, "UNAUTHORIZED: Authentication required for ListBackups"
            
            # Call server function with authenticated user's owner_sub
            result = server.list_backups(self.db, uid, self.user_id)
            
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

    def _get_server_info(self, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Handle GetServerInfo RPC method to get server capabilities and public key.
        
        Args:
            params: Empty list (no parameters required)
            
        Returns:
            Tuple of (server_info_dict, error_message)
        """
        if len(params) != 0:
            return None, "INVALID_ARGUMENT: GetServerInfo expects no parameters"
        
        try:
            # Get session manager and server public key
            session_manager = get_session_manager()
            server_public_key = session_manager.get_server_public_key()
            server_pub_key_b64 = base64.b64encode(server_public_key).decode('utf-8')
            
            server_info = {
                "version": "0.1.0",
                "noise_nk_public_key": server_pub_key_b64,
                "supported_methods": [
                    "RegisterSecret",
                    "RecoverSecret", 
                    "ListBackups",
                    "Echo",
                    "GetServerInfo",
                    "GetAuthStatus",
                    "noise_handshake",
                    "encrypted_call"
                ],
                "encryption_supported": True,
                "encryption_protocol": "Noise-NK"
            }
            
            return server_info, None
            
        except Exception as e:
            logger.error(f"Error in get_server_info: {e}")
            return None, f"INTERNAL_ERROR: {str(e)}"

    def _noise_handshake(self, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Handle noise_handshake RPC method to establish encrypted session.
        
        Args:
            params: List containing [session_id, handshake_message_base64]
            
        Returns:
            Tuple of (handshake_response_dict, error_message)
        """
        try:
            if len(params) != 2:
                return None, "INVALID_ARGUMENT: noise_handshake expects exactly 2 parameters"
            
            session_id, handshake_message_b64 = params
            
            # Validate session ID format
            if not validate_session_id(session_id):
                return None, "INVALID_ARGUMENT: Invalid session ID format"
            
            # Decode handshake message
            try:
                handshake_message = base64.b64decode(handshake_message_b64)
            except Exception as e:
                return None, f"INVALID_ARGUMENT: Invalid base64 handshake message: {str(e)}"
            
            # Get session manager and start handshake
            session_manager = get_session_manager()
            server_response, error = session_manager.start_handshake(session_id, handshake_message)
            
            if error:
                return None, f"HANDSHAKE_ERROR: {error}"
            
            # Return base64-encoded response
            response = {
                "message": base64.b64encode(server_response).decode('ascii')
            }
            
            logger.info(f"Successfully completed handshake for session {session_id[:16]}...")
            return response, None
            
        except Exception as e:
            logger.error(f"Error in noise_handshake: {e}")
            return None, f"INTERNAL_ERROR: {str(e)}"

    def _encrypted_call(self, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Handle encrypted_call RPC method to process encrypted JSON-RPC requests.
        
        Args:
            params: List containing [session_id, encrypted_data_base64]
            
        Returns:
            Tuple of (encrypted_response_dict, error_message)
        """
        try:
            if len(params) != 2:
                return None, "INVALID_ARGUMENT: encrypted_call expects exactly 2 parameters"
            
            session_id, encrypted_data_b64 = params
            
            # Validate session ID format
            if not validate_session_id(session_id):
                return None, "INVALID_ARGUMENT: Invalid session ID format"
            
            # Decode encrypted data
            try:
                encrypted_data = base64.b64decode(encrypted_data_b64)
            except Exception as e:
                return None, f"INVALID_ARGUMENT: Invalid base64 encrypted data: {str(e)}"
            
            # Get session manager and decrypt the call
            session_manager = get_session_manager()
            decrypted_request, error = session_manager.decrypt_call(session_id, encrypted_data)
            
            if error:
                return None, f"DECRYPTION_ERROR: {error}"
            
            # Extract the actual method and params from decrypted request
            inner_method = decrypted_request.get('method')
            inner_params = decrypted_request.get('params', [])
            inner_id = decrypted_request.get('id')
            
            logger.debug(f"Decrypted call: method={inner_method}, params={inner_params}")
            
            # Route the decrypted method call (but not encryption methods!)
            if inner_method in ['noise_handshake', 'encrypted_call']:
                # Prevent recursive encryption calls
                inner_result = None
                inner_error = "INVALID_METHOD: Cannot encrypt encryption methods"
            else:
                inner_result, inner_error = self._route_method(inner_method, inner_params)
            
            # Build the inner response
            if inner_error is None:
                inner_response = {'jsonrpc': '2.0', 'result': inner_result, 'id': inner_id}
            else:
                inner_response = {'jsonrpc': '2.0', 'error': {'code': -32600, 'message': inner_error}, 'id': inner_id}
            
            # Encrypt the response
            encrypted_response, error = session_manager.encrypt_response(session_id, inner_response)
            
            if error:
                return None, f"ENCRYPTION_ERROR: {error}"
            
            # Return base64-encoded encrypted response
            response = {
                "data": base64.b64encode(encrypted_response).decode('ascii')
            }
            
            logger.info(f"Successfully processed encrypted call for session {session_id[:16]}...")
            return response, None
            
        except Exception as e:
            logger.error(f"Error in encrypted_call: {e}")
            return None, f"INTERNAL_ERROR: {str(e)}"

    def _get_auth_status(self, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Handle GetAuthStatus RPC method.
        
        Args:
            params: Empty list (no parameters expected)
            
        Returns:
            Tuple of (auth_status_dict, error_message)
        """
        try:
            if len(params) != 0:
                return None, "INVALID_ARGUMENT: GetAuthStatus expects no parameters"
            
            # Get authentication middleware statistics
            auth_stats = get_auth_stats()
            
            return auth_stats, None
            
        except Exception as e:
            logger.error(f"Error in get_auth_status: {e}")
            return None, f"INTERNAL_ERROR: {str(e)}"

    def log_message(self, format: str, *args) -> None:
        """Override to use proper logging instead of printing to stderr."""
        logger.info(f"{self.address_string()} - {format % args}")


def main():
    """Main function to run the JSON-RPC server."""
    global db_connection
    
    # Initialize database
    db_path = "openadp.db"
    db_connection = database.Database(db_path)
    logger.info(f"Database initialized at {db_path}")

    # Load or generate server Noise-NK key from database
    stored_key_data = db_connection.get_server_config("noise_nk_keypair")
    if stored_key_data is None:
        logger.info("No server key found, generating a new Noise-NK keypair...")
        # Import here to avoid circular dependency
        from openadp.noise_nk import generate_keypair
        server_keypair = generate_keypair()
        
        # Store the keypair data (private key bytes) in database
        # The keypair object contains both private and public key data
        db_connection.set_server_config("noise_nk_keypair", server_keypair.private.data)
        logger.info("New server key generated and saved to database.")
    else:
        logger.info("Loading existing server key from database...")
        # Recreate keypair from stored private key bytes
        from dissononce.extras.meta.protocol.factory import NoiseProtocolFactory
        from dissononce.dh.keypair import KeyPair
        from dissononce.dh.private import PrivateKey
        
        factory = NoiseProtocolFactory()
        protocol = factory.get_noise_protocol('Noise_NK_25519_AESGCM_SHA256')
        
        # Create a private key object from the stored bytes
        private_key_obj = PrivateKey(stored_key_data)
        server_keypair = protocol.dh.generate_keypair(private_key_obj)
        logger.info("Server key loaded from database.")

    # Initialize Noise-NK session manager with our stored key
    from server.noise_session_manager import initialize_session_manager
    session_manager = initialize_session_manager(server_keypair)
    server_public_key = session_manager.get_server_public_key()
    server_pub_key_b64 = base64.b64encode(server_public_key).decode('utf-8')
    
    logger.info("="*50)
    logger.info("SERVER PUBLIC KEY")
    logger.info(f"Noise-NK (Base64): {server_pub_key_b64}")
    logger.info("="*50)

    # Run the server on a configurable port (default 8080)
    port = int(os.environ.get('OPENADP_PORT', '8080'))
    server_address = ('', port)
    httpd = HTTPServer(server_address, RPCRequestHandler)
    
    logger.info(f"Starting JSON-RPC server on port {server_address[1]}...")
    httpd.serve_forever()


if __name__ == '__main__':
    main()
