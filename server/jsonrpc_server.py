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
      https://xyzzy.openadp.org

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

# Import modules directly to avoid dependency issues
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'openadp'))
import database
import crypto
from server import server
from server.noise_session_manager import get_session_manager, validate_session_id

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global server state
db_connection = None

# Authentication configuration - Authentication Code System
AUTH_ENABLED = os.environ.get('OPENADP_AUTH_ENABLED', '1') == '1'

def validate_auth_code_request(auth_code: str, client_ip: str = "unknown") -> Tuple[Optional[str], Optional[str]]:
    """
    Validate an authentication code request.
    
    Args:
        auth_code: Server-specific authentication code (64 hex chars)
        client_ip: Client IP address for DDoS defense
        
    Returns:
        Tuple of (derived_uuid, error_message). If successful, error_message is None.
    """
    try:
        from server.auth_code_middleware import validate_auth_code_request
        return validate_auth_code_request(auth_code, "http://localhost:8080", client_ip)
    except ImportError:
        logger.error("Authentication code middleware not available")
        return None, "Authentication system not available"

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
            
            # Parse JSON-RPC request
            request = json.loads(post_data.decode('utf-8'))
            method = request.get('method')
            params = request.get('params', [])
            request_id = request.get('id')
            
            # Authentication is now handled per-method using authentication codes
            # Echo, GetServerInfo, handshake methods remain unauthenticated
            self.user_id = None
            
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
        elif method == 'GetServerInfo':
            return self._get_server_info(params)
        elif method == 'noise_handshake':
            return self._noise_handshake(params)
        elif method == 'encrypted_call':
            return self._encrypted_call(params)
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
            params: List containing [auth_code, uid, did, bid, version, x, y_str, max_guesses, expiration]
            
        Returns:
            Tuple of (result, error_message)
        """
        try:
            if len(params) != 9:
                return None, "INVALID_ARGUMENT: RegisterSecret expects exactly 9 parameters"
            
            auth_code, uid, did, bid, version, x, y_str, max_guesses, expiration = params
            
            # Validate authentication code
            if AUTH_ENABLED:
                client_ip = getattr(self, 'client_address', ['unknown'])[0] if hasattr(self, 'client_address') else 'unknown'
                derived_uuid, auth_error = validate_auth_code_request(auth_code, client_ip)
                if auth_error:
                    return None, f"AUTHENTICATION_FAILED: {auth_error}"
                
                # Use derived UUID as the user identifier
                uid = derived_uuid
                logger.info(f"Authenticated RegisterSecret request for derived UUID: {uid}")
            
            # Convert parameters to proper types (JSON-RPC may pass some as strings)
            try:
                version = int(version)
                x = int(x)
                max_guesses = int(max_guesses)
                expiration = int(expiration)
            except (ValueError, TypeError) as e:
                return None, f"INVALID_ARGUMENT: Invalid integer parameter: {str(e)}"
            
            # Convert y from string to bytes (x is already an integer from JSON)
            try:
                y_int = int(y_str)
                
                # Validate that the integer can fit in 32 bytes (for elliptic curve coordinates)
                if y_int.bit_length() > 256:
                    return None, f"INVALID_ARGUMENT: Y integer too large ({y_int.bit_length()} bits, max 256)"
                
                # Convert integer to bytes with fixed 32-byte length (little-endian to match client)
                y = y_int.to_bytes(32, "little")
                logger.info(f"Converted y_str (len={len(y_str)}) to {len(y)} bytes, {y_int.bit_length()} bits")
                
            except ValueError as e:
                return None, f"INVALID_ARGUMENT: Invalid integer conversion for y: {str(e)}"
            except OverflowError as e:
                return None, f"INVALID_ARGUMENT: Y integer too large for 32 bytes: {str(e)}"
            
            # Call server function with auth_code
            result = server.register_secret(self.db, uid, did, bid, auth_code, version, x, y, max_guesses, expiration)
            
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
            params: List containing [auth_code, did, bid, b_unexpanded, guess_num]
            
        Returns:
            Tuple of (result, error_message)
        """
        try:
            if len(params) != 5:
                return None, "INVALID_ARGUMENT: RecoverSecret expects exactly 5 parameters"
            
            auth_code, did, bid, b_unexpanded, guess_num = params
            
            # Validate authentication code
            if AUTH_ENABLED:
                client_ip = getattr(self, 'client_address', ['unknown'])[0] if hasattr(self, 'client_address') else 'unknown'
                derived_uuid, auth_error = validate_auth_code_request(auth_code, client_ip)
                if auth_error:
                    return None, f"AUTHENTICATION_FAILED: {auth_error}"
                
                logger.info(f"Authenticated RecoverSecret request for derived UUID: {derived_uuid}")
            
            # Look up the share using auth_code instead of uid
            share_result = self.db.lookup_by_auth_code(auth_code, did, bid)
            if share_result is None:
                return None, "INVALID_ARGUMENT: Share not found"
            
            # Extract uid from the lookup result
            uid, version, x, y, num_guesses, max_guesses, expiration = share_result
            
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
            params: List containing [auth_code]
            
        Returns:
            Tuple of (result, error_message)
        """
        try:
            if len(params) != 1:
                return None, "INVALID_ARGUMENT: ListBackups expects exactly 1 parameter"
            
            auth_code = params[0]
            
            # Validate authentication code
            if AUTH_ENABLED:
                client_ip = getattr(self, 'client_address', ['unknown'])[0] if hasattr(self, 'client_address') else 'unknown'
                derived_uuid, auth_error = validate_auth_code_request(auth_code, client_ip)
                if auth_error:
                    return None, f"AUTHENTICATION_FAILED: {auth_error}"
                
                logger.info(f"Authenticated ListBackups request for derived UUID: {derived_uuid}")
            
            # List backups using auth_code
            result = self.db.list_backups_by_auth_code(auth_code)
            
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
            params: List containing [session_id, encrypted_request_base64]
            
        Returns:
            Tuple of (encrypted_response_dict, error_message)
        """
        try:
            if len(params) != 2:
                return None, "INVALID_ARGUMENT: encrypted_call expects exactly 2 parameters"
            
            session_id, encrypted_request_b64 = params
            
            # Validate session ID format
            if not validate_session_id(session_id):
                return None, "INVALID_ARGUMENT: Invalid session ID format"
            
            # Get session manager and decrypt request
            session_manager = get_session_manager()
            decrypted_request, error = session_manager.decrypt_call(session_id, base64.b64decode(encrypted_request_b64))
            
            if error:
                return None, f"DECRYPTION_ERROR: {error}"
            
            # Extract method and params from decrypted request
            method = decrypted_request.get("method")
            rpc_params = decrypted_request.get("params", [])
            request_id = decrypted_request.get("id", 1)
            
            if not method:
                return None, "INVALID_JSON: Missing method field"
            
            # Handle authentication for state-changing methods
            user_id = None
            if AUTH_ENABLED and method in ["RegisterSecret", "RecoverSecret", "ListBackups"]:
                auth_payload = decrypted_request.get("auth")
                if not auth_payload:
                    return None, "AUTHENTICATION_REQUIRED: Method requires authentication"
                
                # Get handshake hash for signature verification
                handshake_hash = session_manager.get_handshake_hash(session_id)
                if not handshake_hash:
                    return None, "SESSION_ERROR: No handshake hash available"
                
                # Validate encrypted authentication
                user_id, auth_error = validate_encrypted_auth(auth_payload, handshake_hash)
                if auth_error:
                    return None, f"AUTHENTICATION_FAILED: {auth_error}"
                
                logger.info(f"Authenticated encrypted request for {method} by user {user_id}")
                
                # For Phase 4: Use JWT sub as UID for ownership validation
                if method in ["RegisterSecret", "RecoverSecret", "ListBackups"]:
                    # Replace user-provided UID with authenticated JWT sub
                    if method == "RegisterSecret" and len(rpc_params) >= 1:
                        # Replace first parameter (UID) with authenticated user_id
                        rpc_params[0] = user_id
                    elif method == "RecoverSecret" and len(rpc_params) >= 1:
                        # Replace first parameter (UID) with authenticated user_id
                        rpc_params[0] = user_id
                    elif method == "ListBackups" and len(rpc_params) >= 1:
                        # Replace first parameter (UID) with authenticated user_id
                        rpc_params[0] = user_id
            
            # Route the method call
            result, error = self._route_method(method, rpc_params)
            
            # Create JSON-RPC response
            if error:
                response_data = {
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": error},
                    "id": request_id
                }
            else:
                response_data = {
                    "jsonrpc": "2.0", 
                    "result": result,
                    "id": request_id
                }
            
            # Encrypt and return response
            encrypted_response, encrypt_error = session_manager.encrypt_response(session_id, response_data)
            
            if encrypt_error:
                return None, f"ENCRYPTION_ERROR: {encrypt_error}"
            
            return {"data": base64.b64encode(encrypted_response).decode('ascii')}, None
            
        except Exception as e:
            logger.error(f"Error in encrypted_call: {e}")
            import traceback 
            traceback.print_exc()
            return None, f"INTERNAL_ERROR: {str(e)}"

    def log_message(self, format: str, *args) -> None:
        """Override to use proper logging instead of printing to stderr."""
        logger.info(f"{self.address_string()} - {format % args}")


def main():
    """Main function to run the JSON-RPC server."""
    global db_connection
    
    # Initialize database
    db_path = os.environ.get('OPENADP_DB', 'openadp.db')
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
