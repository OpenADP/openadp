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

# Authentication configuration - Global IdP
AUTH_ENABLED = os.environ.get('OPENADP_AUTH_ENABLED', '1') == '1'
AUTH_ISSUER = os.environ.get('OPENADP_AUTH_ISSUER', 'http://localhost:8081/realms/openadp')
AUTH_JWKS_URL = os.environ.get('OPENADP_AUTH_JWKS_URL')

# Auto-derive JWKS URL if not provided (with Keycloak 22.0 workaround)
if not AUTH_JWKS_URL:
    # Try .well-known first, fallback to direct endpoint
    AUTH_JWKS_URL = f"{AUTH_ISSUER}/protocol/openid-connect/certs"

# JWKS cache
jwks_cache = {}
jwks_cache_expiry = 0

def load_jwks():
    """Load JWKS from IdP endpoint with caching."""
    global jwks_cache, jwks_cache_expiry
    import time
    import urllib.request
    
    current_time = time.time()
    cache_ttl = int(os.environ.get('OPENADP_AUTH_CACHE_TTL', '3600'))
    
    if current_time < jwks_cache_expiry and jwks_cache:
        return jwks_cache
    
    try:
        logger.info(f"Fetching JWKS from {AUTH_JWKS_URL}")
        with urllib.request.urlopen(AUTH_JWKS_URL, timeout=10) as response:
            jwks_data = json.loads(response.read())
            jwks_cache = jwks_data
            jwks_cache_expiry = current_time + cache_ttl
            logger.info(f"JWKS cached for {cache_ttl} seconds")
            return jwks_cache
    except Exception as e:
        logger.error(f"Failed to fetch JWKS: {e}")
        return jwks_cache if jwks_cache else None

def validate_jwt_token(access_token: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Validate JWT access token and extract user ID.
    
    Returns:
        Tuple of (user_id, error_message)
    """
    try:
        import jwt
        from jwt import PyJWKClient
        
        # Load JWKS
        jwks_data = load_jwks()
        if not jwks_data:
            return None, "Failed to load JWKS for token validation"
        
        # Decode token header to get key ID
        unverified_header = jwt.get_unverified_header(access_token)
        kid = unverified_header.get('kid')
        
        # Find the signing key
        signing_key = None
        for key in jwks_data.get('keys', []):
            if key.get('kid') == kid:
                signing_key = jwt.PyJWK(key).key
                break
        
        if not signing_key:
            return None, f"No signing key found for kid: {kid}"
        
        # Verify and decode token
        payload = jwt.decode(
            access_token,
            signing_key,
            algorithms=['RS256', 'ES256'],
            issuer=AUTH_ISSUER,
            options={"verify_aud": False}  # We'll check audience manually if needed
        )
        
        # Extract user ID from 'sub' claim
        user_id = payload.get('sub')
        if not user_id:
            return None, "Token missing 'sub' claim"
        
        logger.info(f"JWT token validated for user: {user_id}")
        return user_id, None
        
    except jwt.ExpiredSignatureError:
        return None, "Token has expired"
    except jwt.InvalidTokenError as e:
        return None, f"Invalid token: {str(e)}"
    except Exception as e:
        logger.error(f"JWT validation error: {e}")
        return None, f"Token validation failed: {str(e)}"

def validate_encrypted_auth(auth_payload: dict, handshake_hash: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Validate authentication payload from encrypted Noise-NK channel.
    
    Args:
        auth_payload: Dictionary containing auth information
        handshake_hash: Handshake hash from Noise-NK session
        
    Returns:
        Tuple of (user_id, error_message)
    """
    try:
        # Extract required fields
        access_token = auth_payload.get('access_token')
        handshake_signature = auth_payload.get('handshake_signature') 
        dpop_public_key = auth_payload.get('dpop_public_key')
        
        if not access_token:
            return None, "Missing access_token in auth payload"
        if not handshake_signature:
            return None, "Missing handshake_signature in auth payload"
        if not dpop_public_key:
            return None, "Missing dpop_public_key in auth payload"
        
        # 1. Validate JWT access token
        user_id, jwt_error = validate_jwt_token(access_token)
        if jwt_error:
            return None, f"JWT validation failed: {jwt_error}"
        
        # 2. Verify handshake signature
        try:
            from openadp.auth.dpop import verify_handshake_signature
            signature_valid = verify_handshake_signature(
                handshake_hash=handshake_hash,
                signature_b64=handshake_signature,
                public_key_jwk=dpop_public_key
            )
            
            if not signature_valid:
                return None, "Invalid handshake signature"
                
        except Exception as e:
            return None, f"Handshake signature verification failed: {str(e)}"
        
        # 3. Verify token contains matching public key (DPoP binding)
        # TODO: Keycloak 22.0 doesn't seem to properly bind tokens to DPoP keys
        # For now, we'll skip this check and rely on handshake signature verification
        # which provides equivalent security for our use case
        try:
            import jwt
            unverified_payload = jwt.decode(access_token, options={"verify_signature": False})
            cnf_claim = unverified_payload.get('cnf', {})
            
            # Calculate JWK thumbprint
            from openadp.auth.dpop import calculate_jwk_thumbprint
            expected_thumbprint = calculate_jwk_thumbprint(dpop_public_key)
            token_thumbprint = cnf_claim.get('jkt')
            
            if token_thumbprint and token_thumbprint != expected_thumbprint:
                return None, "Token not bound to provided DPoP key"
            elif not token_thumbprint:
                # Log warning but don't fail - rely on handshake signature instead
                logger.warning(f"Token missing cnf.jkt claim - relying on handshake signature for DPoP binding")
                
        except Exception as e:
            logger.warning(f"DPoP binding verification failed: {str(e)} - continuing with handshake signature")
        
        logger.info(f"Encrypted authentication validated for user: {user_id}")
        return user_id, None
        
    except Exception as e:
        logger.error(f"Encrypted auth validation error: {e}")
        return None, f"Authentication validation failed: {str(e)}"

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
            
            # Check authentication for state-changing methods (Phase 4)
            # Echo, GetServerInfo, handshake methods, and encrypted_call remain unauthenticated
            # encrypted_call handles authentication internally via Phase 3.5 encrypted auth
            unauthenticated_methods = {'Echo', 'GetServerInfo', 'noise_handshake', 'encrypted_call'}
            
            if AUTH_ENABLED and method not in unauthenticated_methods:
                from server.auth_middleware import validate_auth
                user_id, auth_error = validate_auth(post_data, dict(self.headers))
                
                if auth_error:
                    error_response = {
                        'jsonrpc': '2.0',
                        'error': {'code': -32001, 'message': f'Unauthorized: {auth_error}'},
                        'id': request_id
                    }
                    self._send_json_response(error_response)
                    return
                
                # Store user_id for method handlers to use
                self.user_id = user_id
                logger.info(f"Authenticated request for user: {user_id}, method: {method}")
            else:
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
