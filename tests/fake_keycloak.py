"""
Fake Keycloak OIDC Provider for OpenADP Testing

A lightweight, standards-compliant OIDC provider for integration testing.
Supports DPoP, multiple grant types, and proper JWK handling.
"""

import json
import threading
import time
import base64
import uuid
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse, urlencode
from typing import Dict, Any, Optional, List
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


class FakeKeycloakConfig:
    """Configuration for the fake Keycloak server."""
    
    def __init__(self):
        self.host = "localhost"
        self.port = 9000
        self.realm = "openadp"
        self.token_lifetime = 300  # 5 minutes
        self.refresh_token_lifetime = 3600  # 1 hour
        
        # Test users
        self.users = [
            {
                "username": "alice", 
                "password": "password123", 
                "sub": "11111111-1111-1111-1111-111111111111",
                "email": "alice@example.com",
                "name": "Alice Test"
            },
            {
                "username": "bob", 
                "password": "password456", 
                "sub": "22222222-2222-2222-2222-222222222222",
                "email": "bob@example.com", 
                "name": "Bob Test"
            },
        ]
        
        # Test clients
        self.clients = [
            {
                "client_id": "cli-test",
                "client_secret": "secret",
                "allowed_grant_types": ["password", "client_credentials", "refresh_token", "authorization_code"],
                "redirect_uris": ["http://localhost:8888/callback", "http://localhost:8889/callback"]
            },
            {
                "client_id": "public-client",
                "client_secret": None,  # Public client
                "allowed_grant_types": ["authorization_code", "refresh_token"],
                "redirect_uris": ["http://localhost:3000/callback"]
            },
            {
                "client_id": "openadp-cli",
                "client_secret": None,  # Public client for CLI tools
                "allowed_grant_types": ["authorization_code", "refresh_token"],
                "redirect_uris": ["http://localhost:8888/callback", "http://localhost:8889/callback"]
            }
        ]
    
    @property
    def issuer(self) -> str:
        return f"http://{self.host}:{self.port}/realms/{self.realm}"


class JWKManager:
    """Manages JWK generation and signing keys."""
    
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.kid = "test-signing-key"
        self._jwk = None
        self._jwks = None
    
    def get_jwk(self) -> Dict[str, Any]:
        """Get the public key as a JWK."""
        if self._jwk is None:
            self._jwk = self._create_jwk()
        return self._jwk
    
    def get_jwks(self) -> Dict[str, Any]:
        """Get the JWKS document."""
        if self._jwks is None:
            self._jwks = {
                "keys": [self.get_jwk()]
            }
        return self._jwks
    
    def _create_jwk(self) -> Dict[str, Any]:
        """Create a proper JWK from the EC public key."""
        public_numbers = self.public_key.public_numbers()
        
        # Convert coordinates to base64url (32 bytes each for P-256)
        def int_to_base64url(value: int, byte_length: int) -> str:
            byte_value = value.to_bytes(byte_length, byteorder='big')
            return base64.urlsafe_b64encode(byte_value).decode('ascii').rstrip('=')
        
        x_b64 = int_to_base64url(public_numbers.x, 32)
        y_b64 = int_to_base64url(public_numbers.y, 32)
        
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64,
            "use": "sig",
            "alg": "ES256",
            "kid": self.kid
        }
    
    def sign_jwt(self, payload: Dict[str, Any]) -> str:
        """Sign a JWT with the private key."""
        return jwt.encode(
            payload, 
            self.private_key, 
            algorithm="ES256", 
            headers={"kid": self.kid}
        )


class TokenManager:
    """Manages token issuance and validation."""
    
    def __init__(self, config: FakeKeycloakConfig, jwk_manager: JWKManager):
        self.config = config
        self.jwk_manager = jwk_manager
        self.refresh_tokens: Dict[str, Dict[str, Any]] = {}
    
    def create_access_token(self, user: Dict[str, Any], client_id: str, 
                          dpop_jwk: Optional[Dict[str, Any]] = None) -> str:
        """Create an access token."""
        now = int(time.time())
        
        payload = {
            "iss": self.config.issuer,
            "sub": user["sub"],
            "aud": client_id,
            "iat": now,
            "exp": now + self.config.token_lifetime,
            "jti": str(uuid.uuid4()),
            "typ": "Bearer",
            "azp": client_id,
            "scope": "openid profile email"
        }
        
        # Add DPoP confirmation if provided
        if dpop_jwk:
            # Check if this is a mock JWK with pre-calculated thumbprint (from dpop_jkt parameter)
            if "_jkt" in dpop_jwk:
                # Use the pre-calculated thumbprint from dpop_jkt parameter
                thumbprint = dpop_jwk["_jkt"]
            else:
                # Create JWK thumbprint for cnf claim
                jwk_json = json.dumps(dpop_jwk, sort_keys=True, separators=(',', ':'))
                thumbprint = base64.urlsafe_b64encode(
                    hashlib.sha256(jwk_json.encode()).digest()
                ).decode().rstrip('=')
            payload["cnf"] = {"jkt": thumbprint}
        
        return self.jwk_manager.sign_jwt(payload)
    
    def create_refresh_token(self, user: Dict[str, Any], client_id: str) -> str:
        """Create a refresh token."""
        refresh_token = str(uuid.uuid4())
        self.refresh_tokens[refresh_token] = {
            "user": user,
            "client_id": client_id,
            "created_at": time.time()
        }
        return refresh_token
    
    def validate_refresh_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Validate and consume a refresh token."""
        if refresh_token not in self.refresh_tokens:
            return None
        
        token_data = self.refresh_tokens[refresh_token]
        
        # Check expiration
        if time.time() - token_data["created_at"] > self.config.refresh_token_lifetime:
            del self.refresh_tokens[refresh_token]
            return None
        
        # Consume the token (one-time use)
        del self.refresh_tokens[refresh_token]
        return token_data


class FakeKeycloakHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the fake Keycloak server."""
    
    def __init__(self, config: FakeKeycloakConfig, jwk_manager: JWKManager, 
                 token_manager: TokenManager, auth_codes: Dict[str, Dict[str, Any]], *args, **kwargs):
        self.config = config
        self.jwk_manager = jwk_manager
        self.token_manager = token_manager
        self.auth_codes = auth_codes
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to reduce noise in tests."""
        pass
    
    def _send_json(self, obj: Any, code: int = 200, headers: Optional[Dict[str, str]] = None):
        """Send a JSON response."""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")
        
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode("utf-8"))
    
    def _send_error(self, error: str, description: str = None, code: int = 400):
        """Send an OAuth2/OIDC error response."""
        error_obj = {"error": error}
        if description:
            error_obj["error_description"] = description
        self._send_json(error_obj, code)
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        if path == f"/realms/{self.config.realm}/.well-known/openid-configuration":
            self._handle_discovery()
        elif path == f"/realms/{self.config.realm}/protocol/openid-connect/certs":
            self._handle_jwks()
        elif path == f"/realms/{self.config.realm}/protocol/openid-connect/userinfo":
            self._handle_userinfo()
        elif path == f"/realms/{self.config.realm}/protocol/openid-connect/auth":
            self._handle_authorization(parsed_url)
        else:
            self._send_error("not_found", "Endpoint not found", 404)
    
    def do_POST(self):
        """Handle POST requests."""
        path = self.path
        realm_prefix = f"/realms/{self.config.realm}"
        
        if path == f"{realm_prefix}/protocol/openid-connect/token":
            self._handle_token()
        else:
            self.send_response(404)
            self.end_headers()
    
    def _handle_discovery(self):
        """Handle OpenID Connect discovery."""
        discovery_doc = {
            "issuer": self.config.issuer,
            "authorization_endpoint": f"{self.config.issuer}/protocol/openid-connect/auth",
            "token_endpoint": f"{self.config.issuer}/protocol/openid-connect/token",
            "userinfo_endpoint": f"{self.config.issuer}/protocol/openid-connect/userinfo",
            "jwks_uri": f"{self.config.issuer}/protocol/openid-connect/certs",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "scopes_supported": ["openid", "profile", "email"],
            "grant_types_supported": ["authorization_code", "password", "client_credentials", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
        }
        self._send_json(discovery_doc)
    
    def _handle_jwks(self):
        """Handle JWKS endpoint."""
        self._send_json(self.jwk_manager.get_jwks())
    
    def _handle_userinfo(self):
        """Handle userinfo endpoint."""
        # Extract Bearer token
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            self._send_error("invalid_token", "Missing or invalid authorization header", 401)
            return
        
        token = auth_header[7:]  # Remove "Bearer "
        
        try:
            # Verify the token (skip audience validation for userinfo endpoint)
            payload = jwt.decode(
                token,
                self.jwk_manager.public_key,
                algorithms=["ES256"],
                issuer=self.config.issuer,
                options={"verify_aud": False}
            )
            
            # Find user by sub claim
            user = next((u for u in self.config.users if u["sub"] == payload["sub"]), None)
            if not user:
                self._send_error("invalid_token", "User not found", 401)
                return
            
            # Return user info
            userinfo = {
                "sub": user["sub"],
                "name": user["name"],
                "email": user["email"],
                "preferred_username": user["username"]
            }
            
            self._send_json(userinfo)
            
        except jwt.InvalidTokenError as e:
            self._send_error("invalid_token", str(e), 401)
    
    def _handle_authorization(self, parsed_url):
        """Handle authorization endpoint for PKCE flow."""
        query_params = parse_qs(parsed_url.query)
        
        def get_param(name: str) -> Optional[str]:
            values = query_params.get(name, [])
            return values[0] if values else None
        
        response_type = get_param("response_type")
        client_id = get_param("client_id")
        redirect_uri = get_param("redirect_uri")
        state = get_param("state")
        code_challenge = get_param("code_challenge")
        code_challenge_method = get_param("code_challenge_method")
        dpop_jkt = get_param("dpop_jkt")  # Non-standard DPoP extension parameter
        
        # Validate required parameters
        if response_type != "code":
            self._send_error("unsupported_response_type", "Only authorization code flow supported")
            return
        
        if not client_id or not redirect_uri:
            self._send_error("invalid_request", "Missing required parameters")
            return
        
        # Validate client
        client = next((c for c in self.config.clients if c["client_id"] == client_id), None)
        if not client:
            self._send_error("invalid_client", "Unknown client")
            return
        
        if redirect_uri not in client.get("redirect_uris", []):
            self._send_error("invalid_request", "Invalid redirect_uri")
            return
        
        # For testing, auto-approve with first test user
        user = self.config.users[0] if self.config.users else None
        if not user:
            self._send_error("server_error", "No test users configured")
            return
        
        # Generate authorization code
        auth_code = str(uuid.uuid4())
        
        # Store authorization code data
        self.auth_codes[auth_code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "user": user,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "dpop_jkt": dpop_jkt,  # Store dpop_jkt for token exchange
            "created_at": time.time(),
            "used": False
        }
        
        # Build redirect response
        redirect_params = {"code": auth_code}
        if state:
            redirect_params["state"] = state
        
        redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"
        
        # Send redirect response
        self.send_response(302)
        self.send_header("Location", redirect_url)
        self.end_headers()
    
    def _handle_token(self):
        """Handle token endpoint."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode("utf-8")
            params = parse_qs(body)
            
            # Extract parameters (parse_qs returns lists)
            def get_param(name: str) -> Optional[str]:
                values = params.get(name, [])
                return values[0] if values else None
            
            grant_type = get_param("grant_type")
            client_id = get_param("client_id")
            
            if not grant_type:
                self._send_error("invalid_request", "Missing grant_type parameter")
                return
            
            if not client_id:
                self._send_error("invalid_request", "Missing client_id parameter")
                return
            
            # Validate client
            client = next((c for c in self.config.clients if c["client_id"] == client_id), None)
            if not client:
                self._send_error("invalid_client", "Unknown client", 401)
                return
            
            if grant_type not in client["allowed_grant_types"]:
                self._send_error("unsupported_grant_type", f"Grant type {grant_type} not allowed for this client")
                return
            
            # Extract DPoP JWK if present
            dpop_jwk = self._extract_dpop_jwk(params)
            
            # Handle different grant types
            if grant_type == "password":
                self._handle_password_grant(params, client, dpop_jwk)
            elif grant_type == "client_credentials":
                self._handle_client_credentials_grant(params, client, dpop_jwk)
            elif grant_type == "refresh_token":
                self._handle_refresh_token_grant(params, client, dpop_jwk)
            elif grant_type == "authorization_code":
                self._handle_authorization_code_grant(params, client, dpop_jwk)
            else:
                self._send_error("unsupported_grant_type", f"Grant type {grant_type} not implemented")
                
        except Exception as e:
            self._send_error("server_error", f"Internal error: {str(e)}", 500)
    
    def _extract_dpop_jwk(self, params: Dict[str, List[str]]) -> Optional[Dict[str, Any]]:
        """Extract DPoP JWK from request parameters."""
        dpop_jwk_param = params.get("dpop_jwk")
        if dpop_jwk_param:
            try:
                return json.loads(dpop_jwk_param[0])
            except json.JSONDecodeError:
                pass
        return None
    
    def _handle_password_grant(self, params: Dict[str, List[str]], client: Dict[str, Any], 
                              dpop_jwk: Optional[Dict[str, Any]]):
        """Handle resource owner password credentials grant."""
        def get_param(name: str) -> Optional[str]:
            values = params.get(name, [])
            return values[0] if values else None
        
        username = get_param("username")
        password = get_param("password")
        
        if not username or not password:
            self._send_error("invalid_request", "Missing username or password")
            return
        
        # Validate user credentials
        user = next((u for u in self.config.users 
                    if u["username"] == username and u["password"] == password), None)
        if not user:
            self._send_error("invalid_grant", "Invalid username or password", 401)
            return
        
        # Issue tokens
        access_token = self.token_manager.create_access_token(user, client["client_id"], dpop_jwk)
        refresh_token = self.token_manager.create_refresh_token(user, client["client_id"])
        
        response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.token_lifetime,
            "refresh_token": refresh_token,
            "scope": "openid profile email"
        }
        
        self._send_json(response)
    
    def _handle_client_credentials_grant(self, params: Dict[str, List[str]], 
                                       client: Dict[str, Any], dpop_jwk: Optional[Dict[str, Any]]):
        """Handle client credentials grant."""
        def get_param(name: str) -> Optional[str]:
            values = params.get(name, [])
            return values[0] if values else None
        
        client_secret = get_param("client_secret")
        
        # Validate client secret if required
        if client["client_secret"] and client_secret != client["client_secret"]:
            self._send_error("invalid_client", "Invalid client credentials", 401)
            return
        
        # Create a service user for client credentials
        service_user = {
            "sub": f"service-{client['client_id']}",
            "name": f"Service Account for {client['client_id']}",
            "email": f"{client['client_id']}@service.local"
        }
        
        access_token = self.token_manager.create_access_token(service_user, client["client_id"], dpop_jwk)
        
        response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.token_lifetime,
            "scope": "openid profile email"
        }
        
        self._send_json(response)
    
    def _handle_refresh_token_grant(self, params: Dict[str, List[str]], 
                                  client: Dict[str, Any], dpop_jwk: Optional[Dict[str, Any]]):
        """Handle refresh token grant."""
        def get_param(name: str) -> Optional[str]:
            values = params.get(name, [])
            return values[0] if values else None
        
        refresh_token = get_param("refresh_token")
        
        if not refresh_token:
            self._send_error("invalid_request", "Missing refresh_token parameter")
            return
        
        # Validate refresh token
        token_data = self.token_manager.validate_refresh_token(refresh_token)
        if not token_data or token_data["client_id"] != client["client_id"]:
            self._send_error("invalid_grant", "Invalid refresh token", 401)
            return
        
        # Issue new tokens
        user = token_data["user"]
        access_token = self.token_manager.create_access_token(user, client["client_id"], dpop_jwk)
        new_refresh_token = self.token_manager.create_refresh_token(user, client["client_id"])
        
        response = {
            "access_token": access_token,
            "token_type": "Bearer", 
            "expires_in": self.config.token_lifetime,
            "refresh_token": new_refresh_token,
            "scope": "openid profile email"
        }
        
        self._send_json(response)

    def _handle_authorization_code_grant(self, params: Dict[str, List[str]], 
                                       client: Dict[str, Any], dpop_jwk: Optional[Dict[str, Any]]):
        """Handle authorization code grant with PKCE and DPoP support."""
        import base64
        import hashlib
        
        def get_param(name: str) -> Optional[str]:
            values = params.get(name, [])
            return values[0] if values else None
        
        code = get_param("code")
        redirect_uri = get_param("redirect_uri")
        code_verifier = get_param("code_verifier")
        
        print(f"DEBUG: Token exchange request - code: {code}, redirect_uri: {redirect_uri}")
        print(f"DEBUG: Available auth codes: {list(self.auth_codes.keys())}")
        
        if not code:
            self._send_error("invalid_request", "Missing authorization code")
            return
        
        if not redirect_uri:
            self._send_error("invalid_request", "Missing redirect_uri")
            return
        
        # Validate authorization code
        if code not in self.auth_codes:
            print(f"DEBUG: Code {code} not found in auth_codes")
            self._send_error("invalid_grant", "Invalid authorization code")
            return
        
        auth_data = self.auth_codes[code]
        print(f"DEBUG: Found auth_data: {auth_data}")
        
        # Check if code is already used
        if auth_data["used"]:
            print(f"DEBUG: Code {code} already used")
            self._send_error("invalid_grant", "Authorization code already used")
            return
        
        # Check expiration (5 minutes)
        if time.time() - auth_data["created_at"] > 300:
            print(f"DEBUG: Code {code} expired")
            del self.auth_codes[code]
            self._send_error("invalid_grant", "Authorization code expired")
            return
        
        # Validate client and redirect_uri match
        if auth_data["client_id"] != client["client_id"]:
            print(f"DEBUG: Client mismatch - expected {auth_data['client_id']}, got {client['client_id']}")
            self._send_error("invalid_grant", "Client mismatch")
            return
        
        if auth_data["redirect_uri"] != redirect_uri:
            print(f"DEBUG: Redirect URI mismatch - expected {auth_data['redirect_uri']}, got {redirect_uri}")
            self._send_error("invalid_grant", "Redirect URI mismatch")
            return
        
        # Validate PKCE if code_challenge was provided
        if auth_data.get("code_challenge"):
            if not code_verifier:
                print(f"DEBUG: Missing code_verifier for PKCE")
                self._send_error("invalid_request", "Missing code_verifier for PKCE")
                return
            
            # Verify code challenge
            if auth_data.get("code_challenge_method") == "S256":
                challenge_bytes = hashlib.sha256(code_verifier.encode('ascii')).digest()
                expected_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('ascii').rstrip('=')
                print(f"DEBUG: PKCE validation - expected: {auth_data['code_challenge']}, got: {expected_challenge}")
                if auth_data["code_challenge"] != expected_challenge:
                    self._send_error("invalid_grant", "Invalid code_verifier")
                    return
            else:
                self._send_error("unsupported_challenge_method", "Only S256 challenge method supported")
                return
        
        # Handle DPoP binding - use dpop_jkt from authorization request if no DPoP header
        final_dpop_jwk = dpop_jwk
        if not final_dpop_jwk and auth_data.get("dpop_jkt"):
            # Convert dpop_jkt thumbprint back to JWK for token binding
            # For testing, we'll create a mock JWK with the thumbprint
            final_dpop_jwk = {
                "kty": "EC",
                "crv": "P-256", 
                "x": "mock_x_coordinate",
                "y": "mock_y_coordinate",
                "_jkt": auth_data["dpop_jkt"]  # Store original thumbprint
            }
        
        # Mark code as used
        auth_data["used"] = True
        
        # Issue tokens
        user = auth_data["user"]
        access_token = self.token_manager.create_access_token(user, client["client_id"], final_dpop_jwk)
        refresh_token = self.token_manager.create_refresh_token(user, client["client_id"])
        
        print(f"DEBUG: Successfully issued tokens for user {user['username']}")
        
        response = {
            "access_token": access_token,
            "token_type": "DPoP" if final_dpop_jwk else "Bearer",
            "expires_in": self.config.token_lifetime,
            "refresh_token": refresh_token,
            "scope": "openid profile email"
        }
        
        self._send_json(response)


class FakeKeycloakServer:
    """Main server class for the fake Keycloak OIDC provider."""
    
    def __init__(self, host: str = "localhost", port: int = 9000, config: Optional[FakeKeycloakConfig] = None):
        self.config = config or FakeKeycloakConfig()
        self.config.host = host
        self.config.port = port
        
        self.jwk_manager = JWKManager()
        self.token_manager = TokenManager(self.config, self.jwk_manager)
        
        # Store authorization codes at server level so they persist between requests
        self.auth_codes: Dict[str, Dict[str, Any]] = {}
        
        # Create handler class with dependencies injected
        def handler_factory(*args, **kwargs):
            return FakeKeycloakHandler(self.config, self.jwk_manager, self.token_manager, self.auth_codes, *args, **kwargs)
        
        self.httpd = HTTPServer((host, port), handler_factory)
        self.thread = None
    
    @property
    def issuer(self) -> str:
        return self.config.issuer
    
    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/certs"
    
    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"
    
    def start(self):
        """Start the server in a background thread."""
        if self.thread and self.thread.is_alive():
            return
        
        self.thread = threading.Thread(target=self.httpd.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        time.sleep(0.1)  # Give server time to start
    
    def stop(self):
        """Stop the server."""
        if self.httpd:
            self.httpd.shutdown()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
    
    def add_user(self, username: str, password: str, sub: str = None, **kwargs):
        """Add a test user."""
        user = {
            "username": username,
            "password": password,
            "sub": sub or str(uuid.uuid4()),
            "email": kwargs.get("email", f"{username}@example.com"),
            "name": kwargs.get("name", username.title())
        }
        self.config.users.append(user)
    
    def add_client(self, client_id: str, client_secret: str = None, 
                   allowed_grant_types: List[str] = None, **kwargs):
        """Add a test client."""
        client = {
            "client_id": client_id,
            "client_secret": client_secret,
            "allowed_grant_types": allowed_grant_types or ["password"],
            "redirect_uris": kwargs.get("redirect_uris", [])
        }
        self.config.clients.append(client)


if __name__ == "__main__":
    server = FakeKeycloakServer()
    print(f"Fake Keycloak OIDC Provider starting at {server.issuer}")
    print(f"JWKS URI: {server.jwks_uri}")
    print(f"Token endpoint: {server.token_endpoint}")
    print("\nTest users:")
    for user in server.config.users:
        print(f"  - {user['username']} / {user['password']} (sub: {user['sub']})")
    print("\nTest clients:")
    for client in server.config.clients:
        print(f"  - {client['client_id']} (grants: {', '.join(client['allowed_grant_types'])})")
    
    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping fake Keycloak...")
        server.stop() 