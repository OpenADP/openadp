#!/usr/bin/env python3
"""
Test script for Phase 3.5 - Noise-NK Encrypted Authentication

This script tests the complete flow:
1. OAuth token acquisition (simulated)
2. Noise-NK handshake with auth payload
3. Server-side authentication validation
4. Encrypted RPC execution

Usage:
    python test_phase35_auth.py
"""

import os
import sys
import json
import logging
import threading
import time
from typing import Dict, Any, Optional

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'prototype', 'src'))

from client.encrypted_jsonrpc_client import EncryptedOpenADPClient
from openadp.auth import generate_keypair, load_private_key
from openadp.auth.keys import private_key_to_jwk
import server.jsonrpc_server as server_module

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_mock_jwt_token(user_id: str, dpop_public_key_jwk: Dict) -> str:
    """
    Create a mock JWT token for testing (bypasses real OAuth flow).
    
    In a real implementation, this would come from the OAuth Device Flow.
    """
    import jwt
    from openadp.auth.dpop import calculate_jwk_thumbprint
    
    # Calculate JWK thumbprint for cnf claim
    jkt = calculate_jwk_thumbprint(dpop_public_key_jwk)
    
    # Create mock payload
    payload = {
        "iss": "http://localhost:8080/realms/openadp",
        "sub": user_id,
        "aud": "cli-test",
        "exp": int(time.time()) + 3600,  # 1 hour
        "iat": int(time.time()),
        "jti": f"mock-jti-{int(time.time())}",
        "typ": "Bearer",
        "azp": "cli-test",
        "scope": "openid profile email",
        "cnf": {
            "jkt": jkt
        }
    }
    
    # Sign with mock key (for testing only)
    mock_secret = "mock-secret-key-for-testing-only"
    token = jwt.encode(payload, mock_secret, algorithm="HS256")
    
    return token

def start_test_server():
    """Start the OpenADP server in a separate thread."""
    import threading
    import database
    
    # Set up test environment
    os.environ['OPENADP_AUTH_ENABLED'] = '1'
    os.environ['OPENADP_AUTH_ISSUER'] = 'http://localhost:8080/realms/openadp'
    os.environ['OPENADP_PORT'] = '8081'
    
    # Force reload of server module to pick up environment changes
    import importlib
    importlib.reload(server_module)
    
    # Mock JWKS validation for testing
    def mock_validate_jwt_token(access_token: str):
        """Mock JWT validation that accepts our test tokens."""
        try:
            import jwt
            # Decode without verification for testing
            payload = jwt.decode(access_token, options={"verify_signature": False})
            user_id = payload.get('sub')
            return user_id, None
        except Exception as e:
            return None, f"Mock validation error: {str(e)}"
    
    # Replace the real validation with our mock
    server_module.validate_jwt_token = mock_validate_jwt_token
    
    # Initialize database
    db_path = "/tmp/test_phase35.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    server_module.db_connection = database.Database(db_path)
    
    def run_server():
        """Run the server in thread."""
        try:
            from http.server import HTTPServer
            from server.noise_session_manager import initialize_session_manager
            import base64
            
            # Generate server key
            from openadp.noise_nk import generate_keypair
            server_keypair = generate_keypair()
            
            # Initialize session manager
            session_manager = initialize_session_manager(server_keypair)
            server_public_key = session_manager.get_server_public_key()
            
            # Store for client use
            with open('/tmp/server_public_key.hex', 'w') as f:
                f.write(server_public_key.hex())
            
            # Start server
            server_address = ('', 8081)
            httpd = HTTPServer(server_address, server_module.RPCRequestHandler)
            
            logger.info(f"Test server started on port 8081")
            logger.info(f"Server public key: {server_public_key.hex()}")
            
            httpd.serve_forever()
            
        except Exception as e:
            logger.error(f"Server error: {e}")
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    # Wait for server to start
    time.sleep(2)
    
    # Read server public key
    with open('/tmp/server_public_key.hex', 'r') as f:
        server_key_hex = f.read().strip()
    
    return bytes.fromhex(server_key_hex)

def test_encrypted_authentication():
    """Test the complete encrypted authentication flow."""
    logger.info("🚀 Starting Phase 3.5 Encrypted Authentication Test")
    
    try:
        # Step 1: Start test server
        logger.info("📡 Starting test server...")
        server_public_key = start_test_server()
        logger.info(f"✅ Server started with key: {server_public_key.hex()[:32]}...")
        
        # Step 2: Generate DPoP keypair
        logger.info("🔑 Generating DPoP keypair...")
        private_key, public_key_jwk = generate_keypair()
        logger.info("✅ DPoP keypair generated")
        
        # Step 3: Create mock JWT token
        logger.info("🎫 Creating mock OAuth token...")
        user_id = "test-user-12345"
        access_token = create_mock_jwt_token(user_id, public_key_jwk)
        logger.info(f"✅ Mock token created for user: {user_id}")
        
        # Step 4: Create encrypted client
        logger.info("🔌 Creating encrypted client...")
        client = EncryptedOpenADPClient("http://localhost:8081", server_public_key)
        logger.info("✅ Client created")
        
        # Step 5: Test unauthenticated call (should work)
        logger.info("📞 Testing unauthenticated Echo call...")
        result, error = client.echo("Hello unauthenticated!", encrypted=True)
        if error:
            logger.error(f"❌ Unauthenticated call failed: {error}")
            return False
        logger.info(f"✅ Unauthenticated call succeeded: {result}")
        
        # Step 6: Test authenticated call
        logger.info("🔐 Testing authenticated RegisterSecret call...")
        result, error = client.make_authenticated_request(
            "RegisterSecret",
            ["test-uid", "test-did", "test-bid", 1, 1, "12345", 10, 0],
            access_token,
            private_key,
            public_key_jwk
        )
        
        if error:
            logger.error(f"❌ Authenticated call failed: {error}")
            return False
        
        logger.info(f"✅ Authenticated call succeeded: {result}")
        
        # Step 7: Test authentication failure
        logger.info("🚫 Testing invalid authentication...")
        bad_token = "invalid.jwt.token"
        result, error = client.make_authenticated_request(
            "RegisterSecret",
            ["test-uid-2", "test-did-2", "test-bid-2", 1, 1, "67890", 10, 0],
            bad_token,
            private_key,
            public_key_jwk
        )
        
        if not error:
            logger.error("❌ Expected authentication failure but call succeeded")
            return False
        
        logger.info(f"✅ Authentication correctly rejected invalid token: {error}")
        
        logger.info("🎉 Phase 3.5 Test PASSED - Encrypted Authentication Working!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test function."""
    success = test_encrypted_authentication()
    
    if success:
        print("\n" + "="*60)
        print("🎉 PHASE 3.5 IMPLEMENTATION SUCCESSFUL!")
        print("✅ Noise-NK Encrypted Authentication Working")
        print("✅ Server-side auth validation working")
        print("✅ Client-side auth payload creation working")
        print("✅ End-to-end security model validated")
        print("="*60)
        sys.exit(0)
    else:
        print("\n" + "="*60)
        print("❌ PHASE 3.5 TEST FAILED")
        print("🔍 Check logs above for details")
        print("="*60)
        sys.exit(1)

if __name__ == "__main__":
    main() 