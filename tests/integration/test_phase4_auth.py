#!/usr/bin/env python3
"""
Test script for Phase 4 - JWT Sub as UID

This script tests the complete Phase 4 flow:
1. JWT authentication with user_id extraction
2. Encryption using JWT sub as UID
3. Decryption using same JWT sub 
4. Server-side ownership validation

Usage:
    python test_phase4_auth.py
"""

import os
import sys
import json
import logging
import threading
import time
import tempfile
from typing import Dict, Any, Optional

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'prototype', 'src'))

from client.jsonrpc_client import EncryptedOpenADPClient
from openadp.auth import generate_keypair
from openadp.auth.keys import private_key_to_jwk
import server.jsonrpc_server as server_module

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_mock_jwt_token_with_sub(user_id: str, dpop_public_key_jwk: Dict) -> str:
    """
    Create a mock JWT token with specified sub claim for testing.
    
    Args:
        user_id: UUID to use as JWT sub claim
        dpop_public_key_jwk: DPoP public key for token binding
        
    Returns:
        JWT token string
    """
    import jwt
    from openadp.auth.dpop import calculate_jwk_thumbprint
    
    # Calculate JWK thumbprint for cnf claim
    jkt = calculate_jwk_thumbprint(dpop_public_key_jwk)
    
    # Create payload with UUID as sub
    payload = {
        "iss": "http://localhost:8080/realms/openadp",
        "sub": user_id,  # This is now a UUID, not email
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
    """Start the OpenADP server in a separate thread for testing."""
    import threading
    import database
    
    # Set up test environment
    os.environ['OPENADP_AUTH_ENABLED'] = '1'
    os.environ['OPENADP_AUTH_ISSUER'] = 'http://localhost:8080/realms/openadp'
    os.environ['OPENADP_PORT'] = '8082'
    
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
    db_path = "/tmp/test_phase4.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    server_module.db_connection = database.Database(db_path)
    
    def run_server():
        """Run the server in thread."""
        try:
            from http.server import HTTPServer
            from server.noise_session_manager import initialize_session_manager
            
            # Generate server key
            from openadp.noise_nk import generate_keypair
            server_keypair = generate_keypair()
            
            # Initialize session manager
            session_manager = initialize_session_manager(server_keypair)
            server_public_key = session_manager.get_server_public_key()
            
            # Store for client use
            with open('/tmp/server_public_key_phase4.hex', 'w') as f:
                f.write(server_public_key.hex())
            
            # Start server
            server_address = ('', 8082)
            httpd = HTTPServer(server_address, server_module.RPCRequestHandler)
            
            logger.info(f"Phase 4 test server started on port 8082")
            logger.info(f"Server public key: {server_public_key.hex()}")
            
            httpd.serve_forever()
            
        except Exception as e:
            logger.error(f"Server error: {e}")
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    # Wait for server to start
    time.sleep(2)
    
    # Read server public key
    with open('/tmp/server_public_key_phase4.hex', 'r') as f:
        server_key_hex = f.read().strip()
    
    return bytes.fromhex(server_key_hex)

def test_phase4_authentication():
    """Test the complete Phase 4 authentication and ownership validation flow."""
    logger.info("🚀 Starting Phase 4 Authentication Test")
    
    try:
        # Step 1: Start test server
        logger.info("📡 Starting test server...")
        server_public_key = start_test_server()
        logger.info(f"✅ Server started with key: {server_public_key.hex()[:32]}...")
        
        # Step 2: Create two different users with UUIDs
        logger.info("👥 Creating test users...")
        user1_id = "a1b2c3d4-e5f6-7890-1234-567890abcdef"  # UUID format
        user2_id = "f1e2d3c4-b5a6-9870-4321-0987654321fe"  # Different UUID
        
        # Generate DPoP keypairs for both users
        private_key1, public_key_jwk1 = generate_keypair()
        private_key2, public_key_jwk2 = generate_keypair()
        
        # Create JWT tokens with UUIDs as sub claims
        access_token1 = create_mock_jwt_token_with_sub(user1_id, public_key_jwk1)
        access_token2 = create_mock_jwt_token_with_sub(user2_id, public_key_jwk2)
        
        logger.info(f"✅ Created test users: {user1_id[:8]}... and {user2_id[:8]}...")
        
        # Step 3: Create encrypted client
        logger.info("🔌 Creating encrypted client...")
        client = EncryptedOpenADPClient("http://localhost:8082", server_public_key)
        logger.info("✅ Client created")
        
        # Step 4: Test User 1 registration
        logger.info("📝 Testing User 1 secret registration...")
        result, error = client.make_authenticated_request(
            "RegisterSecret",
            ["dummy-uid", "test-device", "test-backup", 1, 1, "12345", 10, 0],  # UID will be replaced by server
            access_token1,
            private_key1,
            public_key_jwk1
        )
        
        if error:
            logger.error(f"❌ User 1 registration failed: {error}")
            return False
            
        logger.info(f"✅ User 1 registration succeeded: {result}")
        
        # Step 5: Test User 1 can list their backups
        logger.info("📋 Testing User 1 backup listing...")
        result, error = client.make_authenticated_request(
            "ListBackups", 
            ["dummy-uid"],  # UID will be replaced by server
            access_token1,
            private_key1,
            public_key_jwk1
        )
        
        if error:
            logger.error(f"❌ User 1 list backups failed: {error}")
            return False
            
        logger.info(f"✅ User 1 backup listing succeeded: {result}")
        if result:
            logger.info(f"   Found {len(result)} backups for user 1")
        
        # Step 6: Test User 2 cannot access User 1's data
        logger.info("🚫 Testing User 2 cannot access User 1's backup...")
        result, error = client.make_authenticated_request(
            "RecoverSecret",
            ["dummy-uid", "test-device", "test-backup", "12345", 0],  # UID will be replaced
            access_token2,  # User 2's token
            private_key2,   # User 2's key
            public_key_jwk2 # User 2's JWK
        )
        
        # This should fail because User 2 shouldn't have access to User 1's data
        if error and "not found" in error.lower():
            logger.info(f"✅ User 2 correctly cannot access User 1's data: {error}")
        else:
            logger.error(f"❌ Security violation: User 2 accessed User 1's data: {result}")
            return False
        
        # Step 7: Test User 2 can register their own data
        logger.info("📝 Testing User 2 can register their own secret...")
        result, error = client.make_authenticated_request(
            "RegisterSecret",
            ["dummy-uid", "test-device", "user2-backup", 1, 2, "67890", 10, 0],  # Different backup ID
            access_token2,
            private_key2,
            public_key_jwk2
        )
        
        if error:
            logger.error(f"❌ User 2 registration failed: {error}")
            return False
            
        logger.info(f"✅ User 2 registration succeeded: {result}")
        
        # Step 8: Test User 2 can access their own data
        logger.info("🔓 Testing User 2 can recover their own secret...")
        result, error = client.make_authenticated_request(
            "RecoverSecret",
            ["dummy-uid", "test-device", "user2-backup", "67890", 0],  # Their backup
            access_token2,
            private_key2,
            public_key_jwk2
        )
        
        if error:
            logger.error(f"❌ User 2 recovery failed: {error}")
            return False
            
        logger.info(f"✅ User 2 recovery succeeded: {result}")
        
        logger.info("🎉 Phase 4 Authentication Test PASSED!")
        logger.info("✅ JWT sub used as UID successfully")
        logger.info("✅ Ownership validation working correctly") 
        logger.info("✅ Users properly isolated from each other")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run the Phase 4 test."""
    logger.info("=" * 60)
    logger.info("Phase 4 - JWT Sub as UID Test")
    logger.info("=" * 60)
    
    success = test_phase4_authentication()
    
    if success:
        logger.info("🎉 All Phase 4 tests PASSED!")
        sys.exit(0)
    else:
        logger.error("❌ Phase 4 tests FAILED!")
        sys.exit(1)

if __name__ == "__main__":
    main() 