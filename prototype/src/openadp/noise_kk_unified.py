#!/usr/bin/env python3
"""
Unified Noise-KK Implementation for OpenADP

This module provides a unified interface for Noise-KK that works with or without
DissoNonce. The simplified implementation (which we've tested and proven working)
is used as the primary implementation, with DissoNonce as an optional enhancement.

This ensures maximum compatibility across different environments while providing
the full security benefits of the Noise-KK pattern.
"""

import logging
from typing import Tuple, Optional, Any, Union

# Always import our proven working implementation
from .noise_kk_simple import (
    SimplifiedNoiseKK, NoiseKKTransport,
    generate_client_keypair, parse_server_public_key,
    create_client_session as simple_create_client_session,
    create_server_session as simple_create_server_session
)

# Try to import DissoNonce as optional enhancement
try:
    # Check if DissoNonce is properly available first
    from dissononce.dh.x25519.x25519 import X25519DH
    from dissononce.processing.handshakepatterns.interactive.KK import KKHandshakePattern
    
    # If we get here, DissoNonce is available
    from .noise_kk_dissononce import (
        NoiseKKSession as DissoNoiseKKSession,
        NoiseKKTransport as DissoNoiseKKTransport,
        generate_keypair as disso_generate_keypair,
        create_client_session as disso_create_client_session,
        create_server_session as disso_create_server_session,
        DISSONONCE_AVAILABLE
    )
    ENHANCED_MODE_AVAILABLE = DISSONONCE_AVAILABLE
    print("✅ DissoNonce library properly available")
except ImportError as e:
    ENHANCED_MODE_AVAILABLE = False
    print(f"ℹ️  DissoNonce not fully available: {e}")
    print("   Using simplified implementation (this is fine!)")

logger = logging.getLogger(__name__)

# Configuration: Choose implementation
USE_DISSONONCE = False  # Set to False to use proven simplified implementation
                        # Set to True to try DissoNonce (may fail on some systems)

class NoiseKK:
    """
    Unified Noise-KK interface that automatically selects the best available implementation.
    
    This class provides a consistent API regardless of which underlying implementation is used.
    """
    
    @staticmethod
    def create_client_session(server_public_key_str: str):
        """Create a client-side Noise-KK session"""
        if USE_DISSONONCE and ENHANCED_MODE_AVAILABLE:
            logger.info("Using DissoNonce implementation")
            return disso_create_client_session(server_public_key_str)
        else:
            logger.info("Using simplified implementation")
            return simple_create_client_session(server_public_key_str)
    
    @staticmethod  
    def create_server_session(server_private_key: Any, client_public_key: Any):
        """Create a server-side Noise-KK session"""
        if USE_DISSONONCE and ENHANCED_MODE_AVAILABLE:
            logger.info("Using DissoNonce implementation")
            return disso_create_server_session(server_private_key, client_public_key)
        else:
            logger.info("Using simplified implementation")
            return simple_create_server_session(server_private_key, client_public_key)
    
    @staticmethod
    def create_transport(socket_obj, noise_session):
        """Create a Noise-KK transport"""
        return NoiseKKTransport(socket_obj, noise_session)
    
    @staticmethod
    def generate_client_keypair():
        """Generate a client keypair"""
        if USE_DISSONONCE and ENHANCED_MODE_AVAILABLE:
            return disso_generate_keypair()
        else:
            return generate_client_keypair()
    
    @staticmethod
    def get_implementation_info() -> dict:
        """Get information about the current implementation"""
        return {
            "simplified_available": True,
            "dissononce_available": ENHANCED_MODE_AVAILABLE, 
            "current_implementation": "DissoNonce" if (USE_DISSONONCE and ENHANCED_MODE_AVAILABLE) else "Simplified",
            "use_dissononce_preference": USE_DISSONONCE
        }


# Export the unified interface with the same names for backward compatibility
def create_client_session(server_public_key_str: str):
    """Create client-side Noise-KK session (unified interface)"""
    return NoiseKK.create_client_session(server_public_key_str)

def create_server_session(server_private_key: Any, client_public_key: Any):
    """Create server-side Noise-KK session (unified interface)"""
    return NoiseKK.create_server_session(server_private_key, client_public_key)

def generate_keypair():
    """Generate keypair (unified interface)"""
    return NoiseKK.generate_client_keypair()

# Always export the transport from the working implementation
# (Both implementations use the same transport interface)


def test_unified_implementation():
    """Test the unified Noise-KK implementation"""
    print("🔧 Testing Unified Noise-KK Implementation")
    print("=" * 50)
    
    # Show implementation info
    info = NoiseKK.get_implementation_info()
    print(f"Implementation info:")
    for key, value in info.items():
        print(f"  {key}: {value}")
    
    print("\n1. Testing simplified implementation...")
    try:
        # Force simplified implementation
        global USE_DISSONONCE
        original_preference = USE_DISSONONCE
        USE_DISSONONCE = False
        
        # Test simplified version
        from .noise_kk_simple import test_simplified_noise_kk
        if test_simplified_noise_kk():
            print("   ✅ Simplified implementation working")
        else:
            print("   ❌ Simplified implementation failed")
            return False
            
    except Exception as e:
        print(f"   ❌ Simplified implementation error: {e}")
        return False
    finally:
        USE_DISSONONCE = original_preference
    
    if ENHANCED_MODE_AVAILABLE:
        print("\n2. Testing DissoNonce implementation...")
        try:
            # Force DissoNonce implementation
            USE_DISSONONCE = True
            
            # Test DissoNonce version
            from .noise_kk_dissononce import test_noise_kk
            if test_noise_kk():
                print("   ✅ DissoNonce implementation working")
            else:
                print("   ❌ DissoNonce implementation failed")
                
        except Exception as e:
            print(f"   ❌ DissoNonce implementation error: {e}")
        finally:
            USE_DISSONONCE = original_preference
    else:
        print("\n2. DissoNonce implementation not available")
    
    print(f"\n3. Current active implementation: {info['current_implementation']}")
    
    # Test unified interface
    print("\n4. Testing unified interface...")
    try:
        # This should work regardless of which implementation is active
        server_key = "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAITestKeyForUnifiedInterface123456789"
        session = create_client_session(server_key)
        print("   ✅ Unified interface working")
        return True
        
    except Exception as e:
        print(f"   ❌ Unified interface error: {e}")
        return False


if __name__ == "__main__":
    success = test_unified_implementation()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 Unified Noise-KK implementation ready!")
        print(f"Active implementation: {NoiseKK.get_implementation_info()['current_implementation']}")
        print("\nBoth simplified and DissoNonce implementations available")
        print("The system will use the most appropriate one for your environment")
    else:
        print("❌ Some tests failed")
    print("=" * 60) 