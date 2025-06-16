#!/usr/bin/env python3
"""
Debug script to check DPoP binding issue.
"""

import sys
import os
import json
import jwt

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'prototype', 'src'))

from openadp.auth.dpop import calculate_jwk_thumbprint

def debug_token_binding():
    """Debug the DPoP token binding issue."""
    
    # Load the cached token data
    token_cache_path = os.path.expanduser("~/.openadp/tokens.json")
    
    if not os.path.exists(token_cache_path):
        print("❌ No cached tokens found. Run encrypt.py first.")
        return
    
    with open(token_cache_path, 'r') as f:
        token_data = json.load(f)
    
    access_token = token_data['access_token']
    jwk_public = token_data['jwk_public']
    
    print("🔍 Debugging DPoP Token Binding")
    print("=" * 50)
    
    # 1. Decode JWT token (without verification)
    try:
        unverified_payload = jwt.decode(access_token, options={"verify_signature": False})
        print("✅ JWT Token Decoded Successfully")
        print(f"   Subject (sub): {unverified_payload.get('sub')}")
        print(f"   Issuer (iss): {unverified_payload.get('iss')}")
        
        # Check cnf claim
        cnf_claim = unverified_payload.get('cnf', {})
        token_thumbprint = cnf_claim.get('jkt')
        
        if token_thumbprint:
            print(f"✅ Token contains cnf.jkt: {token_thumbprint}")
        else:
            print("❌ Token missing cnf.jkt claim!")
            print(f"   Available claims: {list(unverified_payload.keys())}")
            print(f"   cnf claim: {cnf_claim}")
            
    except Exception as e:
        print(f"❌ Failed to decode JWT: {e}")
        return
    
    # 2. Calculate JWK thumbprint from public key
    try:
        calculated_thumbprint = calculate_jwk_thumbprint(jwk_public)
        print(f"✅ Calculated JWK thumbprint: {calculated_thumbprint}")
    except Exception as e:
        print(f"❌ Failed to calculate JWK thumbprint: {e}")
        return
    
    # 3. Compare thumbprints
    print("\n🔍 Thumbprint Comparison:")
    print(f"   Token cnf.jkt:  {token_thumbprint}")
    print(f"   Calculated:     {calculated_thumbprint}")
    
    if token_thumbprint == calculated_thumbprint:
        print("✅ Thumbprints MATCH - DPoP binding should work!")
    else:
        print("❌ Thumbprints DO NOT MATCH - This is the problem!")
        
        # Debug the JWK structure
        print("\n🔍 JWK Structure Debug:")
        print(f"   JWK: {json.dumps(jwk_public, indent=2)}")
        
        # Check if it's a key ordering issue
        print("\n🔍 Checking key ordering...")
        sorted_jwk = dict(sorted(jwk_public.items()))
        print(f"   Sorted JWK: {json.dumps(sorted_jwk, indent=2)}")
        
        try:
            sorted_thumbprint = calculate_jwk_thumbprint(sorted_jwk)
            print(f"   Sorted thumbprint: {sorted_thumbprint}")
        except Exception as e:
            print(f"   Error with sorted: {e}")

if __name__ == "__main__":
    debug_token_binding() 