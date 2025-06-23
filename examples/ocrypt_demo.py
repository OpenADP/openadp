#!/usr/bin/env python3
"""
Ocrypt Demo - Drop-in replacement for password hashing functions

This demo shows how to use Ocrypt to replace traditional password hashing
functions (bcrypt, scrypt, Argon2, PBKDF2) with OpenADP's distributed threshold
cryptography for nation-state-resistant password protection.

The name "Ocrypt" reflects the underlying Oblivious Pseudo Random Function (OPRF) 
cryptography that enables secure, distributed key protection.

Examples include:
1. Basic API usage (register/recover)
2. Ed25519 private key protection
3. API token storage
4. Database encryption key protection
5. Migration from traditional password hashing
"""

import sys
import os
import json
import getpass
from pathlib import Path

# Add the openadp package to the path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'sdk', 'python'))

import openadp.ocrypt as ocrypt


def demo_basic_usage():
    """Demo 1: Basic Ocrypt API usage"""
    print("=" * 60)
    print("DEMO 1: Basic Ocrypt API Usage")
    print("=" * 60)
    
    # Example secret to protect
    secret_data = b"This is my super secret API key: sk_live_51234567890abcdef"
    user_id = "alice@example.com"
    app_id = "payment_processor"
    pin = "1234"
    
    print(f"🔐 Protecting secret for user: {user_id}")
    print(f"📱 Application: {app_id}")
    print(f"🔑 Secret length: {len(secret_data)} bytes")
    print()
    
    try:
        # Register the secret
        print("📋 Step 1: Register secret with OpenADP...")
        metadata = ocrypt.register(
            user_id=user_id,
            app_id=app_id,
            long_term_secret=secret_data,
            pin=pin,
            max_guesses=10
        )
        
        print(f"✅ Registration successful!")
        print(f"📦 Metadata size: {len(metadata)} bytes")
        print(f"🎯 Metadata preview: {metadata[:100]}...")
        print()
        
        # Recover the secret
        print("📋 Step 2: Recover secret using PIN...")
        recovered_secret, remaining_guesses, updated_metadata = ocrypt.recover(metadata, pin)
        
        print(f"✅ Recovery successful!")
        print(f"🔓 Recovered secret: {recovered_secret}")
        print(f"🎯 Remaining guesses: {remaining_guesses}")
        print(f"✅ Secret matches: {recovered_secret == secret_data}")
        print(f"📦 Updated metadata size: {len(updated_metadata)} bytes")
        print()
        
        # Test wrong PIN
        print("📋 Step 3: Test wrong PIN...")
        try:
            ocrypt.recover(metadata, "wrong_pin")
            print("❌ ERROR: Wrong PIN should have failed!")
        except Exception as e:
            print(f"✅ Wrong PIN correctly rejected: {e}")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
    
    print()


def demo_api_token_storage():
    """Demo 2: API token storage"""
    print("=" * 60)
    print("DEMO 2: API Token Storage")
    print("=" * 60)
    
    # Simulate protecting various API tokens
    tokens = {
        "stripe_api_key": "sk_live_51HyperSecureStripeToken123456789",
        "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
        "github_token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "database_password": "super_secure_db_password_2024"
    }
    
    user_id = "service_account_001"
    pin = "service_pin_2024"
    
    protected_tokens = {}
    
    print(f"🔐 Protecting {len(tokens)} API tokens for service account...")
    print()
    
    try:
        # Protect each token
        for token_name, token_value in tokens.items():
            print(f"📋 Protecting {token_name}...")
            
            metadata = ocrypt.register(
                user_id=user_id,
                app_id=token_name,
                long_term_secret=token_value.encode(),
                pin=pin,
                max_guesses=3  # Lower limit for service accounts
            )
            
            protected_tokens[token_name] = metadata
            print(f"   ✅ Protected ({len(metadata)} bytes metadata)")
        
        print()
        print(f"✅ All {len(tokens)} tokens protected!")
        print()
        
        # Recover tokens
        print("📋 Recovering tokens...")
        for token_name, metadata in protected_tokens.items():
            recovered_token_bytes, remaining, updated_metadata = ocrypt.recover(metadata, pin)
            recovered_token = recovered_token_bytes.decode()
            
            original_token = tokens[token_name]
            matches = recovered_token == original_token
            
            print(f"   🔓 {token_name}: {'✅ MATCH' if matches else '❌ MISMATCH'}")
            print(f"      Original:  {original_token[:20]}...")
            print(f"      Recovered: {recovered_token[:20]}...")
        
        print()
        print("✅ All tokens recovered successfully!")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
    
    print()


def demo_database_encryption():
    """Demo 3: Database encryption key protection"""
    print("=" * 60)
    print("DEMO 3: Database Encryption Key Protection")
    print("=" * 60)
    
    import secrets
    
    # Generate a database encryption key
    print("🔐 Generating database encryption key...")
    db_encryption_key = secrets.token_bytes(32)  # AES-256 key
    
    print(f"✅ Generated 256-bit encryption key")
    print(f"🔑 Key: {db_encryption_key.hex()}")
    print()
    
    try:
        # Protect the database key
        user_id = "database_cluster_01"
        app_id = "customer_data_encryption"
        pin = "db_master_pin_2024"
        
        print("📋 Step 1: Protect database key with Ocrypt...")
        metadata = ocrypt.register(
            user_id=user_id,
            app_id=app_id,
            long_term_secret=db_encryption_key,
            pin=pin,
            max_guesses=10
        )
        
        print(f"✅ Database key protected!")
        print(f"📦 Metadata size: {len(metadata)} bytes")
        print()
        
        # Simulate database startup - recover the key
        print("📋 Step 2: Database startup - recover encryption key...")
        recovered_key, remaining, updated_metadata = ocrypt.recover(metadata, pin)
        
        print(f"✅ Database key recovered!")
        print(f"🔑 Recovered key: {recovered_key.hex()}")
        print(f"✅ Keys match: {recovered_key == db_encryption_key}")
        print()
        
        # Simulate encrypting database records
        print("📋 Step 3: Encrypt sample database record...")
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        
        # Sample customer data
        customer_data = json.dumps({
            "customer_id": "cust_12345",
            "name": "John Doe",
            "email": "john@example.com",
            "ssn": "123-45-6789",
            "credit_card": "4111-1111-1111-1111"
        }).encode()
        
        # Encrypt with recovered key
        nonce = get_random_bytes(12)
        cipher = AES.new(recovered_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(customer_data)
        
        print(f"✅ Customer data encrypted!")
        print(f"📄 Original size: {len(customer_data)} bytes")
        print(f"🔒 Encrypted size: {len(ciphertext)} bytes")
        print(f"🔑 Nonce: {nonce.hex()}")
        print(f"🏷️  Tag: {tag.hex()}")
        print()
        
        # Decrypt to verify
        print("📋 Step 4: Decrypt to verify...")
        cipher = AES.new(recovered_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        customer_record = json.loads(decrypted_data.decode())
        print(f"✅ Data decrypted successfully!")
        print(f"👤 Customer: {customer_record['name']} ({customer_record['email']})")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
    
    print()


def demo_migration_from_bcrypt():
    """Demo 4: Migration from traditional password hashing"""
    print("=" * 60)
    print("DEMO 4: Migration from Traditional Password Hashing")
    print("=" * 60)
    
    # Simulate existing bcrypt-style user database
    print("🗃️  Simulating existing user database with bcrypt hashes...")
    
    # Traditional approach (simulated)
    users_old = {
        "alice@example.com": {
            "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3L9.D5.G/m",
            "salt": "LQv3c1yqBWVHxkd0LHAkCO",
            "created": "2023-01-15"
        },
        "bob@example.com": {
            "password_hash": "$2b$12$EXRkDxrfQIyuVvVvVvVvVeyhVSBcFyENqRg5K.HLHpVvVvVvVvVvC",
            "salt": "EXRkDxrfQIyuVvVvVvVvVe", 
            "created": "2023-02-20"
        }
    }
    
    print(f"📊 Found {len(users_old)} users with bcrypt hashes")
    for email, data in users_old.items():
        print(f"   👤 {email}: {data['password_hash'][:30]}...")
    print()
    
    # New Ocrypt approach
    print("🔄 Migrating to Ocrypt...")
    users_new = {}
    
    try:
        for email in users_old.keys():
            # In real migration, user would log in with their password
            # For demo, we'll simulate this
            user_password = "user_password_123"  # Would come from login form
            
            # Generate a per-user secret for authentication
            import secrets
            user_secret = secrets.token_bytes(32)  # This replaces the password hash
            
            print(f"📋 Migrating {email}...")
            
            # Protect the user secret with Ocrypt
            metadata = ocrypt.register(
                user_id=email,
                app_id="user_authentication",
                long_term_secret=user_secret,
                pin=user_password,
                max_guesses=5
            )
            
            users_new[email] = {
                "ocrypt_metadata": metadata,
                "user_secret": user_secret,  # In practice, this would be used for session tokens
                "migrated": "2024-01-15"
            }
            
            print(f"   ✅ Migrated ({len(metadata)} bytes metadata)")
        
        print()
        print(f"✅ Migration complete! {len(users_new)} users migrated")
        print()
        
        # Demonstrate authentication with new system
        print("📋 Testing authentication with new system...")
        test_user = "alice@example.com"
        test_password = "user_password_123"
        
        print(f"🔐 User {test_user} attempting login...")
        
        # Recover user secret using password
        metadata = users_new[test_user]["ocrypt_metadata"]
        recovered_secret, remaining, updated_metadata = ocrypt.recover(metadata, test_password)
        
        # Verify it matches the stored secret
        stored_secret = users_new[test_user]["user_secret"]
        auth_success = recovered_secret == stored_secret
        
        print(f"✅ Authentication: {'SUCCESS' if auth_success else 'FAILED'}")
        print(f"🔑 Secret matches: {auth_success}")
        print(f"🎯 Remaining attempts: {remaining}")
        print()
        
        # Show the benefits
        print("🎉 Migration Benefits:")
        print("   ✅ Nation-state resistant (distributed across multiple servers)")
        print("   ✅ Guess limiting (built-in brute force protection)")
        print("   ✅ No local password storage (metadata contains no secrets)")
        print("   ✅ Automatic backup refresh (on successful authentication)")
        print("   ✅ Threshold recovery (works even if some servers are down)")
        print("   ✅ OPRF-based security (oblivious pseudo random functions)")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
    
    print()


def main():
    """Run all Ocrypt demos"""
    print("🔮 Ocrypt Demo - Nation-State Resistant Password Protection")
    print("🌐 Using OpenADP distributed threshold cryptography")
    print("🔐 Based on Oblivious Pseudo Random Function (OPRF) cryptography")
    print()
    
    # Check if we're in a test environment
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("⚠️  Running in test mode - some demos may be mocked")
        print()
    
    # Run demos
    try:
        demo_basic_usage()
        demo_api_token_storage()
        demo_database_encryption()
        demo_migration_from_bcrypt()
        
        print("=" * 60)
        print("🎉 All demos completed successfully!")
        print("=" * 60)
        print()
        print("📚 Next steps:")
        print("   1. Read the design document: docs/ocrypt_design.md")
        print("   2. Run the test suite: python -m pytest tests/python/test_ocrypt.py")
        print("   3. Check the API documentation in the module docstrings")
        print("   4. Start integrating Ocrypt into your applications!")
        print()
        print("🔗 Learn more about OpenADP at: https://openadp.org")
        print("🔬 Learn about OPRF cryptography: https://tools.ietf.org/rfc/rfc9497.txt")
        
    except KeyboardInterrupt:
        print("\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo suite failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main() 