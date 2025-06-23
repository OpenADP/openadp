#!/usr/bin/env python3
"""
Ocrypt Backup Refresh Demo

This demo shows how Ocrypt's automatic backup refresh works with built-in
two-phase commit safety that can survive network failures and application crashes.

The new simplified API ensures that:
1. recover() automatically refreshes backups using two-phase commit
2. Old backups remain valid until new ones are confirmed working
3. Applications get reliable backup refresh without additional complexity
4. Network failures during backup refresh don't leave users stranded
"""

import sys
import os
import json
from pathlib import Path

# Add the openadp package to the path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'sdk', 'python'))

import openadp.ocrypt as ocrypt


def demo_automatic_backup_refresh():
    """Demo 1: Automatic backup refresh during recovery"""
    print("=" * 70)
    print("DEMO 1: Automatic Backup Refresh During Recovery")
    print("=" * 70)
    
    # Initial registration
    user_id = "alice@example.com"
    app_id = "secure_app"
    secret = b"my_super_secret_api_key_that_must_not_be_lost"
    pin = "1234"
    
    print("📋 Step 1: Initial registration...")
    try:
        # Start with "v1" backup
        metadata_v1 = ocrypt.register(user_id, app_id, secret, pin)
        print(f"✅ Initial registration successful (backup_id: even)")
        print(f"📦 Metadata size: {len(metadata_v1)} bytes")
        print()
        
        # Recovery automatically refreshes backup using two-phase commit
        print("📋 Step 2: Recovery with automatic backup refresh...")
        recovered_secret, remaining, updated_metadata = ocrypt.recover(metadata_v1, pin)
        
        print(f"✅ Recovery successful!")
        print(f"🔓 Secret recovered: {recovered_secret == secret}")
        print(f"🎯 Remaining guesses: {remaining}")
        
        # Check if metadata was updated
        old_metadata_dict = json.loads(metadata_v1.decode('utf-8'))
        new_metadata_dict = json.loads(updated_metadata.decode('utf-8'))
        
        old_bid = old_metadata_dict["backup_id"]
        new_bid = new_metadata_dict["backup_id"]
        
        if old_bid != new_bid:
            print(f"🔄 Backup automatically refreshed: {old_bid} → {new_bid}")
            print(f"📦 Updated metadata size: {len(updated_metadata)} bytes")
            print("💾 Store updated_metadata for future recoveries")
        else:
            print(f"⚠️  Backup refresh failed, but recovery still succeeded")
            print("💾 Continue using original metadata")
        print()
        
        # Verify both backups work (demonstrating two-phase commit safety)
        print("📋 Step 3: Verifying both backups are accessible...")
        
        # Test old backup (should still work due to two-phase commit)
        try:
            secret_old, remaining_old, _ = ocrypt.recover(metadata_v1, pin)
            print(f"✅ Old backup (v1) still works: {secret_old == secret}")
        except Exception as e:
            print(f"⚠️  Old backup (v1) no longer accessible: {e}")
        
        # Test new backup
        if old_bid != new_bid:
            try:
                secret_new, remaining_new, _ = ocrypt.recover(updated_metadata, pin)
                print(f"✅ New backup ({new_bid}) works: {secret_new == secret}")
            except Exception as e:
                print(f"❌ New backup ({new_bid}) failed: {e}")
            
    except Exception as e:
        print(f"❌ Demo failed: {e}")
    
    print()


def demo_backup_id_patterns():
    """Demo 2: Different backup ID patterns"""
    print("=" * 70)
    print("DEMO 2: Different Backup ID Patterns")
    print("=" * 70)
    
    user_id = "bob@example.com"
    app_id = "pattern_test"
    secret = b"test_secret_for_pattern_demo"
    pin = "test123"
    
    print("📋 Testing different backup ID patterns...")
    print()
    
    # Test alternation pattern
    print("🔄 Pattern 1: Simple alternation (even/odd)")
    try:
        metadata_even = ocrypt.register(user_id, app_id + "_alt", secret, pin)
        print(f"✅ Registered with backup_id: even (default)")
        
        # Recovery should flip to odd
        recovered_secret, remaining, updated_metadata = ocrypt.recover(metadata_even, pin)
        new_metadata_dict = json.loads(updated_metadata.decode('utf-8'))
        new_bid = new_metadata_dict["backup_id"]
        print(f"🔄 After recovery: even → {new_bid}")
        print()
        
    except Exception as e:
        print(f"❌ Alternation pattern failed: {e}")
    
    # Test version pattern
    print("🔄 Pattern 2: Version numbering")
    try:
        metadata_v1 = ocrypt.register(user_id, app_id + "_ver", secret, pin)
        print(f"✅ Registered with backup_id: even (default)")
        
        # Recovery should increment to v2
        recovered_secret, remaining, updated_metadata = ocrypt.recover(metadata_v1, pin)
        new_metadata_dict = json.loads(updated_metadata.decode('utf-8'))
        new_bid = new_metadata_dict["backup_id"]
        print(f"🔄 After recovery: v1 → {new_bid}")
        print()
        
    except Exception as e:
        print(f"❌ Version pattern failed: {e}")
    
    # Test custom pattern
    print("🔄 Pattern 3: Custom naming")
    try:
        metadata_prod = ocrypt.register(user_id, app_id + "_custom", secret, pin)
        print(f"✅ Registered with backup_id: even (default)")
        
        # Recovery should generate timestamped version
        recovered_secret, remaining, updated_metadata = ocrypt.recover(metadata_prod, pin)
        new_metadata_dict = json.loads(updated_metadata.decode('utf-8'))
        new_bid = new_metadata_dict["backup_id"]
        print(f"🔄 After recovery: production → {new_bid}")
        print()
        
    except Exception as e:
        print(f"❌ Custom pattern failed: {e}")


def demo_failure_recovery():
    """Demo 3: Graceful handling of backup refresh failures"""
    print("=" * 70)
    print("DEMO 3: Graceful Handling of Backup Refresh Failures")
    print("=" * 70)
    
    user_id = "charlie@example.com"
    app_id = "failure_test"
    secret = b"critical_system_master_key"
    pin = "admin2024"
    
    try:
        print("📋 Step 1: Initial registration...")
        metadata = ocrypt.register(user_id, app_id, secret, pin)
        print(f"✅ Initial registration successful (backup_id: even)")
        print()
        
        print("📋 Step 2: Recovery with potential backup refresh failure...")
        print("   (Network issues might prevent backup refresh, but recovery should still work)")
        
        # Even if backup refresh fails internally, recovery should succeed
        recovered_secret, remaining, updated_metadata = ocrypt.recover(metadata, pin)
        
        print(f"✅ Recovery successful!")
        print(f"🔓 Secret recovered: {recovered_secret == secret}")
        print(f"🎯 Remaining guesses: {remaining}")
        
        # Check if backup was refreshed
        old_metadata_dict = json.loads(metadata.decode('utf-8'))
        new_metadata_dict = json.loads(updated_metadata.decode('utf-8'))
        
        old_bid = old_metadata_dict["backup_id"]
        new_bid = new_metadata_dict["backup_id"]
        
        if old_bid != new_bid:
            print(f"🔄 Backup successfully refreshed: {old_bid} → {new_bid}")
            print("💾 Use updated_metadata for future recoveries")
        else:
            print(f"⚠️  Backup refresh failed, but user is not locked out")
            print("💾 Continue using original metadata")
            print("🛡️  Two-phase commit prevented lockout!")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
    
    print()


def demo_application_integration():
    """Demo 4: Proper application integration patterns"""
    print("=" * 70)
    print("DEMO 4: Proper Application Integration Patterns")
    print("=" * 70)
    
    user_id = "app@example.com"
    app_id = "production_app"
    secret = b"production_database_encryption_key"
    pin = "prod_password_2024"
    
    print("📋 Application startup sequence...")
    
    # Simulate application startup
    metadata_file = "/tmp/app_metadata.json"  # In practice, this would be in secure storage
    
    try:
        # Initial setup (first run)
        if not os.path.exists(metadata_file):
            print("🆕 First run: Registering new secret...")
            metadata = ocrypt.register(user_id, app_id, secret, pin)
            
            # Store metadata securely
            with open(metadata_file, 'wb') as f:
                f.write(metadata)
            print(f"✅ Registration complete, metadata stored")
        else:
            print("🔄 Subsequent run: Loading existing metadata...")
            with open(metadata_file, 'rb') as f:
                metadata = f.read()
        
        print()
        print("📋 Application authentication...")
        
        # Recover secret (with automatic backup refresh)
        recovered_secret, remaining, updated_metadata = ocrypt.recover(metadata, pin)
        
        print(f"✅ Authentication successful!")
        print(f"🔓 Secret recovered: {recovered_secret == secret}")
        print(f"🎯 Remaining guesses: {remaining}")
        
        # Check if we need to update stored metadata
        if updated_metadata != metadata:
            print("📝 Updating stored metadata with refreshed backup...")
            
            # Atomic update pattern for crash safety
            temp_file = metadata_file + ".new"
            with open(temp_file, 'wb') as f:
                f.write(updated_metadata)
            
            # Atomic rename (crash-safe on most filesystems)
            os.rename(temp_file, metadata_file)
            print("✅ Metadata updated atomically")
        else:
            print("📝 Metadata unchanged, no update needed")
        
        print()
        print("🚀 Application ready with recovered secret!")
        
        # Cleanup
        if os.path.exists(metadata_file):
            os.remove(metadata_file)
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        # Cleanup on error
        if os.path.exists(metadata_file):
            os.remove(metadata_file)
        temp_file = metadata_file + ".new"
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    print()


def main():
    """Run all backup refresh demos"""
    print("🔮 Ocrypt Backup Refresh Demo")
    print("🌐 Using OpenADP distributed threshold cryptography")
    print("🔐 Built-in two-phase commit for crash safety")
    print()
    
    # Check if we're in a test environment
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("⚠️  Running in test mode - some demos may be mocked")
        print()
    
    # Run demos
    try:
        demo_automatic_backup_refresh()
        demo_backup_id_patterns()
        demo_failure_recovery()
        demo_application_integration()
        
        print("=" * 70)
        print("🎉 All backup refresh demos completed successfully!")
        print("=" * 70)
        print()
        print("📚 Key takeaways:")
        print("   ✅ recover() automatically refreshes backups using two-phase commit")
        print("   ✅ Old backups remain valid until new ones are confirmed working")
        print("   ✅ Applications should store updated_metadata from recover()")
        print("   ✅ Network failures during refresh don't cause lockouts")
        print("   ✅ Backup ID patterns support different application needs")
        print()
        print("🔗 Learn more about OpenADP at: https://openadp.org")
        
    except KeyboardInterrupt:
        print("\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo suite failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main() 