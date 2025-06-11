#!/usr/bin/env python3
"""
Example integration of Noise-KK into the existing OpenADP client

This shows how to modify the existing client.py to use Noise-KK encryption
over TLS for enhanced security.
"""

import json
import sys
import os

# Add the parent directory to the path to import openadp modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from client.noise_jsonrpc_client import create_noise_client
from openadp import crypto


class OpenADPClientWithNoise:
    """
    Enhanced OpenADP client with Noise-KK encryption support
    
    This class provides the same interface as the original OpenADP client
    but adds Noise-KK encryption for all communications.
    """
    
    def __init__(self, servers_json_path: str = "../api/servers.json"):
        """
        Initialize the client with server information
        
        Args:
            servers_json_path: Path to the servers.json file
        """
        self.servers = self._load_servers(servers_json_path)
        
    def _load_servers(self, servers_json_path: str) -> list:
        """Load server information from servers.json"""
        try:
            with open(servers_json_path, 'r') as f:
                data = json.load(f)
                return data.get('servers', [])
        except FileNotFoundError:
            print(f"Warning: {servers_json_path} not found. Using default server list.")
            return [
                {
                    "id": "xyzzybill",
                    "url": "https://xyzzybill.openadp.org",
                    "public_key": "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder1XyZzyBillServer12345TestKey"
                }
            ]
    
    def backup_secret(self, uid: str, password: str, data: bytes, 
                     threshold: int = 2, num_servers: int = 3) -> bool:
        """
        Backup a secret using threshold cryptography with Noise-KK encryption
        
        Args:
            uid: User identifier
            password: Password for key derivation
            data: Secret data to backup
            threshold: Number of servers needed for recovery
            num_servers: Total number of servers to use
            
        Returns:
            True if backup successful, False otherwise
        """
        print(f"🔐 Backing up secret for user {uid} with Noise-KK encryption")
        
        # Generate device and backup identifiers
        did = "device_" + os.urandom(8).hex()
        bid = "backup_" + os.urandom(8).hex()
        
        # Derive keys from password
        print("Deriving keys from password...")
        user_key = crypto.derive_key_from_password(password, uid.encode())
        
        # Generate secret shares using threshold cryptography
        print(f"Creating {threshold}-of-{num_servers} secret shares...")
        shares = crypto.create_threshold_shares(data, threshold, num_servers)
        
        # Select servers for backup
        selected_servers = self.servers[:num_servers]
        if len(selected_servers) < num_servers:
            print(f"Error: Only {len(selected_servers)} servers available, need {num_servers}")
            return False
        
        # Store shares on servers using Noise-KK
        success_count = 0
        for i, (server, (x, y)) in enumerate(zip(selected_servers, shares)):
            try:
                print(f"Storing share {i+1}/{num_servers} on {server['id']} with Noise-KK...")
                
                # Create Noise-KK client for this server
                with create_noise_client(server['url'], server['public_key']) as client:
                    # Encrypt the share with user key
                    encrypted_y = crypto.encrypt_with_key(user_key, y)
                    
                    # Store on server
                    result, error = client.register_secret(
                        uid=uid,
                        did=did, 
                        bid=bid,
                        version=1,
                        x=x,
                        y=encrypted_y,
                        max_guesses=5,
                        expiration=0  # No expiration
                    )
                    
                    if error:
                        print(f"  ❌ Failed to store on {server['id']}: {error}")
                    else:
                        print(f"  ✅ Successfully stored on {server['id']}")
                        success_count += 1
                        
            except Exception as e:
                print(f"  ❌ Connection error to {server['id']}: {e}")
        
        if success_count >= threshold:
            print(f"✅ Backup successful! {success_count}/{num_servers} shares stored")
            print(f"Recovery info: uid={uid}, did={did}, bid={bid}")
            return True
        else:
            print(f"❌ Backup failed! Only {success_count}/{threshold} required shares stored")
            return False
    
    def recover_secret(self, uid: str, did: str, bid: str, password: str,
                      threshold: int = 2) -> bytes:
        """
        Recover a secret using threshold cryptography with Noise-KK encryption
        
        Args:
            uid: User identifier
            did: Device identifier
            bid: Backup identifier  
            password: Password for key derivation
            threshold: Number of servers needed for recovery
            
        Returns:
            Recovered secret data, or None if recovery failed
        """
        print(f"🔑 Recovering secret for user {uid} with Noise-KK encryption")
        
        # Derive keys from password
        print("Deriving keys from password...")
        user_key = crypto.derive_key_from_password(password, uid.encode())
        
        # Generate point B for recovery protocol
        B = crypto.generate_recovery_point()
        
        # Recover shares from servers
        recovered_shares = []
        for server in self.servers:
            if len(recovered_shares) >= threshold:
                break
                
            try:
                print(f"Recovering share from {server['id']} with Noise-KK...")
                
                # Create Noise-KK client for this server
                with create_noise_client(server['url'], server['public_key']) as client:
                    result, error = client.recover_secret(
                        uid=uid,
                        did=did,
                        bid=bid,
                        b=B,
                        guess_num=1
                    )
                    
                    if error:
                        print(f"  ❌ Failed to recover from {server['id']}: {error}")
                        continue
                    
                    # Parse result
                    version, x, encrypted_siB, num_guesses, max_guesses, expiration = result
                    
                    # Decrypt the share
                    try:
                        siB = crypto.decrypt_with_key(user_key, encrypted_siB)
                        recovered_shares.append((x, siB))
                        print(f"  ✅ Successfully recovered from {server['id']}")
                    except Exception as e:
                        print(f"  ❌ Failed to decrypt share from {server['id']}: {e}")
                        
            except Exception as e:
                print(f"  ❌ Connection error to {server['id']}: {e}")
        
        if len(recovered_shares) < threshold:
            print(f"❌ Recovery failed! Only {len(recovered_shares)}/{threshold} shares recovered")
            return None
        
        # Reconstruct secret from shares
        print(f"Reconstructing secret from {len(recovered_shares)} shares...")
        try:
            secret = crypto.reconstruct_secret(recovered_shares, threshold)
            print("✅ Secret recovery successful!")
            return secret
        except Exception as e:
            print(f"❌ Failed to reconstruct secret: {e}")
            return None
    
    def list_backups(self, uid: str) -> list:
        """
        List all backups for a user with Noise-KK encryption
        
        Args:
            uid: User identifier
            
        Returns:
            List of backup information
        """
        print(f"📋 Listing backups for user {uid} with Noise-KK encryption")
        
        all_backups = []
        for server in self.servers:
            try:
                print(f"Querying {server['id']} with Noise-KK...")
                
                # Create Noise-KK client for this server
                with create_noise_client(server['url'], server['public_key']) as client:
                    result, error = client.list_backups(uid)
                    
                    if error:
                        print(f"  ❌ Failed to query {server['id']}: {error}")
                        continue
                    
                    if result:
                        all_backups.extend(result)
                        print(f"  ✅ Found {len(result)} backups on {server['id']}")
                    else:
                        print(f"  ℹ️  No backups found on {server['id']}")
                        
            except Exception as e:
                print(f"  ❌ Connection error to {server['id']}: {e}")
        
        return all_backups
    
    def test_connectivity(self) -> dict:
        """
        Test connectivity to all servers with Noise-KK encryption
        
        Returns:
            Dictionary of server connectivity status
        """
        print("🔗 Testing server connectivity with Noise-KK encryption")
        
        results = {}
        for server in self.servers:
            try:
                print(f"Testing {server['id']}...")
                
                # Create Noise-KK client for this server
                with create_noise_client(server['url'], server['public_key']) as client:
                    result, error = client.echo(f"Hello from OpenADP client!")
                    
                    if error:
                        results[server['id']] = {"status": "error", "error": error}
                        print(f"  ❌ {server['id']}: {error}")
                    else:
                        results[server['id']] = {"status": "ok", "response": result}
                        print(f"  ✅ {server['id']}: {result}")
                        
            except Exception as e:
                results[server['id']] = {"status": "connection_error", "error": str(e)}
                print(f"  ❌ {server['id']}: Connection error - {e}")
        
        return results


def main():
    """Example usage of the Noise-KK enhanced client"""
    print("🚀 OpenADP Client with Noise-KK Encryption")
    print("=" * 50)
    
    # Create client
    client = OpenADPClientWithNoise()
    
    # Test connectivity
    print("\n1. Testing server connectivity...")
    connectivity = client.test_connectivity()
    
    # Example backup (commented out since we don't have real servers)
    """
    print("\n2. Backing up a secret...")
    test_secret = b"My secret data that needs to be backed up securely!"
    success = client.backup_secret(
        uid="testuser123",
        password="mypassword", 
        data=test_secret,
        threshold=2,
        num_servers=3
    )
    
    if success:
        print("\n3. Attempting recovery...")
        recovered = client.recover_secret(
            uid="testuser123",
            did="device_12345678",
            bid="backup_87654321", 
            password="mypassword",
            threshold=2
        )
        
        if recovered and recovered == test_secret:
            print("✅ Recovery successful! Secret matches original.")
        else:
            print("❌ Recovery failed or data mismatch.")
    """
    
    print("\n" + "=" * 50)
    print("Example complete. The client is ready to use Noise-KK encryption!")


if __name__ == "__main__":
    main() 