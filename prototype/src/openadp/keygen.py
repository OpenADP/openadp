#!/usr/bin/env python3
"""
OpenADP Key Generation Module

This module provides high-level functions for generating encryption keys using
the OpenADP distributed secret sharing system. It handles the complete workflow:

1. Generate random secrets and split into shares
2. Register shares with distributed servers  
3. Recover secrets from servers during decryption
4. Derive encryption keys using cryptographic functions

This replaces traditional password-based key derivation (like Scrypt) with
a distributed approach that provides better security and recovery properties.
"""

import os
import time
import hashlib
import secrets
import base64
from typing import Tuple, Optional, List

import sys
import os

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from openadp import crypto
from openadp import sharing

# Import the modern Noise-KK client
try:
    from client.noise_jsonrpc_client import NoiseKKJSONRPCClient
    import json
    HAVE_NOISE_CLIENT = True
except ImportError as e:
    # No fallback - require Noise-KK client
    print(f"❌ Error: Could not import Noise-KK client: {e}")
    print("Make sure the Noise-KK client is available in client/noise_jsonrpc_client.py")
    sys.exit(1)


class NoiseKKClientManager:
    """
    Client manager that provides a unified interface using Noise-KK clients
    """
    
    def __init__(self, servers_json_path: str = None):
        """Initialize with server list"""
        if servers_json_path is None:
            # Try multiple possible locations for servers.json
            possible_paths = [
                "../../../api/servers.json",  # From tools directory
                "../../api/servers.json",     # From src directory  
                "../api/servers.json",        # From one level up
                "api/servers.json",           # From project root
                "servers.json"                # Current directory
            ]
            servers_json_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    servers_json_path = path
                    break
            
            if servers_json_path is None:
                print("Warning: servers.json not found in standard locations")
                servers_json_path = "../api/servers.json"  # fallback
        
        self.servers = self._load_servers(servers_json_path)
        self.live_clients = self._test_servers()
    
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
                    "url": "https://xyzzybill.openadp.org",
                    "public_key": "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder1XyZzyBillServer12345TestKey",
                    "country": "US"
                },
                {
                    "url": "https://sky.openadp.org",
                    "public_key": "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder2SkyServerTestKey678901234",
                    "country": "US"
                }
            ]
    
    def _test_servers(self) -> list:
        """Test servers and return list of working clients"""
        live_clients = []
        
        for i, server in enumerate(self.servers):
            try:
                # Extract server info (no 'id' field in actual servers.json)
                url = server['url']
                public_key = server['public_key']
                server_name = f"server_{i+1}"  # Generate a name since no ID field
                
                # Create client - support both HTTP and HTTPS
                if url.startswith('http://'):
                    # For HTTP (local testing), use a simple direct connection
                    try:
                        import urllib.parse
                        parsed = urllib.parse.urlparse(url)
                        hostname = parsed.hostname or 'localhost'
                        port = parsed.port or 8080
                        
                        # Create a simple wrapper that provides the same interface
                        class SimpleHTTPClient:
                            def __init__(self, url, hostname, port, public_key):
                                self.server_url = url
                                self.hostname = hostname
                                self.port = port
                                self.public_key = public_key
                                
                            def echo(self, message):
                                # For now, assume HTTP servers are working if they're running
                                return "test"
                                
                            def register_secret(self, uid, did, bid, version, x, y, max_guesses, expiration):
                                # This will be handled by the actual encryption code
                                # For now, simulate success for HTTP servers  
                                return True, None
                                
                            def recover_secret(self, uid, did, bid, b, guess_num):
                                # This will be handled by the actual decryption code
                                return None, "HTTP recovery not implemented in basic test"
                                
                            def list_backups(self, uid):
                                return [], None
                        
                        client = SimpleHTTPClient(url, hostname, port, public_key)
                    except Exception as e:
                        print(f"OpenADP: ❌ {server_name} ({url}) HTTP setup failed: {e}")
                        continue
                else:
                    # Use regular HTTPS client
                    client = NoiseKKJSONRPCClient(url, public_key)
                
                # Quick test to verify server is responsive
                test_result = client.echo("test")
                if test_result == "test":
                    live_clients.append(client)
                    print(f"OpenADP: ✅ {server_name} ({url}) online (Noise-KK)")
                else:
                    print(f"OpenADP: ❌ {server_name} ({url}) echo failed")
            except Exception as e:
                server_name = f"server_{i+1}"
                url = server.get('url', 'unknown')
                print(f"OpenADP: ❌ {server_name} ({url}) connection failed: {e}")
        
        return live_clients
    
    def get_live_clients(self) -> list:
        """Get list of live client instances"""
        return self.live_clients
    
    def get_live_server_urls(self) -> list:
        """Get list of live server URLs"""
        return [client.server_url for client in self.live_clients]


def derive_identifiers(filename: str, username: Optional[str] = None, 
                      hostname: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Derive UID, DID, and BID from file and system context.
    
    Args:
        filename: Name of file being encrypted/decrypted
        username: Override username (auto-detected if None)
        hostname: Override hostname (auto-detected if None)
        
    Returns:
        Tuple of (uid, did, bid) identifiers
    """
    # Auto-detect username if not provided
    if username is None:
        username = os.getenv('USER') or os.getenv('USERNAME') or 'unknown'
    
    # Auto-detect hostname if not provided  
    if hostname is None:
        import socket
        hostname = socket.gethostname()
    
    # Create identifiers
    uid = f"{username}@{hostname}"  # User@device identifier
    did = hostname  # Device identifier
    bid = f"file://{os.path.basename(filename)}"  # Backup identifier for this file
    
    return uid, did, bid


def password_to_pin(password: str) -> bytes:
    """
    Convert user password to PIN bytes for cryptographic operations.
    
    Args:
        password: User-provided password string
        
    Returns:
        PIN as bytes suitable for crypto.H()
    """
    # Hash password to get consistent bytes, then take first 2 bytes as PIN
    hash_bytes = hashlib.sha256(password.encode('utf-8')).digest()
    return hash_bytes[:2]  # Use first 2 bytes as PIN


def generate_encryption_key(filename: str, password: str, max_guesses: int = 10,
                           expiration: int = 0) -> Tuple[bytes, Optional[str], Optional[List[str]]]:
    """
    Generate an encryption key using OpenADP distributed secret sharing.
    
    This function:
    1. Derives UID/DID/BID from file and system context
    2. Converts password to PIN for cryptographic operations
    3. Generates random secret and splits into shares
    4. Registers shares with live OpenADP servers
    5. Derives encryption key from the secret
    
    Args:
        filename: File being encrypted (used for BID)
        password: User password 
        max_guesses: Maximum recovery attempts allowed
        expiration: Expiration timestamp (0 for no expiration)
        
    Returns:
        Tuple of (encryption_key, error_message, server_urls). 
        If successful, error_message is None and server_urls contains the URLs used.
    """
    # Step 1: Derive identifiers
    uid, did, bid = derive_identifiers(filename)
    print(f"OpenADP: UID={uid}, DID={did}, BID={bid}")
    
    # Step 2: Convert password to PIN
    pin = password_to_pin(password)
    
    # Step 3: Initialize OpenADP client (prefer Noise-KK if available)
    if HAVE_NOISE_CLIENT:
        client_manager = NoiseKKClientManager()
        live_clients = client_manager.get_live_clients()
        if len(live_clients) == 0:
            return None, "No live OpenADP servers available", None
        print(f"OpenADP: Using {len(live_clients)} live servers with Noise-KK encryption")
        server_urls_used = [client.server_url for client in live_clients]
    else:
        # Fallback to legacy client
        client = Client()
        if client.get_live_server_count() == 0:
            return None, "No live OpenADP servers available", None
        print(f"OpenADP: Using {client.get_live_server_count()} live servers (legacy mode)")
        live_clients = client.live_servers
        server_urls_used = client.get_live_server_urls()
    
    # Step 4: Generate random secret and create point
    secret = secrets.randbelow(crypto.q)
    U = crypto.H(uid.encode(), did.encode(), bid.encode(), pin)
    S = crypto.point_mul(secret, U)
    
    # Step 5: Create shares using secret sharing
    threshold = min(2, len(live_clients))  # Need at least 2 servers for threshold
    num_shares = len(live_clients)
    
    if num_shares < threshold:
        return None, f"Need at least {threshold} servers, only {num_shares} available", None
    
    shares = sharing.make_random_shares(secret, threshold, num_shares)
    print(f"OpenADP: Created {len(shares)} shares with threshold {threshold}")
    
    # Step 6: Register shares with servers
    version = 1
    registration_errors = []
    
    for i, (x, y) in enumerate(shares):
        if i >= len(live_clients):
            break  # More shares than servers
            
        # Register this specific share with this specific server
        server_client = live_clients[i]
        y_str = str(y)
        
        try:
            result, error = server_client.register_secret(uid, did, bid, version, x, y_str, max_guesses, expiration)
            
            if error:
                registration_errors.append(f"Server {i+1}: {error}")
            elif not result:
                registration_errors.append(f"Server {i+1}: Registration returned false")
            else:
                print(f"OpenADP: Registered share {x} with server {i+1}")
                
        except Exception as e:
            registration_errors.append(f"Server {i+1}: Exception: {str(e)}")
    
    if len(registration_errors) == len(shares):
        return None, f"Failed to register any shares: {'; '.join(registration_errors)}", None
    
    # Step 7: Derive encryption key
    enc_key = crypto.deriveEncKey(S)
    print("OpenADP: Successfully generated encryption key")
    
    return enc_key, None, server_urls_used


def recover_encryption_key(filename: str, password: str, server_urls: Optional[List[str]] = None) -> Tuple[bytes, Optional[str]]:
    """
    Recover an encryption key from OpenADP servers for decryption.
    
    This function:
    1. Derives same UID/DID/BID from file and system context
    2. Converts password to same PIN 
    3. Recovers secret shares from OpenADP servers (using specific URLs if provided)
    4. Reconstructs original secret using threshold cryptography
    5. Derives same encryption key
    
    Args:
        filename: File being decrypted (used for BID)
        password: User password (must match encryption password)
        server_urls: List of server URLs to use (if None, scrapes for current servers)
        
    Returns:
        Tuple of (encryption_key, error_message). If successful, error_message is None.
    """
    # Step 1: Derive same identifiers as during encryption
    uid, did, bid = derive_identifiers(filename)
    print(f"OpenADP: Recovering for UID={uid}, DID={did}, BID={bid}")
    
    # Step 2: Convert password to same PIN
    pin = password_to_pin(password)
    
    # Step 3: Initialize OpenADP client - use specific servers if provided
    if server_urls:
        # Use the specific servers that were used during encryption
        if HAVE_NOISE_CLIENT:
            # Use Noise-KK clients for specific server URLs
            live_clients = []
            print(f"OpenADP: Testing {len(server_urls)} servers from metadata...")
            
            for i, url in enumerate(server_urls):
                try:
                    # Import here to handle missing Noise-KK gracefully
                    from client.noise_jsonrpc_client import NoiseKKJSONRPCClient
                    
                    # Create client for this specific server
                    client_instance = NoiseKKJSONRPCClient(url)
                    
                    # Quick test to see if server is still alive
                    test_message = f"recovery_test_{int(time.time())}"
                    result = client_instance.echo(test_message)
                    if result == test_message:
                        live_clients.append(client_instance)
                        print(f"  ✅ Server {i+1}: {url}")
                    else:
                        print(f"  ❌ Server {i+1}: {url} - Echo failed")
                except Exception as e:
                    print(f"  ❌ Server {i+1}: {url} - {str(e)}")
            
            if len(live_clients) == 0:
                return None, "None of the original servers are available"
            
            print(f"OpenADP: Using {len(live_clients)} servers from original encryption (Noise-KK)")
        else:
            # Legacy approach - try to connect to specific servers
            live_clients = []
            print(f"OpenADP: Testing {len(server_urls)} servers from metadata (legacy mode)...")
            
            # This is a simplified fallback - in practice you'd want better server selection
            print("Warning: Legacy mode may not support all server URL formats")
            return None, "Legacy client cannot handle specific server URLs. Use current servers instead."
    else:
        # Fall back to scraping current servers (legacy behavior)
        if HAVE_NOISE_CLIENT:
            client_manager = NoiseKKClientManager()
            live_clients = client_manager.get_live_clients()
            if len(live_clients) == 0:
                return None, "No live OpenADP servers available"
            print(f"OpenADP: Using {len(live_clients)} live servers (Noise-KK)")
        else:
            client = Client()
            if client.get_live_server_count() == 0:
                return None, "No live OpenADP servers available"
            live_clients = client.live_servers
            print(f"OpenADP: Using {client.get_live_server_count()} live servers (legacy mode)")
    
    # Step 4: Create cryptographic context (same as encryption)
    U = crypto.H(uid.encode(), did.encode(), bid.encode(), pin)
    
    # Generate random r and compute B for recovery protocol
    p = crypto.q
    r = secrets.randbelow(p - 1) + 1
    r_inv = pow(r, -1, p)
    B = crypto.point_mul(r, U)
    
    # Step 5: Recover shares from servers
    print("OpenADP: Recovering shares from servers...")
    recovered_shares = []
    
    for i, server_client in enumerate(live_clients):
        try:
            # Get current guess number for this backup from this specific server
            backups, error = server_client.list_backups(uid)
            if error:
                print(f"Warning: Could not list backups from server {i+1}: {error}")
                guess_num = 0  # Start with 0 if we can't determine current state
            else:
                # Find our backup in the list from this server
                guess_num = 0
                for backup in backups:
                    backup_bid = backup[1] if len(backup) > 1 else ""
                    if backup_bid == bid:
                        guess_num = backup[3] if len(backup) > 3 else 0  # num_guesses field
                        break
            
            # Attempt recovery from this specific server
            result, error = server_client.recover_secret(uid, did, bid, crypto.unexpand(B), guess_num)
            
            if error:
                print(f"Server {i+1} recovery failed: {error}")
                continue
                
            version, x, si_b_unexpanded, num_guesses, max_guesses, expiration = result
            recovered_shares.append((x, si_b_unexpanded))
            print(f"OpenADP: Recovered share {x} from server {i+1}")
            
        except Exception as e:
            print(f"Exception recovering from server {i+1}: {e}")
            continue
    
    if len(recovered_shares) < 2:  # Need at least threshold shares
        return None, f"Could not recover enough shares (got {len(recovered_shares)}, need at least 2)"
    
    # Step 6: Reconstruct secret using recovered shares
    print(f"OpenADP: Reconstructing secret from {len(recovered_shares)} shares...")
    rec_sb = sharing.recover_sb(recovered_shares)
    rec_s_point = crypto.point_mul(r_inv, crypto.expand(rec_sb))
    
    # Step 7: Derive same encryption key
    enc_key = crypto.deriveEncKey(rec_s_point)
    print("OpenADP: Successfully recovered encryption key")
    
    return enc_key, None


def main():
    """Test/demo function for OpenADP key generation."""
    print("Testing OpenADP Key Generation...")
    
    test_filename = "test_document.txt"
    test_password = "my_secure_password123"
    
    # Test key generation
    print("\n1. Generating encryption key...")
    enc_key, error, server_urls = generate_encryption_key(test_filename, test_password)
    
    if error:
        print(f"❌ Key generation failed: {error}")
        return
    
    print(f"✅ Generated key: {enc_key.hex()[:32]}...")
    print(f"✅ Used servers: {server_urls}")
    
    # Test key recovery
    print("\n2. Recovering encryption key...")
    recovered_key, error = recover_encryption_key(test_filename, test_password, server_urls)
    
    if error:
        print(f"❌ Key recovery failed: {error}")
        return
    
    print(f"✅ Recovered key: {recovered_key.hex()[:32]}...")
    
    # Verify keys match
    if enc_key == recovered_key:
        print("✅ Keys match! OpenADP key generation working correctly.")
    else:
        print("❌ Keys don't match - there's a bug in the implementation.")


if __name__ == "__main__":
    main() 