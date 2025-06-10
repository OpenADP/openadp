#!/usr/bin/env python3
"""
OpenADP Client Business Logic

This module provides high-level business logic for interacting with OpenADP servers.
It manages multiple servers, handles failover, and provides convenient methods for
common operations.
"""

import time
from typing import List, Optional, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import scrape
from jsonrpc_client import OpenADPClient


class Client:
    """
    High-level client for OpenADP operations.
    
    This client manages multiple OpenADP servers, tests them for liveness,
    and provides business logic methods for common operations like registering
    and recovering secrets.
    """
    
    def __init__(self, servers_url: str = "https://servers.openadp.org", 
                 fallback_servers: Optional[List[str]] = None,
                 echo_timeout: float = 10.0,
                 max_workers: int = 10):
        """
        Initialize the OpenADP client.
        
        Args:
            servers_url: URL to scrape for server list (default: https://servers.openadp.org)
            fallback_servers: List of fallback servers to use if scraping fails
            echo_timeout: Timeout in seconds for echo tests (default: 10.0)
            max_workers: Maximum number of threads for concurrent server testing (default: 10)
        """
        self.servers_url = servers_url
        self.echo_timeout = echo_timeout
        self.max_workers = max_workers
        
        # Set default fallback servers if none provided
        if fallback_servers is None:
            fallback_servers = [
                "https://xyzzybill.openadp.org",
                "https://sky.openadp.org"
            ]
        self.fallback_servers = fallback_servers
        
        # Initialize live servers list
        self.live_servers: List[OpenADPClient] = []
        
        # Scrape and test servers
        self._initialize_servers()
    
    def _initialize_servers(self):
        """
        Scrape server list and test each server for liveness.
        Only servers that respond to echo are kept as live servers.
        """
        print("Scraping server list...")
        
        # Scrape server URLs
        server_urls = scrape.scrape_server_urls(self.servers_url)
        
        # Use fallback servers if scraping failed
        if not server_urls:
            print(f"Failed to scrape servers from {self.servers_url}, using fallback servers")
            server_urls = self.fallback_servers
        else:
            print(f"Found {len(server_urls)} servers to test")
        
        # Test servers concurrently for better performance
        self.live_servers = self._test_servers_concurrently(server_urls)
        
        print(f"Initialization complete: {len(self.live_servers)} live servers available")
        if self.live_servers:
            print("Live servers:")
            for i, client in enumerate(self.live_servers, 1):
                print(f"  {i}. {client.server_url}")
        else:
            print("WARNING: No live servers found! All operations will fail.")
    
    def _test_servers_concurrently(self, server_urls: List[str]) -> List[OpenADPClient]:
        """
        Test multiple servers concurrently for liveness using echo.
        
        Args:
            server_urls: List of server URLs to test
            
        Returns:
            List of OpenADPClient instances for live servers
        """
        live_servers = []
        
        def test_server(url: str) -> Optional[OpenADPClient]:
            """Test a single server and return client if live."""
            try:
                print(f"Testing server: {url}")
                client = OpenADPClient(url)
                
                # Test with echo - use a simple test message
                test_message = f"liveness_test_{int(time.time())}"
                result, error = client.echo(test_message)
                
                if error:
                    print(f"  ❌ {url}: {error}")
                    return None
                elif result == test_message:
                    print(f"  ✅ {url}: Live")
                    return client
                else:
                    print(f"  ❌ {url}: Echo returned unexpected result: {result}")
                    return None
                    
            except Exception as e:
                print(f"  ❌ {url}: Exception during test: {str(e)}")
                return None
        
        # Use ThreadPoolExecutor for concurrent testing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all server tests
            future_to_url = {executor.submit(test_server, url): url for url in server_urls}
            
            # Collect results as they complete
            for future in as_completed(future_to_url):
                client = future.result()
                if client:
                    live_servers.append(client)
        
        return live_servers
    
    def _test_single_server(self, url: str) -> Optional[OpenADPClient]:
        """
        Test a single server for liveness.
        
        Args:
            url: Server URL to test
            
        Returns:
            OpenADPClient instance if server is live, None otherwise
        """
        try:
            client = OpenADPClient(url)
            
            # Test with echo
            test_message = f"liveness_test_{int(time.time())}"
            result, error = client.echo(test_message)
            
            if error:
                return None
            elif result == test_message:
                return client
            else:
                return None
                
        except Exception:
            return None
    
    def get_live_server_count(self) -> int:
        """
        Get the number of currently live servers.
        
        Returns:
            Number of live servers
        """
        return len(self.live_servers)
    
    def get_live_server_urls(self) -> List[str]:
        """
        Get URLs of all currently live servers.
        
        Returns:
            List of live server URLs
        """
        return [client.server_url for client in self.live_servers]
    
    def refresh_servers(self):
        """
        Re-scrape and re-test all servers to refresh the live server list.
        This can be called if servers become unresponsive.
        """
        print("Refreshing server list...")
        self._initialize_servers()
    
    def add_server(self, url: str) -> bool:
        """
        Add a new server to the live server list if it passes the echo test.
        
        Args:
            url: Server URL to add
            
        Returns:
            True if server was added successfully, False otherwise
        """
        # Check if server is already in the list
        for client in self.live_servers:
            if client.server_url == url:
                print(f"Server {url} is already in the live server list")
                return True
        
        # Test the server
        print(f"Testing new server: {url}")
        client = self._test_single_server(url)
        
        if client:
            self.live_servers.append(client)
            print(f"✅ Added server: {url}")
            return True
        else:
            print(f"❌ Failed to add server: {url}")
            return False
    
    def list_backups(self, uid: str) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """
        List backups for a user by querying live servers.
        
        Tries each live server in order until one succeeds. Since servers should
        be replicas with the same data, we only need one successful response.
        
        Args:
            uid: User ID to list backups for
            
        Returns:
            Tuple of (backup_list, error_message). If successful, error_message is None.
        """
        if not self.live_servers:
            return None, "No live servers available"
        
        errors = []
        
        for i, client in enumerate(self.live_servers):
            try:
                result, error = client.list_backups(uid)
                
                if error:
                    errors.append(f"{client.server_url}: {error}")
                    continue
                
                # Success! Return the result
                if i > 0:  # If we had to try multiple servers
                    print(f"Successfully retrieved backups from {client.server_url} (after {i} failed attempts)")
                
                return result, None
                
            except Exception as e:
                errors.append(f"{client.server_url}: Exception: {str(e)}")
                continue
        
        # All servers failed
        error_msg = f"All {len(self.live_servers)} servers failed. Errors: " + "; ".join(errors)
        return None, error_msg


if __name__ == "__main__":
    # Demo/test the client initialization
    print("Initializing OpenADP Client...")
    client = Client()
    
    print(f"\nClient initialized with {client.get_live_server_count()} live servers:")
    for i, url in enumerate(client.get_live_server_urls(), 1):
        print(f"  {i}. {url}")
    
    # Test listBackups functionality
    if client.get_live_server_count() > 0:
        print(f"\nTesting listBackups...")
        test_uid = "test_user_123"
        backups, error = client.list_backups(test_uid)
        
        if error:
            print(f"❌ listBackups failed: {error}")
        else:
            print(f"✅ listBackups succeeded")
            if backups:
                print(f"Found {len(backups)} backups for user '{test_uid}':")
                for i, backup in enumerate(backups, 1):
                    print(f"  {i}. {backup}")
            else:
                print(f"No backups found for user '{test_uid}'")
    else:
        print(f"\n⚠️  Skipping listBackups test - no live servers available") 