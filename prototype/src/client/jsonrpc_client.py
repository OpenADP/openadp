#!/usr/bin/env python3
"""
JSON-RPC Client for OpenADP Server

This client provides Python methods to interact with the OpenADP JSON-RPC server.
It exposes the following methods:
- register_secret: Register a secret with the server
- recover_secret: Recover a secret from the server
- list_backups: List backups for a user
- echo: Echo a message (for testing)
"""

import json
import requests
from typing import Any, Dict, List, Optional, Tuple, Union


class OpenADPClient:
    """Client for communicating with OpenADP JSON-RPC server."""
    
    def __init__(self, server_url: str = "http://localhost:8080"):
        """
        Initialize the OpenADP client.
        
        Args:
            server_url: URL of the JSON-RPC server (default: http://localhost:8080)
        """
        self.server_url = server_url
        self.request_id = 0
    
    def _make_request(self, method: str, params: List[Any]) -> Tuple[Any, Optional[str]]:
        """
        Make a JSON-RPC request to the server.
        
        Args:
            method: The RPC method name
            params: List of parameters for the method
            
        Returns:
            Tuple of (result, error_message). If successful, error_message is None.
        """
        self.request_id += 1
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.request_id
        }
        
        try:
            response = requests.post(
                self.server_url,
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                timeout=30
            )
            response.raise_for_status()
            
            result = response.json()
            
            if "error" in result:
                error_info = result["error"]
                if isinstance(error_info, dict):
                    error_msg = error_info.get("message", str(error_info))
                else:
                    error_msg = str(error_info)
                return None, error_msg
            
            return result.get("result"), None
            
        except requests.exceptions.RequestException as e:
            return None, f"Network error: {str(e)}"
        except json.JSONDecodeError as e:
            return None, f"JSON decode error: {str(e)}"
        except Exception as e:
            return None, f"Unexpected error: {str(e)}"
    
    def register_secret(self, uid: str, did: str, bid: str, version: int, 
                       x: str, y: str, max_guesses: int, expiration: int) -> Tuple[bool, Optional[str]]:
        """
        Register a secret with the server.
        
        Args:
            uid: User ID
            did: Device ID
            bid: Backup ID
            version: Version number
            x: X coordinate
            y: Y coordinate
            max_guesses: Maximum number of guesses allowed
            expiration: Expiration timestamp
            
        Returns:
            Tuple of (success, error_message). If successful, error_message is None.
        """
        params = [uid, did, bid, version, x, y, max_guesses, expiration]
        result, error = self._make_request("RegisterSecret", params)
        
        if error:
            return False, error
        
        return bool(result), None
    
    def recover_secret(self, uid: str, did: str, bid: str, b: str, guess_num: int) -> Tuple[Optional[str], Optional[str]]:
        """
        Recover a secret from the server.
        
        Args:
            uid: User ID
            did: Device ID
            bid: Backup ID
            b: B parameter for recovery
            guess_num: Guess number
            
        Returns:
            Tuple of (recovered_secret, error_message). If successful, error_message is None.
        """
        params = [uid, did, bid, b, guess_num]
        result, error = self._make_request("RecoverSecret", params)
        
        if error:
            return None, error
        
        return result, None
    
    def list_backups(self, uid: str) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """
        List backups for a user.
        
        Args:
            uid: User ID
            
        Returns:
            Tuple of (backup_list, error_message). If successful, error_message is None.
        """
        params = [uid]
        result, error = self._make_request("ListBackups", params)
        
        if error:
            return None, error
        
        return result, None
    
    def echo(self, message: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Echo a message (for testing connectivity).
        
        Args:
            message: Message to echo
            
        Returns:
            Tuple of (echoed_message, error_message). If successful, error_message is None.
        """
        params = [message]
        result, error = self._make_request("Echo", params)
        
        if error:
            return None, error
        
        return result, None


# Convenience functions for simple usage without creating a client instance
def create_client(server_url: str = "http://localhost:8080") -> OpenADPClient:
    """Create and return a new OpenADP client instance."""
    return OpenADPClient(server_url)


def register_secret(uid: str, did: str, bid: str, version: int, 
                   x: str, y: str, max_guesses: int, expiration: int,
                   server_url: str = "http://localhost:8080") -> Tuple[bool, Optional[str]]:
    """Convenience function to register a secret."""
    client = OpenADPClient(server_url)
    return client.register_secret(uid, did, bid, version, x, y, max_guesses, expiration)


def recover_secret(uid: str, did: str, bid: str, b: str, guess_num: int,
                  server_url: str = "http://localhost:8080") -> Tuple[Optional[str], Optional[str]]:
    """Convenience function to recover a secret."""
    client = OpenADPClient(server_url)
    return client.recover_secret(uid, did, bid, b, guess_num)


def list_backups(uid: str, server_url: str = "http://localhost:8080") -> Tuple[Optional[List[Dict]], Optional[str]]:
    """Convenience function to list backups."""
    client = OpenADPClient(server_url)
    return client.list_backups(uid)


def echo(message: str, server_url: str = "http://localhost:8080") -> Tuple[Optional[str], Optional[str]]:
    """Convenience function to echo a message."""
    client = OpenADPClient(server_url)
    return client.echo(message)


if __name__ == "__main__":
    # Simple test/demo
    client = OpenADPClient("https://xyzzybill.openadp.org")
    
    print("Testing echo...")
    result, error = client.echo("Hello, World!")
    if error:
        print(f"Error: {error}")
    else:
        print(f"Echo result: {result}")
