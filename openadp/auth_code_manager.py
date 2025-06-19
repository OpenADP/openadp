"""
Authentication Code Manager for OpenADP Clients

This module provides client-side authentication code generation and management
for the OpenADP authentication code system.

Key features:
- Generate secure 128-bit authentication codes
- Derive server-specific codes using SHA256(auth_code || server_url)
- Manage authentication codes for multiple servers
- Provide secure storage recommendations
"""

import hashlib
import secrets
from typing import Dict, List


class AuthCodeManager:
    """
    Manages authentication codes for OpenADP clients.
    
    Provides methods to generate base authentication codes and derive
    server-specific codes for distributed authentication.
    """
    
    def __init__(self):
        """Initialize the authentication code manager."""
        self.secure_random = secrets.SystemRandom()
    
    def generate_auth_code(self) -> str:
        """
        Generate a new 128-bit authentication code.
        
        Returns:
            32-character hex string representing 128 bits of entropy
        """
        # Generate 16 random bytes (128 bits)
        random_bytes = self.secure_random.getrandbits(128)
        # Convert to 32-character hex string
        return f"{random_bytes:032x}"
    
    def derive_server_code(self, base_code: str, server_url: str) -> str:
        """
        Derive server-specific authentication code.
        
        Args:
            base_code: Base 128-bit authentication code (32 hex chars)
            server_url: Server URL for derivation
            
        Returns:
            Server-specific authentication code (64 hex chars)
        """
        combined = f"{base_code}:{server_url}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def get_server_codes(self, base_code: str, server_urls: List[str]) -> Dict[str, str]:
        """
        Get authentication codes for all servers.
        
        Args:
            base_code: Base 128-bit authentication code
            server_urls: List of server URLs
            
        Returns:
            Dictionary mapping server URLs to their specific auth codes
        """
        return {
            url: self.derive_server_code(base_code, url)
            for url in server_urls
        }
    
    def validate_base_code_format(self, base_code: str) -> bool:
        """
        Validate base authentication code format.
        
        Args:
            base_code: Base authentication code to validate
            
        Returns:
            True if format is valid, False otherwise
        """
        # Must be exactly 32 hex characters (128 bits)
        if len(base_code) != 32:
            return False
        
        try:
            int(base_code, 16)
            return True
        except ValueError:
            return False
    
    def validate_server_code_format(self, server_code: str) -> bool:
        """
        Validate server-specific authentication code format.
        
        Args:
            server_code: Server authentication code to validate
            
        Returns:
            True if format is valid, False otherwise
        """
        # Must be exactly 64 hex characters (SHA256 hash)
        if len(server_code) != 64:
            return False
        
        try:
            int(server_code, 16)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def get_storage_recommendations() -> Dict[str, str]:
        """
        Get recommendations for secure authentication code storage.
        
        Returns:
            Dictionary with storage recommendations for different use cases
        """
        return {
            "disk_encryption": "Store authentication code on the encrypted disk itself",
            "password_manager": "Store authentication code in your password manager vault",
            "phone_backup": "Store authentication code with your phone backup system",
            "multi_device": "Sync authentication code across devices using secure cloud storage",
            "paper_backup": "Write authentication code on paper and store in secure location",
            "hardware_token": "Store authentication code on hardware security key (if supported)",
            "warning": "Never store authentication codes in plaintext on unencrypted storage"
        }


def main():
    """
    Demo function for authentication code manager.
    
    Demonstrates authentication code generation and server-specific derivation.
    """
    print("Testing OpenADP Authentication Code Manager...")
    
    # Create manager
    manager = AuthCodeManager()
    
    # Generate base authentication code
    base_code = manager.generate_auth_code()
    print(f"Generated base authentication code: {base_code}")
    print(f"Base code length: {len(base_code)} characters")
    print(f"Base code valid: {manager.validate_base_code_format(base_code)}")
    
    # Test server URLs
    server_urls = [
        "https://server1.openadp.org",
        "https://server2.openadp.org", 
        "https://server3.openadp.org"
    ]
    
    # Derive server-specific codes
    print("\nDeriving server-specific codes:")
    server_codes = manager.get_server_codes(base_code, server_urls)
    
    for url, code in server_codes.items():
        print(f"  {url}: {code}")
        print(f"    Length: {len(code)} characters")
        print(f"    Valid: {manager.validate_server_code_format(code)}")
    
    # Show storage recommendations
    print("\nStorage recommendations:")
    recommendations = manager.get_storage_recommendations()
    for use_case, recommendation in recommendations.items():
        print(f"  {use_case}: {recommendation}")
    
    print("\n✅ Authentication code manager tests completed!")


if __name__ == '__main__':
    main() 