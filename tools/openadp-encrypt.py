#!/usr/bin/env python3
"""
OpenADP File Encryption Tool - Python Version

This tool exactly matches the functionality of cmd/openadp-encrypt/main.go
"""

import argparse
import os
import sys
import json
import getpass
import struct
import socket
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Add the openadp package to the path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'sdk', 'python'))

from openadp.keygen import generate_encryption_key, Identity
from openadp.client import get_servers, get_fallback_server_info, ServerInfo, OpenADPClient

VERSION = "1.0.0"
NONCE_SIZE = 12  # AES-GCM nonce size


class Metadata:
    """Metadata stored with encrypted files"""
    def __init__(self, servers, threshold, version, auth_code, user_id):
        self.servers = servers
        self.threshold = threshold
        self.version = version
        self.auth_code = auth_code
        self.user_id = user_id
    
    def to_dict(self):
        return {
            "servers": self.servers,
            "threshold": self.threshold,
            "version": self.version,
            "auth_code": self.auth_code,
            "user_id": self.user_id
        }


def show_help():
    print("""OpenADP File Encryption Tool

USAGE:
    openadp-encrypt.py --file <filename> [OPTIONS]

OPTIONS:
    --file <path>          File to encrypt (required)
    --password <password>  Password for key derivation (will prompt if not provided)
    --user-id <id>         User ID for secret ownership (will prompt if not provided)
    --servers <urls>       Comma-separated list of server URLs (optional)
    --servers-url <url>    URL to scrape for server list (default: https://servers.openadp.org)
    --version              Show version information
    --help                 Show this help message

USER ID SECURITY:
    Your User ID uniquely identifies your secrets on the servers. It is critical that:
    • You use the same User ID for all your files
    • You keep your User ID private (anyone with it can overwrite your secrets)
    • You choose a unique User ID that others won't guess
    • You remember your User ID for future decryption

    You can set the OPENADP_USER_ID environment variable to avoid typing it repeatedly.

SERVER DISCOVERY:
    By default, the tool fetches the server list from servers.openadp.org/api/servers.json
    If the registry is unavailable, it falls back to hardcoded servers.
    Use -servers to specify your own server list and skip discovery.

EXAMPLES:
    # Encrypt a file using discovered servers (fetches from servers.openadp.org)
    openadp-encrypt.py --file document.txt

    # Encrypt using specific servers (skip discovery)
    openadp-encrypt.py --file document.txt --servers "https://server1.com,https://server2.com"

    # Use a different server registry
    openadp-encrypt.py --file document.txt --servers-url "https://my-registry.com"

    # Use environment variables to avoid prompts
    export OPENADP_PASSWORD="mypassword"
    export OPENADP_USER_ID="myuserid"
    openadp-encrypt.py --file document.txt

The encrypted file will be saved as <filename>.enc
""")


def get_hostname():
    """Get hostname for device identification"""
    try:
        return socket.gethostname()
    except:
        return "unknown"


def write_uint32_le(f, value):
    """Write a 32-bit unsigned integer in little-endian format"""
    f.write(struct.pack('<I', value))


def encrypt_file(input_filename, password, user_id, server_infos, servers_url):
    """Encrypt a file using OpenADP servers"""
    output_filename = input_filename + ".enc"
    
    # Generate encryption key using OpenADP with full distributed protocol
    print("🔄 Generating encryption key using OpenADP servers...")
    # Create Identity from filename, user_id, and hostname (matching old derive_identifiers behavior)
    identity = Identity(
        uid=user_id,
        did=get_hostname(),
        bid=f"file://{os.path.basename(input_filename)}"
    )
    result = generate_encryption_key(identity, password, 10, 0, server_infos)
    
    if result.error:
        raise Exception(f"failed to generate encryption key: {result.error}")
    
    # Extract information from the result
    enc_key = result.encryption_key
    auth_codes = result.auth_codes
    actual_server_urls = [server_info.url for server_info in result.server_infos]
    threshold = result.threshold
    
    print(f"🔑 Generated authentication codes for {len(auth_codes.server_auth_codes)} servers")
    print(f"🔑 Key generated successfully (UID={user_id}, DID={get_hostname()}, BID=file://{os.path.basename(input_filename)})")
    
    # Show which servers were actually used for key generation
    if len(actual_server_urls) > 0 and len(actual_server_urls) != len(server_infos):
        print(f"📋 Servers actually used for key generation ({len(actual_server_urls)}):")
        for i, url in enumerate(actual_server_urls, 1):
            print(f"   {i}. {url}")
    
    # Read input file
    try:
        with open(input_filename, 'rb') as f:
            plaintext = f.read()
    except Exception as e:
        raise Exception(f"failed to read input file: {e}")
    
    # Generate random nonce
    nonce = get_random_bytes(NONCE_SIZE)
    
    # Create metadata using the actual results from keygen
    metadata = Metadata(
        servers=actual_server_urls,
        threshold=threshold,
        version="1.0",
        auth_code=auth_codes.base_auth_code,
        user_id=user_id
    )
    
    metadata_json = json.dumps(metadata.to_dict()).encode('utf-8')
    
    # Encrypt the file using metadata as additional authenticated data
    cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(metadata_json)  # Additional authenticated data
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # Combine ciphertext and tag for compatibility with Go's GCM implementation
    encrypted_data = ciphertext + tag
    
    # Write encrypted file: [metadata_length][metadata][nonce][encrypted_data]
    try:
        with open(output_filename, 'wb') as f:
            # Write metadata length (4 bytes, little endian)
            write_uint32_le(f, len(metadata_json))
            
            # Write metadata
            f.write(metadata_json)
            
            # Write nonce
            f.write(nonce)
            
            # Write encrypted data
            f.write(encrypted_data)
    except Exception as e:
        raise Exception(f"failed to create output file: {e}")
    
    print(f"📁 Input:  {input_filename} ({len(plaintext)} bytes)")
    print(f"📁 Output: {output_filename} ({4 + len(metadata_json) + NONCE_SIZE + len(encrypted_data)} bytes)")
    print(f"🔐 Encryption: AES-GCM")
    print(f"🌐 Servers: {len(actual_server_urls)} servers used")
    print(f"🎯 Threshold: {threshold}-of-{len(actual_server_urls)} recovery")
    
    # Show final server list stored in metadata
    print(f"📋 Servers stored in encrypted file metadata:")
    for i, url in enumerate(actual_server_urls, 1):
        print(f"   {i}. {url}")


def main():
    parser = argparse.ArgumentParser(description="OpenADP File Encryption Tool", add_help=False)
    parser.add_argument("--file", dest="filename", help="File to encrypt (required)")
    parser.add_argument("--password", help="Password for key derivation (will prompt if not provided)")
    parser.add_argument("--user-id", dest="user_id", help="User ID for secret ownership (will prompt if not provided)")
    parser.add_argument("--servers", help="Comma-separated list of server URLs (optional)")
    parser.add_argument("--servers-url", dest="servers_url", default="https://servers.openadp.org", 
                       help="URL to scrape for server list (default: https://servers.openadp.org)")
    parser.add_argument("--version", action="store_true", help="Show version information")
    parser.add_argument("--help", action="store_true", help="Show help information")
    
    args = parser.parse_args()
    
    if args.version:
        print(f"OpenADP File Encryption Tool v{VERSION}")
        return
    
    if args.help:
        show_help()
        return
    
    if not args.filename:
        print("Error: --file is required")
        show_help()
        sys.exit(1)
    
    # Check if input file exists
    if not os.path.exists(args.filename):
        print(f"Error: Input file '{args.filename}' not found.")
        sys.exit(1)
    
    # Get password (priority: flag > environment > prompt)
    password_str = ""
    if args.password:
        password_str = args.password
        print("⚠️  Warning: Password provided via command line (visible in process list)")
    elif os.environ.get("OPENADP_PASSWORD"):
        password_str = os.environ.get("OPENADP_PASSWORD")
        print("Using password from environment variable")
    else:
        password_str = getpass.getpass("Enter password: ")
    
    # Get user ID (priority: flag > environment > prompt)
    user_id_str = ""
    if args.user_id:
        user_id_str = args.user_id
        print("⚠️  Warning: User ID provided via command line (visible in process list)")
    elif os.environ.get("OPENADP_USER_ID"):
        user_id_str = os.environ.get("OPENADP_USER_ID")
        print("Using user ID from environment variable")
    else:
        user_id_str = input("Enter your user ID (this identifies your secrets): ").strip()
        if not user_id_str:
            print("Error: User ID cannot be empty")
            sys.exit(1)
    
    # Validate user ID
    user_id_str = user_id_str.strip()
    if len(user_id_str) < 3:
        print("Error: User ID must be at least 3 characters long")
        sys.exit(1)
    if len(user_id_str) > 64:
        print("Error: User ID must be at most 64 characters long")
        sys.exit(1)
    
    # Get server list
    server_infos = []
    if args.servers:
        print("📋 Using manually specified servers...")
        server_urls = [url.strip() for url in args.servers.split(",")]
        print(f"   Servers specified: {len(server_urls)}")
        for i, url in enumerate(server_urls, 1):
            print(f"   {i}. {url}")
        
        # Get public keys directly from each server via GetServerInfo
        print("   🔍 Querying servers for public keys...")
        server_infos = []
        for url in server_urls:
            try:
                # Create a basic client to call GetServerInfo
                basic_client = OpenADPClient(url)
                server_info = basic_client.get_server_info()
                
                # Extract public key from server info
                public_key = ""
                if isinstance(server_info, dict) and "noise_nk_public_key" in server_info:
                    noise_key = server_info["noise_nk_public_key"]
                    if noise_key:
                        public_key = "ed25519:" + noise_key
                
                server_infos.append(ServerInfo(
                    url=url,
                    public_key=public_key,
                    country="Unknown"
                ))
                
                key_status = "❌ No public key" if not public_key else "🔐 Public key available"
                print(f"   ✅ {url} - {key_status}")
            except Exception as e:
                print(f"   ⚠️  Failed to get server info from {url}: {e}")
                # Add server without public key as fallback
                server_infos.append(ServerInfo(
                    url=url,
                    public_key="",
                    country="Unknown"
                ))
    else:
        print(f"🌐 Discovering servers from registry: {args.servers_url}")
        
        # Try to get full server information including public keys
        try:
            server_infos = get_servers(args.servers_url)
            if not server_infos:
                raise Exception("No servers returned from registry")
            print(f"   ✅ Successfully fetched {len(server_infos)} servers from registry")
        except Exception as e:
            print(f"   ⚠️  Failed to fetch from registry: {e}")
            print("   🔄 Falling back to hardcoded servers...")
            server_infos = get_fallback_server_info()
            print(f"   Fallback servers: {len(server_infos)}")
        
        print("   📋 Server list with public keys:")
        for i, server in enumerate(server_infos, 1):
            key_status = "❌ No public key" if not server.public_key else "🔐 Public key available"
            print(f"      {i}. {server.url} [{server.country}] - {key_status}")
    
    if not server_infos:
        print("❌ Error: No servers available")
        sys.exit(1)
    
    # Encrypt the file
    try:
        encrypt_file(args.filename, password_str, user_id_str, server_infos, args.servers_url)
        print("✅ File encrypted successfully!")
    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 