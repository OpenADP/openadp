#!/usr/bin/env python3
"""
OpenADP File Decryption Tool - Python Version

This tool exactly matches the functionality of cmd/openadp-decrypt/main.go
"""

import argparse
import os
import sys
import json
import getpass
import struct
import hashlib
import socket
from pathlib import Path
from Crypto.Cipher import AES

# Add the openadp package to the path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'sdk', 'python'))

from openadp.keygen import recover_encryption_key, Identity, AuthCodes
from openadp.client import get_servers, get_fallback_server_info, ServerInfo, OpenADPClient
from openadp.debug import set_debug_mode, debug_log

VERSION = "0.1.3"
NONCE_SIZE = 12  # AES-GCM nonce size


class Metadata:
    """Metadata stored with encrypted files"""
    def __init__(self, data_dict):
        self.servers = data_dict.get("servers", [])
        self.threshold = data_dict.get("threshold", 0)
        self.version = data_dict.get("version", "")
        self.auth_code = data_dict.get("auth_code", "")
        self.user_id = data_dict.get("user_id", "")
        self.device_id = data_dict.get("device_id", "")
        self.backup_id = data_dict.get("backup_id", "")


def show_help():
    print("""OpenADP File Decryption Tool

USAGE:
    openadp-decrypt.py --file <filename> [OPTIONS]

OPTIONS:
    --file <path>          File to decrypt (required)
    --password <password>  Password for key derivation (will prompt if not provided)
    --user-id <id>         User ID override (will use metadata or prompt if not provided)
    --servers <urls>       Comma-separated list of server URLs to override metadata servers
    --debug                Enable debug mode for deterministic operations
    --version              Show version information
    --help                 Show this help message

USER ID HANDLING:
    The tool will use the User ID in this priority order:
    1. Command line flag (--user-id)
    2. User ID stored in the encrypted file metadata
    3. OPENADP_USER_ID environment variable
    4. Interactive prompt

    You only need to specify a User ID if it's missing from the file metadata
    or if you want to override it for some reason.

DEBUG MODE:
    When --debug is enabled, all cryptographic operations become deterministic
    for testing purposes. This should NEVER be used in production.

EXAMPLES:
    # Decrypt a file using servers from metadata
    openadp-decrypt.py --file document.txt.enc

    # Decrypt using override servers
    openadp-decrypt.py --file document.txt.enc --servers "https://server1.com,https://server2.com"

    # Override user ID (useful for corrupted metadata)
    openadp-decrypt.py --file document.txt.enc --user-id "myuserid"

    # Enable debug mode for testing
    openadp-decrypt.py --file document.txt.enc --debug

    # Use environment variables
    export OPENADP_PASSWORD="mypassword"
    export OPENADP_USER_ID="myuserid"
    openadp-decrypt.py --file document.txt.enc

The decrypted file will be saved without the .enc extension
""")


def read_uint32_le(data):
    """Read a 32-bit unsigned integer in little-endian format"""
    return struct.unpack('<I', data[:4])[0]


def recover_encryption_key_with_metadata(metadata, password, user_id, server_infos, threshold):
    """Recover encryption key using OpenADP servers with portable metadata"""
    debug_log(f"Starting key recovery with portable metadata")
    debug_log(f"User ID: {user_id}, Threshold: {threshold}")
    debug_log(f"Server count: {len(server_infos)}")
    
    # Create Identity using portable values from metadata (for portable decryption)
    # The device_id and backup_id must match what was used during encryption
    device_id, backup_id = "", ""
    
    if metadata.device_id and metadata.backup_id:
        # Read from metadata (portable format)
        device_id = metadata.device_id
        backup_id = metadata.backup_id
        print("✅ Using device_id and backup_id from metadata (portable format)")
    else:
        # Fallback to current environment (legacy compatibility)
        device_id = socket.gethostname()
        backup_id = f"file://{os.path.basename('unknown')}"
        print("⚠️  Using device_id and backup_id from current environment (legacy format)")
    
    identity = Identity(uid=user_id, did=device_id, bid=backup_id)
    debug_log(f"Identity created - UID: {identity.uid}, DID: {identity.did}, BID: {identity.bid}")
    print(f"🔑 Identity: user_id={identity.uid}, device_id={identity.did}, backup_id={identity.bid}")
    
    # Regenerate server auth codes from base auth code
    base_auth_code = metadata.auth_code
    server_auth_codes = {}
    for server_info in server_infos:
        # Derive server-specific code using SHA256 (same as GenerateAuthCodes)
        combined = f"{base_auth_code}:{server_info.url}"
        hash_obj = hashlib.sha256(combined.encode('utf-8'))
        server_auth_codes[server_info.url] = hash_obj.hexdigest()
        debug_log(f"Generated auth code for {server_info.url}")
    
    # Create AuthCodes structure from metadata
    auth_codes = AuthCodes(
        base_auth_code=base_auth_code,
        server_auth_codes=server_auth_codes,
        user_id=user_id
    )
    debug_log(f"AuthCodes structure created with {len(server_auth_codes)} server codes")
    
    # Recover encryption key using the full distributed protocol
    result = recover_encryption_key(identity, password, server_infos, threshold, auth_codes)
    if result.error:
        debug_log(f"Key recovery failed: {result.error}")
        raise Exception(f"key recovery failed: {result.error}")
    
    debug_log(f"Key recovered successfully ({len(result.encryption_key)} bytes)")
    print("✅ Key recovered successfully")
    return result.encryption_key


def recover_encryption_key_with_server_info(filename, password, user_id, base_auth_code, server_infos, threshold):
    """Legacy function - recover encryption key using OpenADP servers"""
    debug_log(f"Starting key recovery for file: {filename}")
    debug_log(f"User ID: {user_id}, Threshold: {threshold}")
    debug_log(f"Server count: {len(server_infos)}")
    
    # Create Identity from filename, user_id (legacy behavior)
    hostname = socket.gethostname()
    identity = Identity(
        uid=user_id,
        did=hostname,
        bid=f"file://{os.path.basename(filename)}"
    )
    debug_log(f"Identity created - UID: {identity.uid}, DID: {identity.did}, BID: {identity.bid}")
    print(f"🔑 Recovering with UID={identity.uid}, DID={identity.did}, BID={identity.bid}")
    
    # Regenerate server auth codes from base auth code
    server_auth_codes = {}
    for server_info in server_infos:
        # Derive server-specific code using SHA256 (same as GenerateAuthCodes)
        combined = f"{base_auth_code}:{server_info.url}"
        hash_obj = hashlib.sha256(combined.encode('utf-8'))
        server_auth_codes[server_info.url] = hash_obj.hexdigest()
        debug_log(f"Generated auth code for {server_info.url}")
    
    # Create AuthCodes structure from metadata
    auth_codes = AuthCodes(
        base_auth_code=base_auth_code,
        server_auth_codes=server_auth_codes,
        user_id=user_id
    )
    debug_log(f"AuthCodes structure created with {len(server_auth_codes)} server codes")
    
    # Recover encryption key using the full distributed protocol
    result = recover_encryption_key(identity, password, server_infos, threshold, auth_codes)
    if result.error:
        debug_log(f"Key recovery failed: {result.error}")
        raise Exception(f"key recovery failed: {result.error}")
    
    debug_log(f"Key recovered successfully ({len(result.encryption_key)} bytes)")
    print("✅ Key recovered successfully")
    return result.encryption_key


def get_auth_codes_from_metadata(metadata):
    """Extract authentication codes and user ID from metadata"""
    if not metadata.auth_code:
        raise Exception("no authentication code found in metadata")
    
    if not metadata.user_id:
        raise Exception("no user ID found in metadata")
    
    return metadata.auth_code, metadata.user_id


def decrypt_file(input_filename, password, user_id, override_servers):
    """Decrypt a file using OpenADP servers"""
    debug_log(f"Starting file decryption: {input_filename}")
    debug_log(f"User ID: {user_id}")
    debug_log(f"Override servers: {override_servers is not None}")
    
    # Determine output filename
    if input_filename.endswith(".enc"):
        output_filename = input_filename[:-4]  # Remove .enc extension
    else:
        output_filename = input_filename + ".dec"
        print(f"Warning: Input file doesn't end with .enc, using '{output_filename}' for output")
    
    debug_log(f"Output filename: {output_filename}")
    
    # Read the encrypted file
    try:
        with open(input_filename, 'rb') as f:
            file_data = f.read()
        debug_log(f"Read encrypted file: {len(file_data)} bytes")
    except Exception as e:
        debug_log(f"Failed to read input file: {e}")
        raise Exception(f"failed to read input file: {e}")
    
    # Validate file size
    min_size = 4 + 1 + NONCE_SIZE + 1  # metadata_length + minimal_metadata + nonce + minimal_ciphertext
    if len(file_data) < min_size:
        debug_log(f"File too small: {len(file_data)} bytes (minimum {min_size})")
        raise Exception(f"file is too small to be a valid encrypted file (expected at least {min_size} bytes, got {len(file_data)})")
    
    # Extract metadata length (first 4 bytes, little endian)
    metadata_length = read_uint32_le(file_data[:4])
    debug_log(f"Metadata length: {metadata_length} bytes")
    
    # Validate metadata length
    if metadata_length > len(file_data) - 4 - NONCE_SIZE:
        debug_log(f"Invalid metadata length: {metadata_length}")
        raise Exception(f"invalid metadata length {metadata_length}")
    
    # Extract components: [metadata_length][metadata][nonce][encrypted_data]
    metadata_start = 4
    metadata_end = metadata_start + metadata_length
    nonce_start = metadata_end
    nonce_end = nonce_start + NONCE_SIZE
    
    metadata_json = file_data[metadata_start:metadata_end]
    nonce = file_data[nonce_start:nonce_end]
    ciphertext = file_data[nonce_end:]
    
    debug_log(f"Extracted nonce: {nonce.hex()}")
    debug_log(f"Ciphertext length: {len(ciphertext)} bytes")
    
    # Parse metadata
    try:
        metadata_dict = json.loads(metadata_json.decode('utf-8'))
        metadata = Metadata(metadata_dict)
        debug_log(f"Parsed metadata: {len(metadata.servers)} servers, threshold {metadata.threshold}")
    except Exception as e:
        debug_log(f"Failed to parse metadata: {e}")
        raise Exception(f"failed to parse metadata: {e}")
    
    server_urls = metadata.servers
    if not server_urls:
        raise Exception("no server URLs found in metadata")
    
    print(f"Found metadata with {len(server_urls)} servers, threshold {metadata.threshold}")
    print(f"File version: {metadata.version}")
    
    # Show servers from metadata
    print("📋 Servers from encrypted file metadata:")
    for i, url in enumerate(server_urls, 1):
        print(f"   {i}. {url}")
    
    # Use override servers if provided
    server_infos = []
    if override_servers:
        print(f"🔄 Overriding metadata servers with {len(override_servers)} custom servers")
        print("📋 Override servers:")
        for i, url in enumerate(override_servers, 1):
            print(f"   {i}. {url}")
        
        # Get public keys directly from each override server via GetServerInfo
        print("   🔍 Querying override servers for public keys...")
        server_infos = []
        for url in override_servers:
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
        
        server_urls = override_servers
    else:
        # Get server information from the secure registry (servers.json) instead of querying each server individually
        print("   🔍 Fetching server information from secure registry...")
        
        # Use the default servers.json registry URL
        servers_url = "https://servers.openadp.org/api/servers.json"
        
        # Try to get full server information including public keys from the registry
        try:
            registry_server_infos = get_servers(servers_url)
            if not registry_server_infos:
                raise Exception("No servers returned from registry")
            print(f"   ✅ Successfully fetched {len(registry_server_infos)} servers from registry")
        except Exception as e:
            print(f"   ⚠️  Failed to fetch from registry: {e}")
            print("   🔄 Falling back to hardcoded servers...")
            registry_server_infos = get_fallback_server_info()
        
        # Match servers from metadata with registry servers to get public keys
        server_infos = []
        for metadata_url in server_urls:
            # Find matching server in registry
            matched_server = None
            for registry_server in registry_server_infos:
                if registry_server.url == metadata_url:
                    matched_server = registry_server
                    break
            
            if matched_server:
                # Use server info from registry (includes public key)
                server_infos.append(matched_server)
                key_status = "❌ No public key" if not matched_server.public_key else "🔐 Public key available (from registry)"
                print(f"   ✅ {metadata_url} - {key_status}")
            else:
                # Server not found in registry, add without public key as fallback
                print(f"   ⚠️  Server {metadata_url} not found in registry, adding without public key")
                server_infos.append(ServerInfo(
                    url=metadata_url,
                    public_key="",
                    country="Unknown"
                ))
    
    # Check authentication requirements
    if not metadata.auth_code:
        print("ℹ️  File was encrypted without authentication (legacy), but using auth for decryption")
    else:
        print("🔒 File was encrypted with authentication (standard)")
    
    # Determine final user ID (priority: flag > metadata > environment > prompt)
    final_user_id = ""
    if user_id:
        final_user_id = user_id
        print(f"🔐 Using user ID from command line: {final_user_id}")
    elif metadata.user_id:
        final_user_id = metadata.user_id
        print(f"🔐 Using user ID from file metadata: {final_user_id}")
    elif os.environ.get("OPENADP_USER_ID"):
        final_user_id = os.environ.get("OPENADP_USER_ID")
        print("🔐 Using user ID from environment variable")
    else:
        final_user_id = input("Enter your user ID (same as used during encryption): ").strip()
        if not final_user_id:
            raise Exception("user ID cannot be empty")
    
    # Check authentication requirements
    if not metadata.auth_code:
        raise Exception("No authentication code found in metadata - file may be corrupted or from unsupported version")
    
    # Recover encryption key using OpenADP with portable metadata
    print("🔄 Recovering encryption key from OpenADP servers...")
    enc_key = recover_encryption_key_with_metadata(metadata, password, final_user_id, server_infos, metadata.threshold)
    
    # Decrypt the file using metadata as additional authenticated data
    try:
        # Split the encrypted data into ciphertext and tag (Go's GCM implementation combines them)
        if len(ciphertext) < 16:  # GCM tag is 16 bytes
            raise Exception("ciphertext too short for GCM tag")
        
        actual_ciphertext = ciphertext[:-16]
        tag = ciphertext[-16:]
        
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
        cipher.update(metadata_json)  # Additional authenticated data
        plaintext = cipher.decrypt_and_verify(actual_ciphertext, tag)
    except Exception as e:
        # AEAD authentication failure should always be fatal
        raise Exception(f"decryption failed: {e} (wrong password or corrupted file)")
    
    # Write the decrypted file
    try:
        with open(output_filename, 'wb') as f:
            f.write(plaintext)
    except Exception as e:
        raise Exception(f"failed to write output file: {e}")
    
    print(f"📁 Input:  {input_filename} ({len(file_data)} bytes)")
    print(f"📁 Output: {output_filename} ({len(plaintext)} bytes)")
    print(f"🌐 Servers: {len(server_urls)} servers used")
    print(f"🎯 Threshold: {metadata.threshold}-of-{len(server_urls)} recovery")
    print("🔐 Authentication: Enabled (Authentication Codes)")
    
    # Show final server list used for recovery
    print("📋 Servers used for decryption:")
    for i, url in enumerate(server_urls, 1):
        print(f"   {i}. {url}")


def main():
    parser = argparse.ArgumentParser(description="OpenADP File Decryption Tool", add_help=False)
    parser.add_argument("--file", dest="filename", help="File to decrypt (required)")
    parser.add_argument("--password", help="Password for key derivation (will prompt if not provided)")
    parser.add_argument("--user-id", dest="user_id", help="User ID override (will use metadata or prompt if not provided)")
    parser.add_argument("--servers", help="Comma-separated list of server URLs to override metadata servers")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for deterministic operations")
    parser.add_argument("--version", action="store_true", help="Show version information")
    parser.add_argument("--help", action="store_true", help="Show help information")
    
    args = parser.parse_args()
    
    # Enable debug mode if requested
    if args.debug:
        set_debug_mode(True)
        debug_log("Debug mode enabled for openadp-decrypt")
    
    if args.version:
        print(f"OpenADP File Decryption Tool v{VERSION}")
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
    
    # Parse override servers if provided
    override_server_urls = []
    if args.servers:
        override_server_urls = [url.strip() for url in args.servers.split(",")]
    
    # Decrypt the file
    try:
        decrypt_file(args.filename, password_str, args.user_id, override_server_urls)
        print("✅ File decrypted successfully!")
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 
