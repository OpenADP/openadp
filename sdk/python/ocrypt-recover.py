#!/usr/bin/env python3

import argparse
import sys
import os
import getpass
import json
from openadp.ocrypt import recover_and_reregister
from openadp.debug import set_debug_mode, debug_log

def safe_write_file(filename, data, encoding='utf-8'):
    """
    Safely write data to a file, backing up existing file first.
    
    Args:
        filename: Path to the file to write
        data: Data to write (string or bytes)
        encoding: Encoding to use for writing (default: utf-8)
    """
    # Check if file exists
    if os.path.exists(filename):
        # File exists, create backup
        backup_name = filename + ".old"
        print(f"📋 Backing up existing {filename} to {backup_name}", file=sys.stderr)
        
        try:
            os.rename(filename, backup_name)
            print(f"✅ Backup created: {backup_name}", file=sys.stderr)
        except Exception as e:
            raise Exception(f"Failed to backup existing file: {e}")
    
    # Write new file
    try:
        if isinstance(data, bytes):
            with open(filename, 'wb') as f:
                f.write(data)
        else:
            with open(filename, 'w', encoding=encoding) as f:
                f.write(data)
    except Exception as e:
        raise Exception(f"Failed to write file: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Recover a long-term secret and re-register with fresh cryptographic material.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""This tool:
  1. Recovers your secret from old metadata
  2. Re-registers it with fresh cryptographic material
  3. Outputs new metadata (automatically backs up existing files)

Examples:
  %(prog)s --metadata '{"servers":[...]}'
  %(prog)s --metadata "$(cat metadata.json)" --output metadata.json
  %(prog)s --metadata "$(cat metadata.json)" --password mypin
  %(prog)s --metadata "$(cat metadata.json)" --debug

Note: Existing files are automatically backed up with .old extension"""
    )
    
    parser.add_argument("--metadata", required=True, help="Metadata blob from registration (required)")
    parser.add_argument("--password", help="Password/PIN to unlock the secret (will prompt if not provided)")
    parser.add_argument("--servers-url", default="", help="Custom URL for server registry (default: https://servers.openadp.org/api/servers.json)")
    parser.add_argument("--output", help="File to write new metadata JSON (writes to stdout if not specified)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode (deterministic operations)")
    parser.add_argument("--test-mode", action="store_true", help="Enable test mode (outputs JSON with secret and metadata)")
    
    args = parser.parse_args()
    
    # Enable debug mode if requested
    if args.debug:
        set_debug_mode(True)
        debug_log("🐛 Debug mode enabled - using deterministic operations")
        print("🐛 Debug mode enabled - using deterministic operations", file=sys.stderr)
    
    # Show default servers URL in help
    if not args.servers_url:
        debug_log("Using default servers URL: https://servers.openadp.org/api/servers.json")
    
    # Handle password input
    if args.password:
        pin = args.password
        debug_log("Password provided via command line")
    else:
        pin = getpass.getpass("Password: ")
        if not pin:
            print("Error: password cannot be empty", file=sys.stderr)
            sys.exit(1)
        debug_log("Password provided via prompt")
    
    debug_log(f"Metadata length: {len(args.metadata)} characters")
    debug_log(f"Servers URL: {args.servers_url if args.servers_url else 'default'}")
    debug_log(f"Output file: {args.output if args.output else 'stdout'}")
    
    try:
        # Call the new recover_and_reregister API
        debug_log("Starting ocrypt recovery and re-registration...")
        result = recover_and_reregister(
            old_metadata=args.metadata.encode('utf-8'),
            pin=pin,
            servers_url=args.servers_url
        )
        debug_log("Recovery and re-registration completed successfully")
        debug_log(f"Secret length: {len(result.secret)} bytes")
        debug_log(f"New metadata length: {len(result.new_metadata)} bytes")
        
        # Handle test mode
        if args.test_mode:
            try:
                # Try to decode secret as UTF-8 string
                secret_str = result.secret.decode('utf-8')
            except UnicodeDecodeError:
                # Binary data, use hex
                secret_str = result.secret.hex()
            
            test_result = {
                "secret": secret_str,
                "new_metadata": result.new_metadata.decode('utf-8')
            }
            print(json.dumps(test_result))
            debug_log("Test mode output generated")
            return
        
        # Normal mode: Print recovered secret to stderr for user verification
        try:
            # Try to decode as UTF-8 string
            secret_str = result.secret.decode('utf-8')
            print(f"🔑 Recovered secret: {secret_str}", file=sys.stderr)
        except UnicodeDecodeError:
            # Binary data, show hex
            print(f"🔑 Recovered secret (hex): {result.secret.hex()}", file=sys.stderr)
        
        # Output new metadata
        new_metadata_str = result.new_metadata.decode('utf-8')
        
        if args.output:
            # Write to file with safe backup
            safe_write_file(args.output, new_metadata_str)
            print(f"✅ New metadata written to {args.output}", file=sys.stderr)
            debug_log(f"New metadata written to file: {args.output}")
        else:
            # Write to stdout
            print(new_metadata_str)
            debug_log("New metadata written to stdout")
            
    except Exception as e:
        debug_log(f"Recovery failed: {e}")
        print(f"Recovery and re-registration failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 