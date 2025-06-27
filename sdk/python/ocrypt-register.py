#!/usr/bin/env python3

import argparse
import sys
import os
import getpass
import json
from openadp.ocrypt import register
from openadp.debug import set_debug_mode, debug_log

def main():
    parser = argparse.ArgumentParser(
        description="Register a long-term secret using Ocrypt distributed cryptography.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --user-id alice@example.com --app-id myapp --long-term-secret "my secret key"
  %(prog)s --user-id alice@example.com --app-id myapp --long-term-secret "my secret key" --output metadata.json
  %(prog)s --user-id alice@example.com --app-id myapp --long-term-secret "my secret key" --debug"""
    )
    
    parser.add_argument("--user-id", required=True, help="Unique identifier for the user (required)")
    parser.add_argument("--app-id", required=True, help="Application identifier to namespace secrets per app (required)")
    parser.add_argument("--long-term-secret", required=True, help="Long-term secret to protect (required)")
    parser.add_argument("--password", help="Password/PIN to unlock the secret (will prompt if not provided)")
    parser.add_argument("--max-guesses", type=int, default=10, help="Maximum wrong PIN attempts before lockout (default: 10)")
    parser.add_argument("--servers-url", default="", help="Custom URL for server registry (empty uses default)")
    parser.add_argument("--output", help="File to write metadata JSON (writes to stdout if not specified)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for deterministic operations")
    
    args = parser.parse_args()
    
    # Enable debug mode if requested
    if args.debug:
        set_debug_mode(True)
        debug_log("Debug mode enabled for ocrypt-register")
    
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
    
    debug_log(f"User ID: {args.user_id}")
    debug_log(f"App ID: {args.app_id}")
    debug_log(f"Long-term secret length: {len(args.long_term_secret)} characters")
    debug_log(f"Max guesses: {args.max_guesses}")
    debug_log(f"Servers URL: {args.servers_url if args.servers_url else 'default'}")
    debug_log(f"Output file: {args.output if args.output else 'stdout'}")
    
    try:
        # Call ocrypt.register
        debug_log("Starting ocrypt registration...")
        metadata = register(
            user_id=args.user_id,
            app_id=args.app_id,
            long_term_secret=args.long_term_secret.encode('utf-8'),
            pin=pin,
            max_guesses=args.max_guesses,
            servers_url=args.servers_url
        )
        debug_log(f"Registration completed, metadata size: {len(metadata)} bytes")
        
        # Output metadata as JSON
        if args.output:
            # Write to file
            with open(args.output, 'wb') as f:
                f.write(metadata)
            print(f"✅ Metadata written to {args.output}", file=sys.stderr)
            debug_log(f"Metadata written to file: {args.output}")
        else:
            # Write to stdout
            print(metadata.decode('utf-8'))
            debug_log("Metadata written to stdout")
            
    except Exception as e:
        debug_log(f"Registration failed: {e}")
        print(f"Registration failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 