#!/usr/bin/env python3

import argparse
import sys
import os
import getpass
import json
from openadp.ocrypt import register

def main():
    parser = argparse.ArgumentParser(
        description="Register a long-term secret using Ocrypt distributed cryptography.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --user-id alice@example.com --app-id myapp --long-term-secret "my secret key"
  %(prog)s --user-id alice@example.com --app-id myapp --long-term-secret "my secret key" --output metadata.json"""
    )
    
    parser.add_argument("--user-id", required=True, help="Unique identifier for the user (required)")
    parser.add_argument("--app-id", required=True, help="Application identifier to namespace secrets per app (required)")
    parser.add_argument("--long-term-secret", required=True, help="Long-term secret to protect (required)")
    parser.add_argument("--password", help="Password/PIN to unlock the secret (will prompt if not provided)")
    parser.add_argument("--max-guesses", type=int, default=10, help="Maximum wrong PIN attempts before lockout (default: 10)")
    parser.add_argument("--servers-url", default="", help="Custom URL for server registry (empty uses default)")
    parser.add_argument("--output", help="File to write metadata JSON (writes to stdout if not specified)")
    
    args = parser.parse_args()
    
    # Handle password input
    if args.password:
        pin = args.password
    else:
        pin = getpass.getpass("Password: ")
        if not pin:
            print("Error: password cannot be empty", file=sys.stderr)
            sys.exit(1)
    
    try:
        # Call ocrypt.register
        metadata = register(
            user_id=args.user_id,
            app_id=args.app_id,
            long_term_secret=args.long_term_secret.encode('utf-8'),
            pin=pin,
            max_guesses=args.max_guesses,
            servers_url=args.servers_url
        )
        
        # Output metadata as JSON
        if args.output:
            # Write to file
            with open(args.output, 'wb') as f:
                f.write(metadata)
            print(f"✅ Metadata written to {args.output}", file=sys.stderr)
        else:
            # Write to stdout
            print(metadata.decode('utf-8'))
            
    except Exception as e:
        print(f"Registration failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 