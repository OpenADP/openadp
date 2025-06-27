#!/usr/bin/env python3

import argparse
import sys
import os
import getpass
import json
from openadp.ocrypt import recover

def main():
    parser = argparse.ArgumentParser(
        description="Recover a long-term secret using Ocrypt distributed cryptography.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --metadata '{"servers":[...]}'
  %(prog)s --metadata "$(cat metadata.json)" --output result.json
  %(prog)s --metadata "$(cat metadata.json)" --password mypin"""
    )
    
    parser.add_argument("--metadata", required=True, help="Metadata blob from registration (required)")
    parser.add_argument("--password", help="Password/PIN to unlock the secret (will prompt if not provided)")
    parser.add_argument("--servers-url", default="", help="Custom URL for server registry (empty uses default)")
    parser.add_argument("--output", help="File to write recovery result JSON (writes to stdout if not specified)")
    
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
        # Call ocrypt.recover
        secret, remaining_guesses, updated_metadata = recover(
            metadata=args.metadata.encode('utf-8'),
            pin=pin,
            servers_url=args.servers_url
        )
        
        # Create JSON tuple output (matching Go structure)
        result = {
            "secret": secret.decode('utf-8'),
            "remaining_guesses": remaining_guesses,
            "updated_metadata": updated_metadata.decode('utf-8')
        }
        
        output_json = json.dumps(result, separators=(',', ':'))
        
        # Output result as JSON
        if args.output:
            # Write to file
            with open(args.output, 'w') as f:
                f.write(output_json)
            print(f"✅ Recovery result written to {args.output}", file=sys.stderr)
        else:
            # Write to stdout
            print(output_json)
            
    except Exception as e:
        print(f"Recovery failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 