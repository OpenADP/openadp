#!/usr/bin/env python3

import argparse
import sys
import os
import getpass
import json
from openadp.ocrypt import recover
from openadp.debug import set_debug_mode, debug_log

def main():
    parser = argparse.ArgumentParser(
        description="Recover a long-term secret using Ocrypt distributed cryptography.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --metadata '{"servers":[...]}'
  %(prog)s --metadata "$(cat metadata.json)" --output result.json
  %(prog)s --metadata "$(cat metadata.json)" --password mypin
  %(prog)s --metadata "$(cat metadata.json)" --debug"""
    )
    
    parser.add_argument("--metadata", required=True, help="Metadata blob from registration (required)")
    parser.add_argument("--password", help="Password/PIN to unlock the secret (will prompt if not provided)")
    parser.add_argument("--servers-url", default="", help="Custom URL for server registry (empty uses default)")
    parser.add_argument("--output", help="File to write recovery result JSON (writes to stdout if not specified)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for deterministic operations")
    
    args = parser.parse_args()
    
    # Enable debug mode if requested
    if args.debug:
        set_debug_mode(True)
        debug_log("Debug mode enabled for ocrypt-recover")
    
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
        # Call ocrypt.recover
        debug_log("Starting ocrypt recovery...")
        secret, remaining_guesses, updated_metadata = recover(
            metadata=args.metadata.encode('utf-8'),
            pin=pin,
            servers_url=args.servers_url
        )
        debug_log(f"Recovery completed successfully")
        debug_log(f"Secret length: {len(secret)} bytes")
        debug_log(f"Remaining guesses: {remaining_guesses}")
        debug_log(f"Updated metadata length: {len(updated_metadata)} bytes")
        
        # Create JSON tuple output (matching Go structure)
        result = {
            "secret": secret.decode('utf-8'),
            "remaining_guesses": remaining_guesses,
            "updated_metadata": updated_metadata.decode('utf-8')
        }
        
        output_json = json.dumps(result, separators=(',', ':'))
        debug_log(f"Output JSON length: {len(output_json)} characters")
        
        # Output result as JSON
        if args.output:
            # Write to file
            with open(args.output, 'w') as f:
                f.write(output_json)
            print(f"✅ Recovery result written to {args.output}", file=sys.stderr)
            debug_log(f"Recovery result written to file: {args.output}")
        else:
            # Write to stdout
            print(output_json)
            debug_log("Recovery result written to stdout")
            
    except Exception as e:
        debug_log(f"Recovery failed: {e}")
        print(f"Recovery failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 