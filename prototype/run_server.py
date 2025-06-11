#!/usr/bin/env python3
"""
OpenADP Server Runner

This script runs the OpenADP JSON-RPC server with Noise-KK encryption and proper Python path setup.
It should be placed in the prototype root directory and used instead of running
the server module directly.
"""

import sys
import os

# Add the src directory to Python path
src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_path)

# Import and run the server
from server.noise_jsonrpc_server import main

if __name__ == "__main__":
    main() 