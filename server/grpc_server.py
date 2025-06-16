# Copyright 2025 OpenADP Authors.  This work is licensed under the Apache 2.0 license.
# 
# It is best to keep the I/O wrappers around a service separate from the
# service logic itself.  This is the gRPC wrapper for the OpenADP service.
# There may also be an HTTP wrapper in the future.

import grpc
from concurrent import futures
import logging

import sys
import os

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from openadp import database
from server import server

# Try to import protobuf files, but make it optional since they might not be generated
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'proto'))
    import openadp_pb2
    import openadp_pb2_grpc
    GRPC_AVAILABLE = True
except ImportError:
    print("Warning: gRPC protobuf files not found. Run protobuf generation first.")
    GRPC_AVAILABLE = False

if GRPC_AVAILABLE:
    class OpenADPServicer(openadp_pb2_grpc.OpenADPServicer):
        """Provides methods that implement functionality of OpenADP server."""

        def __init__(self):
            self.db = database.Database("openadp.db")

        def RegisterSecret(self, request, context):
            try:
                server.register_secret(self.db, request.UID, request.DID, request.BID,
                    request.version, request.x, request.y, request.max_guesses, request.expiration)
                return openadp_pb2.Empty()
            except Exception as e:
                context.abort(grpc.StatusCode.INTERNAL, str(e))

        def RecoverSecret(self, request, context):
            try:
                res = server.recover_secret(self.db, request.UID, request.DID,
                        request.BID, request.B, request.guess_num)
                if isinstance(res, BaseException):
                    context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(res))
                return res
            except Exception as e:
                context.abort(grpc.StatusCode.INTERNAL, str(e))

        def ListBackups(self, request, context):
            try:
                res = server.list_backups(self.db, request.UID)
                if isinstance(res, BaseException):
                    context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(res))
                return res
            except Exception as e:
                context.abort(grpc.StatusCode.INTERNAL, str(e))
else:
    # Dummy class if gRPC is not available
    class OpenADPServicer:
        pass

def serve():
    if not GRPC_AVAILABLE:
        print("Error: gRPC protobuf files not available. Cannot start gRPC server.")
        return
        
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    openadp_pb2_grpc.add_OpenADPServicer_to_server(OpenADPServicer(), server)
    server.add_insecure_port("[::]:50051")
    print("Starting to serve...")
    server.start()
    print(server.wait_for_termination())

def main():
    """Main function for gRPC server."""
    logging.basicConfig()
    serve()

if __name__ == '__main__':
    main()
