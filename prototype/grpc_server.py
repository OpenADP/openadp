# Copyright 2025 OpenADP Authors.  This work is licensed under the Apache 2.0 license.
# 
# It is best to keep the I/O wrappers around a service separate from the
# service logic itself.  This is the gRPC wrapper for the OpenADP service.
# There may also be an HTTP wrapper in the future.

import grpc
from concurrent import futures
import logging

import database
import openadp_pb2
import openadp_pb2_grpc
import openadp_server

class OpenADPServicer(openadp_pb2_grpc.OpenADPServicer):
    """Provides methods that implement functionality of OpenADP server."""

    def __init__(self):
        self.db = database.Database("openadp.db")

    def RegisterSecret(self, request, context):
        try:
            openadp_server.registerSecret(self.db, request.UID, request.DID, request.BID,
                request.version, request.x, request.y, request.max_guesses, request.expiration)
            return ()
        except Exception as e:
            context.abort(grpc.StatusCode.INTERNAL, str(e))

    def RecoverSecret(self, request, coontext):
        try:
            res =  openadp_server.recoverSecret(self.db, request.UID, request.DID,
                    request.BID, request.B, request.guess_num)
            if isinstance(res, BaseException):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(res))
            return res
        except Exception as e:
            context.abort(grpc.StatusCode.INTERNAL, str(e))

    def ListBackups(self, request, context):
        try:
            res =  openadp_server.listBackups(self.db, request.UID)
            if isinstance(res, BaseException):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(res))
            return res
        except Exception as e:
            context.abort(grpc.StatusCode.INTERNAL, str(e))

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    openadp_pb2_grpc.add_OpenADPServicer_to_server(OpenADPServicer(), server)
    server.add_insecure_port("[::]:50051")
    print("Starting to serve...")
    server.start()
    print(server.wait_for_termination())

if __name__ == '__main__':
    logging.basicConfig()
    serve()
