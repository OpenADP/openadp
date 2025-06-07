# Copyright 2025 OpenADP Authors.  This work is licensed under the Apache 2.0 license.
# 
# It is best to keep the I/O wrappers around a service separate from the
# service logic itself.  This is the gRPC wrapper for the OpenADP service.
# There may also be an HTTP wrapper in the future.

import grpc

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    route_guide_pb2_grpc.add_RouteGuideServicer_to_server(RouteGuideServicer(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    server.wait_for_termination()
