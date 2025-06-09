# This seems to work as a client call:
#
#     $ curl --verbose -H "Content-Type: application/json" -d \
#     '{"jsonrpc":"2.0","method":"add","params":[3, 11],"id":1}' \
#     https://openadp.org/servers/xyzzybill
#
# The response is:
#
#    {"jsonrpc": "2.0", "result": 14, "id": 1}
#
# Note that https is required!

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

import database
import server

# There does not appear to be a lightweight JSON-RPC library that results in
# less work, so just handle it manually.
class RPCRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
       self.db = Database("openadp.db")
       super().__init__(*args, **kwargs)

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        try:
            request = json.loads(post_data.decode('utf-8'))
            method = request.get('method')
            params = request.get('params', [])
            request_id = request.get('id')

            if method == 'RegisterSecret':
                (result, error) = self.registerSecretadd(params)
            elif method == 'RecoverSecret':
                (result, error) = self.recoverSecret(params)
            elif method == 'ListBackups':
                (result, error) = self.listBackups(params)
            else:
                result = None
                error = {'code': -32601, 'message': 'Method not found'}

            if result is not None:
                response = {'jsonrpc': '2.0', 'result': result, 'id': request_id}
            else:
                 response = {'jsonrpc': '2.0', 'error': error, 'id': request_id}

        except json.JSONDecodeError:
            response = {'jsonrpc': '2.0', 'error': {'code': -32700, 'message':
                    'Parse error'}, 'id': None}

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('utf-8'))

    def registerSecretadd(self, params):
        try:
            openadp_server.registerSecret(self.db, request.UID, request.DID, request.BID,
                request.version, request.x, request.y, request.max_guesses, request.expiration)
            return (True, None)
        except Exception as e:
            return (None, "INTERNAL_ERROR: " + str(e))

    def recoverSecret(self, param):
        try:
            res =  openadp_server.recoverSecret(self.db, request.UID, request.DID,
                    request.BID, request.B, request.guess_num)
            if isinstance(res, BaseException):
                return (None, "INVALID_ARGUMENT: " + str(res))
            return (res, None)
        except Exception as e:
            return (None, "INTERNAL_ERROR: " + str(e))

    def listBackups(self, params):
        try:
            res =  openadp_server.listBackups(self.db, request.UID)
            if isinstance(res, BaseException):
                return (None, "INVALID_ARGUMENT: " + str(res))
            return (res, None)
        except Exception as e:
            return (None, "INTERNAL_ERROR: " + str(e))

port = 8080
server_address = ('', port)
httpd = HTTPServer(server_address, RPCRequestHandler)
print(f"Starting server on port {port}")
httpd.serve_forever()
