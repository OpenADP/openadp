# This seems to work as a client call:
#
#     $ curl -H "Content-Type: application/json" -d \
#       '{"jsonrpc":"2.0","method":"Echo","params":["Hello, World!"],"id":1}' \
#       https://xyzzybill.openadp.org
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
       self.db = database.Database("openadp.db")
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
            elif method == 'Echo':
                if len(params) == 1:
                    (result, error) = (params[0], None)
                else:
                    (None, "Echo expects exactly 1 parameter")
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
            if len(params) != 8:
                return (None, "INVALID_ARGUMENT: RegisterSecret expects exactly 8 parameters")
            uid, did, bid, version, x, y, max_guesses, expiration = params
            server.registerSecret(self.db, uid, did, bid, version, x, y, max_guesses, expiration)
            return (True, None)
        except Exception as e:
            return (None, "INTERNAL_ERROR: " + str(e))

    def recoverSecret(self, params):
        try:
            if len(params) != 5:
                return (None, "INVALID_ARGUMENT: RecoverSecret expects exactly 5 parameters")
            uid, did, bid, b, guess_num = params
            res = server.recoverSecret(self.db, uid, did, bid, b, guess_num)
            if isinstance(res, BaseException):
                return (None, "INVALID_ARGUMENT: " + str(res))
            return (res, None)
        except Exception as e:
            return (None, "INTERNAL_ERROR: " + str(e))

    def listBackups(self, params):
        try:
            if len(params) != 1:
                return (None, "INVALID_ARGUMENT: ListBackups expects exactly 1 parameter")
            uid = params[0]
            res = server.listBackups(self.db, uid)
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
