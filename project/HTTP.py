"""
Challenge HTTP server: An HTTP server to respond to the HTTP-01 challenge.

ShutDownHTTPServer: A HTTP server to receive a shutdown request from the ACME server


"""

from flask import Flask, request, Response

#Use flask as the HTTP server to respond to the HTTP-01 challenge

class HTTPChallengeServer:
    def __init__(self):
        self.challenge = {}
        self.app = Flask(__name__)
        self.register_routes()

    def register_routes(self):
        @self.app.route('/.well-known/acme-challenge/<token>')
        def serve_challenge(token):
            return self.get_challenge_response(token)

    def get_challenge_response(self, token):
        #print("Token in the http chal to check: ", token)
        #print("Test with token dic (all): ", self.challenge)
        if token in self.challenge:
            response = Response(self.challenge[token])
            response.headers["Content-Type"] = "application/octet-stream"
            #print(" This is the resonse in the http chal: ", response)
            return response
        else:
            raise Exception("Token not found")

    def add_auth(self, token, key_auth):
        #print("Added token:", token)
        #print("Added key_auth:", key_auth)
        self.challenge[token] = key_auth


    def start_server(self, port, host):
        self.app.run(port=port, host=host, threaded=True)



#Shutdown the server when the ACME server is done
class ShutdownHTTPServer:
    def __init__(self):
        self.app = Flask(__name__)

        @self.app.route('/shutdown', methods=['GET'])
        def shutdown():
            shutdown_func = request.environ.get('werkzeug.server.shutdown')
            if shutdown_func:
                shutdown_func()
                return 'Server shutting down...'
            return 'Shutdown function not available', 500

    def shutdown_server(self, port, host):
        self.app.run(port=port, host=host, threaded=True) #Shutting down the server.

