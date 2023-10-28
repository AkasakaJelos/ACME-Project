"""
Challenge HTTP server: An HTTP server to respond to the HTTP-01 challenge.

ShutDownHTTPServer: A HTTP server to receive a shutdown request from the ACME server


"""

from flask import Flask, Response, request

#Use flask as the HTTP server to respond to the HTTP-01 challenge

class HTTPChallengeServer:
    def __init__(self):
        self.challenge = {}
        self.app = Flask(__name__)
        self.register_routes()

    def register_routes(self):
        @self.app.route('/.well-known/acme-challenge/<token>', methods=['GET'])
        def serve_challenge(token):
            return self.get_challenge_response(token)

    def get_challenge_response(self, token):
        if token in self.challenge:
            response = Response(self.challenge[token])
            response.headers['Content-Type'] = 'application/octet-stream'
            return response
        return "Token not found"

    def start_server(self, port, host):
        self.app.run(port=port, host=host, threaded=True)



#Shutdown the server when the ACME server is done
class ShutdownHTTPServer:
    def __init__(self):
        self.app = Flask(__name__)
        self.register_routes()

    def register_routes(self):
        @self.app.route('/shutdown', methods=['POST'])
        def shutdown():
            self.shutdown_server()
            return 'Server shutting down...'

    def shutdown_server(self, port, host):
        self.app.run(port=port, host=host, threaded=True) #Shutting down the server.

