"""
The Certificate HTTPS server uses a certificate obtained by the ACME client


"""

from flask import Flask, request

class Certificate_HTTPS:
    def __init__(self):
        self.server = Flask(__name__)
        self.cert_server()


    def cert_server(self):
        @self.server.route("/")
        def run():
            print("HTTPS server is running")


    def run_server(self, port, host, cert, key):
        ssl_context = (cert, key)
        self.server.run(port=port, host=host, ssl_context=ssl_context, threaded=True)



class ShutdownHTTPSServer:
    def __init__(self):
        self.app = Flask(__name__)
        self.register_routes()

    def register_routes(self):
        @self.app.route('/shutdown', methods=['POST'])
        def shutdown():
            shutdown_func = request.environ.get('werkzeug.server.shutdown')
            if shutdown_func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            shutdown_func()
            return 'Server shutting down...'

    def run_server(self, port, host, cert, key):
        ssl_context = (cert, key)
        self.app.run(port=port, host=host, ssl_context=ssl_context, threaded=True)

