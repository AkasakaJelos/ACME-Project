"""
The Certificate HTTPS server uses a certificate obtained by the ACME client


"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from flask import Flask, requests

class Certificate_HTTPS:
    def __init__(self):
        self.server = Flask(__name__)
        self.cert_server()


    def cert_server(self):
        @self.server.route("/")
        def shutdown():
            print ("HTTPS server is running")


    def startHTTPServer(self, host, port, key, cert):
        self.server.run(host = host, port = port, key = key, cert = cert)
    def GenerateCSRForServer(self):
        #Generate the key for the server
        self.key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Generate a CSR
        self.csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"), #Country
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"), #State
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"), #Locality
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NetSecProject"), #Organization
            x509.NameAttribute(NameOID.COMMON_NAME, u"newtwitter.ch"), #Common name
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName(u"newtwitter.ch"), #DNS name
            ]),
            critical=False,
            # Sign the CSR with the private key.
        ).sign(self.key, hashes.SHA256())
        return self.key, self.csr



class ShutdownHTTPSServer:
    def __init__(self):
        self.app = Flask(__name__)
        self.register_routes()

    def register_routes(self):
        @self.app.route('/shutdown', methods=['POST'])
        def shutdown():
            shutdown_func = requests.environ.get('werkzeug.server.shutdown')
            if shutdown_func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            self.shutdown_server()
            return 'Server shutting down...'

    def shutdown_server(self, port, host, cert, key):
        self.app.run(port=port, host=host, ssl_ = (cert, key), threaded=True) #Shutting down the server.

