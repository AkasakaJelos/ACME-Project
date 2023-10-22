"""
Acme client implementation



"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import argparse
import http.server as http_server
import dnslib
from dnslib.server import DNSServer
import ssl
from flask import Flask
import socket

#Used to generate the public private key pair to prove the client is controlling it




class Certificate_HTTPS:
    def __init__(self,ip, port):
        self.IP = ip
        self.port = port


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

    def stopHTTPServer(self):
        #Stops the HTTP server
        pass






class DNS_Server:
    """
    Setup my own dns server

    """
    def __init__(self, request, handler, record):
        self.request = request
        self.handler = handler
        self.record = record

    def dns_resolve(self):
        reply = self.request.reply()
        qType = self.request.q
        q_name = self.request.q.qname

        print("qType: ", qType)
        print("q_name: ", q_name)
        print("q: ", self.request.q)
        print("qname: ", self.request.q.qname)

        if qType == dnslib.QTYPE.A:
            reply.add_answer(dnslib.RR(q_name, dnslib.QTYPE.A, rdata=dnslib.A("localhost"), ttl=60))

        elif qType == dnslib.QTYPE.TXT:
            reply.add_answer(dnslib.RR(q_name, dnslib.QTYPE.TXT, rdata=dnslib.TXT("Hello World"), ttl=60))
        else:
            reply.add_answer(dnslib.RR(q_name, dnslib.QTYPE.CNAME, rdata=dnslib.CNAME("localhost"), ttl=60))
        return reply




"""
Main implementation of the ACME client
-------------------------------------------
                                  directory
                                      |
                                      +--> newNonce
                                      |
          +----------+----------+-----+-----+------------+
          |          |          |           |            |
          |          |          |           |            |
          V          V          V           V            V
     newAccount   newAuthz   newOrder   revokeCert   keyChange
          |          |          |
          |          |          |
          V          |          V
       account       |        order --+--> finalize
                     |          |     |
                     |          |     +--> cert
                     |          V
                     +---> authorization
                               | ^
                               | | "up"
                               V |
                             challenge

                     ACME Resources and Relationships
"""
class ACME_Client:
    def __init__(self):
        pass

    def AccountCreation(self):
        #Create a new account and return account
        pass

    def newOrder(self):
        pass

    def revokeCert(self):
        pass

    def keyChange(self):
        pass



def keyAuthorization(token, accountkey):
    return token + "." + accountkey



def main():
    parse = argparse.ArgumentParser(description='ACME client')
    parse.add_argument('-u', '--dir', help='The directory you want to get certified', required=True)
    parse.add_argument('-c', '--record', help='Only challenge type', required=True)
    parse.add_argument('-d', '--domain', help='The domain you want to access.', action='append', required=True)
    parse.add_argument('-r', '--certificate',help='certificate', required=False)
    args = parse.parse_args()

    DNS_SERVER_PORT = 10053 #UDP port 10053
    CHALLENGE_SERVER_PORT = 5002 #TCP port 5002
    CHALLENGE_SERVER_SHUTDOWN_PORT = 5003 #TCP port 5003
    CERTIFICATE_PORT = 5001 #TCP port 5001

    #Start the DNS server
    resolver = dnslib.server.DNSResolver()
    server = DNSServer(resolver,port=DNS_SERVER_PORT,address = "localhost",logger = dnslib.DNSLogger(prefix = False), tcp=False)
    server.start_thread()
    assert server.is_running
    print("DNS server started")

    #Start the HTTP server
    app = Flask(__name__)
    @app.route('/.well-known/acme-challenge/<token>', methods=['GET'])
    def challenge(token):
        return token
    app.run(host='localhost', port=CHALLENGE_SERVER_PORT, debug=True)
    print("HTTP server started")

    #Start the HTTPS server
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    #Generate the key and the certificate
    key, csr = Certificate_HTTPS().GenerateCSRForServer()
    context.load_cert_chain(csr, key)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    #Start the HTTPS server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('localhost',CERTIFICATE_PORT))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(1024)
                    if not data: break
                    conn.sendall(data)






if __name__ == "__main__":
    main()

