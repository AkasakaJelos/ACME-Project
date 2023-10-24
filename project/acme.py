"""
Acme client implementation

./run dns01 --dir https://example.com/dir --record 1.2.3.4 --domain netsec.ethz.ch --domain syssec.ethz.ch

"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import argparse
import http.server as http_server
import base64
import json

import ssl
from flask import Flask
import requests
import socket
#Private libs
from DNS import DNS_Server

#Used to generate the public private key pair to prove the client is controlling it


#JWS sign and verify for the message of the ACME protocol


def enc(header, payload):
    pass
class JWK:
    def __init__(self, key):
        self.key = key

    def sign(self, message):
        #Sign the message with the private key
        pass

    def verify(self, signature, message):
        #Verify the message with the public key
        pass




class Certificate_HTTPS:
    def __init__(self, ip, port):
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
    def __init__(self,account_key):
        self.account_key = account_key



    def AccountCreation(self):
        #Create a new account and return account
        Host = "localhost"
        alg = "ES256"
        public_key_info = self.account_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        #Create the JWS header
        head = {'Host': 'localhost', 'Content-Type': 'application/jose+json'}
        protected = enc(head, { "alg": alg,
                                    "jwk": public_key_info.public_key(),
                                    "nonce": "nonce",
                                    "url": "http://"+Host+"/acme/new-account"})
        header_json = json.dumps(protected)
        response = requests.post("http://"+Host+"/acme/new-account", data=header_json)

        return response

    def newOrder(self):
        pass

    def revokeCert(self):
        pass

    def keyChange(self):
        pass



def run_dns_server(server, args):
    for domain in args.domain:
        server.resolve_update(domain, args.dir, args.record)
    server.start_server()

def stop_dns_server(server):
    server.shutdown_server()



def main():
    parse = argparse.ArgumentParser(description='ACME client')
    parse.add_argument('challenge', help='The challenge type you want to use', choices=['dns01', 'http01'])
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
    print("DNS server starting........")
    server = DNS_Server(args.record, DNS_SERVER_PORT)
    run_dns_server(server, args)
    print("DNS server started")

    # shutdown the DNS server

    print("DNS server shutting down........")
    stop_dns_server(server)
    print("DNS server shut down")








if __name__ == "__main__":
    main()

