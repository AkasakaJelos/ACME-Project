"""
Acme client implementation

./run dns01 --dir https://example.com/dir --record localhost --domain netsec.ethz.ch --domain syssec.ethz.ch


Easy copy:
1. JWA: https://datatracker.ietf.org/doc/html/rfc7518
2. JWS: https://datatracker.ietf.org/doc/html/rfc7515
3. ACME: https://datatracker.ietf.org/doc/html/rfc8555


"""

from cryptography.hazmat.primitives import serialization
from threading import Thread
import argparse

import base64
from base64 import urlsafe_b64encode
import json


import Crypto
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

import ssl
import requests
import socket
#Private libs
from DNS import DNS_Server
from HTTP import HTTPChallengeServer, ShutdownHTTPServer
from JWS import JWS

#Used to generate the public private key pair to prove the client is controlling it





#One should use urlsafe base64 encoding from FAQ
def base64enc(payload):
    return urlsafe_b64encode(payload if isinstance(payload,bytes) else payload).decode('utf8').rstrip("=")



"""

The following class only contains the necessary operations to send to the ACME server. 
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
                     
The sequence will be ordered as following according to RFC8555: 

1. Account resources: create_account
2. Order resources: create_order, get_order, finalize_order
3. Authorization resources: get_authorization
4. Challenge resources: get_challenge, respond_challenge
5. Certificate resources: download_certificate, revoke_certificate
6. Key resources: get_key, update_key
"""
class ACME_Client:
    def __init__(self,client):
        #Add things if they are useful
        self.client = client
        self.Header_JWS = {"User-Agent": "ACME Client", "Content-Type": "application/jose+json"}
        self.Header = {"User-Agent": "ACME Client"}
        self.Host = "example.com"
        self.Port = "5002"
        self.jws = JWS()
        self.directory = {} #newAccount, newNonce, newOrder, newAuthz, revokeCert, keyChange


    def create_account(self):
        """
        Account resource(1):

        ACME (RFC8555) create account:

       POST /acme/new-account HTTP/1.1
       Host: example.com
       Content-Type: application/jose+json

       {
         "protected": base64url({
           "alg": "ES256",
           "jwk": {...},
           "nonce": "6S8IqOGY7eL2lsGoTZYifg",
           "url": "https://example.com/acme/new-account"
         }),
         "payload": base64url({
           "termsOfServiceAgreed": true,
           "contact": [
             "mailto:cert-admin@example.org",
             "mailto:admin@example.org"
           ]
         }),
         "signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"
       }

       JWK specification (RFC7638):
        o  "crv"
        o  "kty"
        o  "x"
        o  "y"

        :return:
        #Create the important aspects of the account you have to send. When do we need to generate new private-public key pair?
        Key should be fresh in every run, so we will have to create new sign algo and account key each time we launch something...
        """

        account_key = ECC.generate(curve='P-256') #Generate the key pair for the account, need to be FREEEEESSHHHH
        #x, y = account_key.pointQ.x, account_key.pointQ.y #ECC curve point x and y, used for debugging
        #print("x: ", x, "y: ", y)
        jwk = self.get_jwk(account_key) #JWK of the account key
        #print(jwk)

        #Create the JWS header, is this protected? I think it's protected
        protected = base64enc(json.dumps({ "alg": "ES256",
                        "jwk": jwk,
                        "nonce": "nonce",
                        "url": self.directory["newAccount"]}))
        #Send the data to the server, I still need to encrypt the data using the private key
        #And the JWS signature
        self.sign = DSS.new(account_key, 'fips-186-3') #Sign the data using the private key
        payload = base64enc(json.dumps({"termsOfServiceAgreed": True})) #Add the payload, ignore the contact to
        sig, ecdsa = self.sign_body(protected, payload)
        print("sig: ", sig)
        print("ecdsa:", ecdsa)
        #Get the full body
        body = json.dumps({"protected": protected, "payload": payload, "signature": sig})
        response = requests.post(url = self.directory["newAccount"], json= body, headers=self.Header_JWS) #Does this work? Should be JWS
        if response.status_code == 201:
            print("Account created")
            print(response.headers["Location"])
            return response.json(), response.headers["Location"]

        raise Exception("Account creation failed")

    def applyCert(self): #7.4
        # TODO: Place new order for the certificate
        pass

    def pre_authorization(self): #Pre-authorization,
        #TODO: Get the authorization
        pass

    def download_cert(self): #7.4.2
        #TODO: Get the challenge
        pass

    def revokeCert(self): #7.5
        # TODO:Revoke the certificate
        pass

    def keyChange(self):
        # TODO: Cahnge the key of the account
        pass


    #---------------------Helper functions---------------------
    def get_nonce(self):
        """
        Get the nonce from the server
        :return:
        """
        response = self.client.head("http://" + self.Host+ ":" + self.PORT +"/acme/new-nonce")
        nonce = response.headers["Replay-Nonce"]
        return nonce


    def get_jwk(self, key):
        """
        Get the jwk from the key
        :param key:
        :return:
        """
        jwk = {
            "crv": "P-256",
            "kty": "EC",
            "x": base64enc(key.pointQ.x.to_bytes()),
            "y": base64enc(key.pointQ.y.to_bytes()),
        }
        return jwk
    def get_url_(self,url):
        url_ = self.client.get(url, headers=self.Header)
        if url_.status_code == 200:
            return url_.json()
        else:
            raise Exception("Error getting url")

    def sign_body(self, header, payload, key):
        """
        Sign the body of the request
        :param body:
        :return:
        """
        if key is None:
            raise Exception("No account key, you may need to create a new account for that...will never happen I think")
        ecdsa = DSS.new(key, 'fips-186-3') #Sign the data using the private key
        return base64enc(ecdsa.sign(JWS.H("{}.{}".format(header,payload), "ascii"))), ecdsa #Sign.sign, love it












#Run the dns server
def run_dns_server(server, args):
    for domain in args.domain:
        server.resolve_update(domain, args.dir, args.record)
    server.start_server() #This doesn't work.


#Stop the dns server
def stop_dns_server(server):
    server.shutdown_server()












def main():
    #Parse the arguments, use the comments from the header to test
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


    IPAddr = "127.0.0.1" #Default IP address


    if args.challenge=="dns01":
        IPAddr = args.record
    elif args.challenge=="http01":
        IPAddr = args.record

    #---------------------Start the DNS server---------------------
    print("DNS server starting........")
    server = DNS_Server(args.record, DNS_SERVER_PORT)
    run_dns_server(server, args)
    print("DNS server started")

    #---------------------Start the challenge server---------------------
    print("Challenge server starting........")
    arguments = (CHALLENGE_SERVER_PORT, IPAddr)
    challenge_server = HTTPChallengeServer()
    #Use server thread instead of server, FAQ
    server_thread = Thread(target=challenge_server.start_server, args = arguments)
    server_thread.start()
    print("Challenge server started")

    #---------------------Start the acme server---------------------
    server = requests.Session()
    server.verify = 'pebble.minica.pem'
    acme = ACME_Client(server)
    #Create account

    acme.directory = acme.get_url_(args.dir)
    if not acme.directory:
        print("Error getting directory")
        return
    print(acme.directory)
    account = acme.create_account()
    print(account)
    if not account.ok:
        print("Account creation failed")
        return
    print("SUCCESS WITH ACCOUNT CREATION")


    #TODO: Apply certificate issuance
    #TODO: Identifier authorization
    #TODO: Download Certificate
    #TODO: Revoke Certificate


    #---------------------Start the certificate server---------------------
    #TODO: Stop the server

    #TODO: Start the certificate server
    print("Certificate server starting........")


    #certificate_path = "project/pebble.minica.pem"
    #certificate_server = Certificate_HTTPS(IPAddr, CERTIFICATE_PORT)


    # ---------------------shutdown the DNS server---------------------
    print("DNS server shutting down........")
    stop_dns_server(server)
    print("DNS server shut down")


    #-------------- shutdown the challenge server, why tf 21P?---------------------

    print("Challenge server shutting down........")
    shutdown_server = ShutdownHTTPServer()
    shutdown_server.shutdown_server(CHALLENGE_SERVER_SHUTDOWN_PORT, IPAddr)
    print("Challenge server shut down")










if __name__ == "__main__":
    main()

