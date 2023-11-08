"""
Acme client implementation

./run dns01 --dir https://example.com/dir --record 127.0.0.1 --domain netsec.ethz.ch --domain syssec.ethz.ch
./run http01 --dir https://example.com/dir --record 127.0.0.1 --domain netsec.ethz.ch --domain syssec.ethz.ch


./run dns01 --dir https://example.com/dir --record localhost --domain netsec.ethz.ch --domain syssec.ethz.ch
./run http01 --dir https://example.com/dir --record localhost --domain netsec.ethz.ch --domain syssec.ethz.ch

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
    if isinstance(payload, str):
        payload = payload.encode('utf8')
    encoded = urlsafe_b64encode(payload)
    print("_This is encoded: ", encoded)
    decoded = encoded.decode('utf8').rstrip("=")
    return decoded

def H(data, encoding):
    # hash function using SHA256 encoding, used for the DNS challenge and more
    if isinstance(data, str):
        data = data.encode(encoding)
        print(data)
    Hash = SHA256.new(data) #Added string encode as it could be bytes. Used for the DNS challenge
    print(Hash)
    return Hash


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

1. Account resources: create_account (status 201)
2. Order resources: create_order, get_order, finalize_order (status 201)
3. Authorization resources: get_authorization (status 200)
4. Challenge resources: get_challenge, respond_challenge (status 200)
5. Certificate resources: download_certificate, revoke_certificate (status 200)
6. Key resources: get_key, update_key (status 200)
"""
class ACME_Client:
    def __init__(self,client):
        #Add things if they are useful
        self.client = client
        self.JOSE_Header = {"User-Agent": "ACME Client", "Content-Type": "application/jose+json"}
        self.Header = {"User-Agent": "ACME Client"}
        #self.jws = JWS()
        self.directory = {} #newAccount, newNonce, newOrder, newAuthz, revokeCert, keyChange
        self.kid = None # This will be returned in the response["location"] of the account creation after creating the account
        self.account_key = None


    def create_account(self, directory):
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
        self.directory = directory

        self.account_key = ECC.generate(curve='P-256') #Generate the key pair for the account, need to be FREEEEESSHHHH
        #x, y = account_key.pointQ.x, account_key.pointQ.y #ECC curve point x and y, used for debugging
        #print("x: ", x, "y: ", y)
        jwk = self.get_jwk(self.account_key) #JWK of the account key
        print("JWK: ", jwk)
        #print(jwk)

        #Create the JWS header, is this protected? I think it's protected
        protected = base64enc(json.dumps({ "alg": "ES256",
                        "jwk": jwk,
                        "nonce": self.get_nonce(), #Get the nonce from the server
                        "url": directory["newAccount"]}))

        print("This is protected: ", protected)
        #Send the data to the server, I still need to encrypt the data using the private key
        #And the JWS signature
        self.sign = DSS.new(self.account_key, 'fips-186-3') #Sign the data using the private key
        payload = base64enc(json.dumps({"termsOfServiceAgreed": True})) #Add the payload, ignore the contact to
        sig, ecdsa = self.sign_body(protected, payload, self.account_key)
        print("sig: ", sig)
        print("ecdsa:", ecdsa)
        #Get the full body
        body = json.dumps({"protected": protected, "payload": payload, "signature": sig})
        print("This is bodyy: ", body)
        response = requests.post(directory["newAccount"], json= body, headers=self.JOSE_Header) #Does this work? Should be JWS
        print(response)
        if response.status_code == 201:
            print("Account created")
            print("That's kid: ", response.headers["Location"])
            self.kid = response.headers["Location"] # assign kid for this matter
            return response.json(), response.headers["Location"]

        raise Exception("Account creation failed")

    def applyCert(self, domains): #7.4
        """
       POST /acme/new-order HTTP/1.1
       Host: example.com
       Content-Type: application/jose+json

       {
         "protected": base64url({
           "alg": "ES256",
           "kid": "https://example.com/acme/acct/evOfKhNU60wg",
           "nonce": "5XJ1L3lEkMG7tR6pA00clA",
           "url": "https://example.com/acme/new-order"
         }),
         "payload": base64url({
           "identifiers": [
             { "type": "dns", "value": "www.example.org" },
             { "type": "dns", "value": "example.org" }
           ],
           "notBefore": "2016-01-01T00:04:00+04:00",
           "notAfter": "2016-01-08T00:04:00+04:00"
         }),
         "signature": "H6ZXtGjTZyUnPeKn...wEA4TklBdh3e454g"
       }
        :return:
        """
        # Create the JWS header, is this protected? I think it's protected
        protected = base64enc(json.dumps({"alg": "ES256",
                                          "kid ": self.kid,
                                          "nonce": self.get_nonce(),  # Get the nonce from the server
                                          "url": self.directory["newAccount"]}))
        #Create payload
        identifiers = []
        for domain in domains: #We have multiple domains for this task
            identifiers.append({"type": "dns", "value": domain})

        payload = base64enc(json.dumps(
            {"identifiers": identifiers}))  # We want to have the url for the assign cert

        #Sign the body
        sig, ecdsa = self.sign_body(protected, payload, self.account_key)
        print("sig: ", sig)
        print("ecdsa:", ecdsa)
        # Get the full body
        body = json.dumps({"protected": protected, "payload": payload, "signature": sig})

        #Send the request

        response = requests.post(url=self.directory["newOrder"], json=body, headers=self.JOSE_Header)  # Does this work? Should be JWS

        if response.status_code == 201:
            print("Order created")
            print(response.headers["Location"])
            return response.json(), response.headers["Location"] #order and url

        raise Exception("Order creation failed")



    def download_cert(self, cert_url,key, key_path, cert_path): #7.4.2
        """

           POST /acme/cert/mAt3xBGaobw HTTP/1.1
           Host: example.com
           Content-Type: application/jose+json
           Accept: application/pem-certificate-chain

           {
             "protected": base64url({
               "alg": "ES256",
               "kid": "https://example.com/acme/acct/evOfKhNU60wg",
               "nonce": "uQpSjlRb4vQVCjVYAyyUWg",
               "url": "https://example.com/acme/cert/mAt3xBGaobw"
             }),
             "payload": "",
             "signature": "nuSDISbWG8mMgE7H...QyVUL68yzf3Zawps"
           }

        :return:
        """
        #Download cert
        if self.account_key is None:
            raise Exception("No account key, you may need to create a new account for that, or creating account has been failed")
        protected = base64enc(json.dumps({"alg": "ES256",
                                            "kid ": self.kid,
                                            "nonce": self.get_nonce(),  # Get the nonce from the server
                                            "url": cert_url}))

        payload = base64enc(json.dumps({"payload": ""}))  # It is nothing

        #Sign the body
        sig, ecdsa = self.sign_body(protected, payload, key = key)
        print("sig: ", sig)
        print("ecdsa:", ecdsa)
        # Get the full body
        body = json.dumps({"protected": protected, "payload": payload, "signature": sig}) #Body generated
        print("This is bodyy: ", body)

        #Send the request
        response = requests.post(url=cert_url, json=body, headers=self.JOSE_Header)

        if response.status_code == 200:
            #Write the certificate into the file
            cert = response.content #Get the certificate
            print(cert)
            #Write cert path into the file
            with open(cert_path, "wb") as f:
                f.write(cert)
            #Write key path into the file
            with open(key_path, "wb") as f:
                f.write(self.account_key.private_byte(
                    encodings = serialization.Encoding.PEM,
                    format = serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm = serialization.NoEncryption(),
                ))

            print("Certificate SUCCESSFULLY downloaded")
            return cert

        raise Exception("Certificate download failed")



    def pre_authorization(self, domains): #Pre-authorization,
        """
           POST /acme/authz/PAniVnsZcis HTTP/1.1
           Host: example.com
           Content-Type: application/jose+json

         {
             "protected": base64url({
             "alg": "ES256",
             "kid": "https://example.com/acme/acct/evOfKhNU60wg",
                "nonce": "uQpSjlRb4vQVCjVYAyyUWg",
             "url": "https://example.com/acme/authz/PAniVnsZcis"
            }),
            "payload": "",
            "signature": "nuSDISbWG8mMgE7H...QyVUL68yzf3Zawps"
         }
        :return:
        """
        protected = base64enc(json.dumps({"alg": "ES256",
                                          "kid ": self.kid,
                                          "nonce": self.get_nonce(),  # Get the nonce from the server
                                          "url": self.directory["newOrder"]}))
        payload = base64enc(json.dumps({"payload": ""}))  # It is nothing


        #Sign the body
        sig, ecdsa = self.sign_body(protected, payload, key = self.account_key)
        print("sig: ", sig)
        print("ecdsa:", ecdsa)
        # Get the full body
        body = json.dumps({"protected": protected, "payload": payload, "signature": sig})
        response = requests.post(url=self.directory["newOrder"], json=body, headers=self.JOSE_Header)  # Does this work? Should be JWS

        if response.status_code == 200:
            print("Order created")
            print(response.headers["Location"])
            return response.json(), response.headers["Location"]

        raise Exception("Order creation failed")



    def authorization(self):

        #TODO: Get the authorization

        #Generate key authorization
        key_autho = self.get_jwk(self.account_key)



        pass



    def revokeCert(self, cert): #7.5
        """
       POST /acme/revoke-cert HTTP/1.1
       Host: example.com
       Content-Type: application/jose+json

       {
         "protected": base64url({
           "alg": "ES256",
           "kid": "https://example.com/acme/acct/evOfKhNU60wg",
           "nonce": "JHb54aT_KTXBWQOzGYkt9A",
           "url": "https://example.com/acme/revoke-cert"
         }),
         "payload": base64url({
           "certificate": "MIIEDTCCAvegAwIBAgIRAP8...",
           "reason": 4
         }),
         "signature": "Q1bURgJoEslbD1c5...3pYdSMLio57mQNN4"
       }

        Don't think we use cert's key pair.....
        :return:
        """
        pass


    def keyChange(self):
        """
           POST /acme/key-change HTTP/1.1
           Host: example.com
           Content-Type: application/jose+json

           {
             "protected": base64url({
               "alg": "ES256",
               "kid": "https://example.com/acme/acct/evOfKhNU60wg",
               "nonce": "S9XaOcxP5McpnTcWPIhYuB",
               "url": "https://example.com/acme/key-change"
             }),
             "payload": base64url({
               "protected": base64url({
                 "alg": "ES256",
                 "jwk": /* new key */,
                 "url": "https://example.com/acme/key-change"
               }),
               "payload": base64url({
                 "account": "https://example.com/acme/acct/evOfKhNU60wg",
                 "oldKey": /* old key */
               }),
               "signature": "Xe8B94RD30Azj2ea...8BmZIRtcSKPSd8gU"
             }),
             "signature": "5TWiqIYQfIDfALQv...x9C2mg8JGPxl5bI4"
           }


        :return:
        """
        pass




    #--------------------------Helper functions--------------------------
    def get_nonce(self):
        """
        Get the nonce from the server
        :return:
        """
        response = self.get_url_(self.directory["newNonce"])
        print(response.headers)
        nonce = response.headers["Replay-Nonce"]
        print(nonce)
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

    def get_url_(self, url):
        url_ = self.client.get(url, headers=self.Header)
        if url_.status_code == 200:
            try:
                self.directory = url_.json()
                return url_.json()
            except json.decoder.JSONDecodeError:
                raise Exception("Received non-JSON response")
        elif url_.status_code == 204:
            print(url_)
            self.directory = url_
            return url_  #Empty response
        else:
            raise Exception(f"Error getting URL, status code: {url_.status_code}")



    def sign_body(self, header, payload, key):
        """
        Sign the body of the request
        :param body:
        :return:
        """
        if key is None:
            raise Exception("No account key, you may need to create a new account for that...will never happen I think")
        ecdsa = DSS.new(key, 'fips-186-3') #Sign the data using the private key
        message = f"{header}.{payload}"
        hashed_message = H(message, encoding='ascii')
        sign_message = ecdsa.sign(hashed_message)
        return base64enc(sign_message), ecdsa #Sign.sign, hate it, bugs are here

    def https_challenge(self, challenge, key_authorization,http_server):#8.3
        """
        type (required, string):  The string "http-01".

           token (required, string):  A random value that uniquely identifies
              the challenge.  This value MUST have at least 128 bits of entropy.
              It MUST NOT contain any characters outside the base64url alphabet
              and MUST NOT include base64 padding characters ("=").  See
              [RFC4086] for additional information on randomness requirements.

           {
             "type": "http-01",
             "url": "https://example.com/acme/chall/prV_B7yEyA4",
             "status": "pending",
             "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
           }


        :return:
        """
        #Implement the https challenge
        key_auth = f"{challenge['token']}.{key_authorization}"
        http_server.add_auth(challenge["token"], key_auth)
        return challenge["url"], key_auth



    def dns_challenge(self, challenge, key_authorization, dns_server): #8.4
        """  type (required, string):  The string "dns-01".

           token (required, string):  A random value that uniquely identifies
              the challenge.  This value MUST have at least 128 bits of entropy.
              It MUST NOT contain any characters outside the base64url alphabet,
              including padding characters ("=").  See [RFC4086] for additional
              information on randomness requirements.

           {
             "type": "dns-01",
             "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
             "status": "pending",
             "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
           }
        """
        # Implement the dns challenge response
        key_auth = f"{challenge['token']}.{key_authorization}"
        message = H(data = key_auth, encoding='ascii').digest()
        key_auth = base64enc(message)
        dns_server.resolve_update(f"__acme.{challenge['identifier']['value']}", key_auth, "TXT")
        print("key auth: ", key_auth)
        return challenge["url"], key_auth












#Run the dns server
def run_dns_server(server, args):
    for domain in args.domain:
        server.resolve_update(domain, args.dir, args.record)
    server.start_server() #This doesn't work.


#Stop the dns server
def stop_dns_server(server):
    server.shutdown()












def main():
    #Parse the arguments, use the comments from the header to test
    parse = argparse.ArgumentParser(description='ACME client')
    parse.add_argument('challenge', help='The challenge type you want to use', choices=['dns01', 'http01'])
    parse.add_argument('-u', '--dir', help='The directory you want to get certified', required=True)
    parse.add_argument('-c', '--record', help='Only challenge type', required=True)
    parse.add_argument('-d', '--domain', help='The domain you want to access.', action='append', required=True)
    parse.add_argument('-r', '--revoke',help='certificate revokation, for dns and https', required=False)
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
    #server_response = server.get(args.dir, verify = 'pebble.minica.pem')
    #print(server_response.json())

    acme = ACME_Client(server)
    #Create account

    directory = acme.get_url_(args.dir)
    if not directory:
        print("Error getting directory")
        return
    print("this is the directory", directory)
    account = acme.create_account(directory)
    print("Account is this: ", account)
    if not account:
        print("Account creation failed")
        return
    print("SUCCESS WITH ACCOUNT CREATION")


    #Apply certificate issuance
    cert_order, cert_url = acme.applyCert(args.domain)
    print(cert_order)
    if not cert_order:
        print("Certificate order failed")
        return
    print("SUCCESS WITH CERTIFICATE ORDER")




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

