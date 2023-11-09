"""
Acme client implementation

./run dns01 --dir https://0.0.0.0:14000/dir --record localhost --domain netsec.ethz.ch --domain syssec.ethz.ch
./run http01 --dir https://0.0.0.0:14000/dir --record 127.0.0.1 --domain netsec.ethz.ch --domain syssec.ethz.ch --revoke


./run dns01 --dir https://0.0.0.0:14000/dir --record localhost --domain netsec.ethz.ch
./run http01 --dir https://0.0.0.0:14000/dir --record localhost --domain netsec.ethz.ch --domain syssec.ethz.ch

Easy copy:
1. JWA: https://datatracker.ietf.org/doc/html/rfc7518
2. JWS: https://datatracker.ietf.org/doc/html/rfc7515
3. ACME: https://datatracker.ietf.org/doc/html/rfc8555

"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import warnings


from cryptography.hazmat.primitives import serialization
from threading import Thread
import argparse
import time

import base64
from base64 import urlsafe_b64encode
import json


import Crypto
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

import requests
#Private libs
from DNS import DNS_Server
from HTTP import HTTPChallengeServer, ShutdownHTTPServer
from HTTPS import Certificate_HTTPS, ShutdownHTTPSServer
from JWS import JWS

#Used to generate the public private key pair to prove the client is controlling it




def base64enc_fin(payload):
    if isinstance(payload, str):
        payload = payload.encode('utf8')
    encoded = urlsafe_b64encode(payload)
    #print("_This is encoded: ", encoded)
    decoded = encoded.decode('utf8')
    return decoded
#One should use urlsafe base64 encoding from FAQ
def base64enc(payload):
    if isinstance(payload, str):
        payload = payload.encode('utf8')
    encoded = urlsafe_b64encode(payload)
    #print("_This is encoded: ", encoded)
    decoded = encoded.decode('utf8').rstrip("=")
    return decoded

def H(data, encoding):
    # hash function using SHA256 encoding, used for the DNS challenge and more
    if isinstance(data, str):
        data = data.encode(encoding)
        #print(data)
    Hash = SHA256.new(data) #Added string encode as it could be bytes. Used for the DNS challenge
    #print(Hash)
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
    def __init__(self,client, cert):
        #Add things if they are useful
        self.client = client
        self.JOSE_Header = {"User-Agent": "ACME Client", "Content-Type": "application/jose+json"}
        self.Header = {"User-Agent": "ACME Client"}
        #self.jws = JWS()
        self.directory = {} #newAccount, newNonce, newOrder, newAuthz, revokeCert, keyChange
        self.kid = None # This will be returned in the response["location"] of the account creation after creating the account
        self.account_key = None
        self.cert = cert
        self.status_of_order = ["pending", "ready", "processing", "valid", "invalid"]


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
        #print("JWK: ", jwk)
        #print(jwk)

        #Create the JWS header, is this protected? I think it's protected
        protected = base64enc(json.dumps({ "alg": "ES256",
                        "jwk": jwk,
                        "nonce": self.get_nonce(), #Get the nonce from the server
                        "url": directory["newAccount"]}))

        #print("This is protected: ", protected)
        #Send the data to the server, I still need to encrypt the data using the private key
        #And the JWS signature
        self.sign = DSS.new(self.account_key, 'fips-186-3') #Sign the data using the private key
        payload = base64enc(json.dumps({"termsOfServiceAgreed": True})) #Add the payload, ignore the contact to
        sig, ecdsa = self.sign_body(protected, payload)
        #print("sig: ", sig)
        #print("ecdsa:", ecdsa)
        #Get the full body
        body = json.dumps({"protected": protected, "payload": payload, "signature": sig})
        #print("This is bodyy: ", body)
        response = requests.post(directory["newAccount"], data = body, headers=self.JOSE_Header, verify=self.cert) #Does this work? Should be JWS
        #print(response.json())
        if response.status_code == 201:
            #print("Account created")
            #print("That's kid: ", response.headers["Location"])
            self.kid = response.headers["Location"]
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
        if not self.kid:
             raise Exception("No kid, thus no account created. Please create an account first"  )
        # Create the JWS header, is this protected? I think it's protected
        if not self.directory:
            raise Exception("Directory empty, please get the directory first")

        #Create payload
        identifiers = []
        for domain in domains: #We have multiple domains for this task
            identifiers.append({"type": "dns", "value": domain})

        _payload = {"identifiers": identifiers}  # We want to have the url for the assign cert
        protected,payload,sig = self.get_body(self.directory["newOrder"], _payload )

        #print("sig: ", sig)
        #print("ecdsa:", ecdsa)
        # Get the full body
        body = json.dumps({"protected": protected, "payload": payload, "signature": sig})

        #print("Thsi is the body from newOrder: ", body)

        #Send the request

        response = requests.post(url=self.directory["newOrder"], data=body, headers=self.JOSE_Header, verify=self.cert )  # Does this work? Should be JWS
        #print("Response from order", response.json())
        if response.status_code == 201:
            #print("Order created")
            #print(response.headers["Location"])
            return response.json(), response.headers["Location"] #order and url

        raise Exception("Order creation failed")



    def download_cert(self, cert_url, key, key_path, cert_path): #7.4.2
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
                                            "kid": self.kid,
                                            "nonce": self.get_nonce(),  # Get the nonce from the server
                                            "url": cert_url}))

        payload = ""  # It is nothing

        #Sign the body
        sig, ecdsa = self.sign_body(protected, payload)
        #print("sig: ", sig)
        #print("ecdsa:", ecdsa)
        # Get the full body
        body = json.dumps({"protected": protected, "payload": payload, "signature": sig}) #Body generated
        print("This is bodyy: ", body)

        #Send the request
        response = requests.post(url=cert_url, data=body, headers=self.JOSE_Header, verify=self.cert)
        print("This is the response after applying cert: ", response.json())
        if response.status_code == 200:
            #Write the certificate into the file


            cert_cert_url = response.json()["certificate"] #Get the cert url

            protected, payload, sig = self.get_body(cert_cert_url, "")
            body = json.dumps({"protected": protected,
                                 "payload": "",
                                 "signature": sig})
            response = self.client.post(url=cert_cert_url, data=body, headers=self.JOSE_Header, verify=self.cert)
            print("THis is downloading: ", response)
            if response.status_code == 200:
                #Write cert path into the file
                cert = response.content  # Get the certificate
                print("That's cert brroooo:", cert)
                with open(cert_path, "wb") as f:
                    f.write(cert)
                #Write key path into the file
                with open(key_path, "wb") as f:
                    f.write(key.private_bytes(
                        encoding = serialization.Encoding.PEM,
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
                                          "kid": self.kid,
                                          "nonce": self.get_nonce(),  # Get the nonce from the server
                                          "url": self.directory["newOrder"]}))
        payload =""  # It is nothing


        #Sign the body
        sig, ecdsa = self.sign_body(protected, payload)
        #print("sig: ", sig)
        #print("ecdsa:", ecdsa)
        # Get the full body
        body = json.dumps({"protected": protected, "payload": payload, "signature": sig})
        response = requests.post(url=self.directory["newOrder"], json=body, headers=self.JOSE_Header, verify = self.cert)  # Does this work? Should be JWS
        #print("This is the response after applying cert: ", response.json())
        if response.status_code == 200:
            #print("Order created")
            #print(response.headers["Location"]) #
            return response.json(), response.headers["Location"]

        raise Exception("Order creation failed")



    def authorization_and_challenge_response(self, urls, key_authorization, chal,  http_server, dns_server): #7.5
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

        """

        #Generate key authorization

        validation_urls = []
        for url in urls:
            protected,payload, sig = self.get_body(url, "")
            body =json.dumps({"protected":protected,
                                 "payload": "",
                                 "signature": sig})
            print("This is body from url:::", body)
            response = self.client.post(url=url, data=body, headers=self.JOSE_Header, verify = self.cert)
            print("response for json_ challenge collecting phase: ", response.json())
            if response.status_code == 200:
                #print("Collect Challenge")
                challenges = response.json()["challenges"]
                for cha in challenges:
                    if cha["type"] == "http-01" and chal == "http01":
                        print("Adding http challenge: ", cha)
                        validation_urls.append(self.http_challenge(cha, key_authorization, http_server))
                    elif cha["type"] == "dns-01" and chal == "dns01":
                        print("Adding dns challenge: ", cha)
                        validation_urls.append(self.dns_challenge(response, cha, key_authorization, dns_server))

            else:
                raise Exception("Authorization failed")
            if not validation_urls:
                raise Exception("No validation urls")
        print("FINISHED COLLECTING CHALLENGES")
        #print("VALIDATION URLS: ", validation_urls)
        url_collection= [] #Used to poll the status
        for url in validation_urls:
            #Need to respond to the challenges
            print("Processing on: ", url)
            url_collection.append(url)
            protected = base64enc(json.dumps({"alg": "ES256",
                                                "kid": self.kid,
                                                "nonce": self.get_nonce(),  # Get the nonce from the server
                                                "url": url}))
            payload = base64enc("{}")
            #Sign the body
            sig, _ = self.sign_body(protected, payload)
            #print("sig: ", sig)
            #print("ecdsa:", ecdsa)
            # Get the full body
            body = json.dumps({"protected": protected, "payload": payload, "signature": sig})
            response = self.client.post(url=url, data=body, headers=self.JOSE_Header, verify = self.cert)  # Does this work? Should be JWS
            print(response.json())
            if response.status_code == 200:
                print("Challenge success, next one")
            else:
                raise Exception("Challenge failed")

        print("Challenge success!!! All done!!!")
        #Poll the resources until the status is valid
        return True




    def finalize_order(self, order_url, finalize_url, der):
        """
             POST /acme/order/TOlocE8rfgo/finalize HTTP/1.1
            Host: example.com
            Content-Type: application/jose+json

            {
              "protected": base64url({
                "alg": "ES256",
                "kid": "https://example.com/acme/acct/evOfKhNU60wg",
                "nonce": "MSF2j2nawWHPxxkE3ZJtKQ",
                "url": "https://example.com/acme/order/TOlocE8rfgo/finalize"
              }),
              "payload": base64url({
                "csr": "MIIBPTCBxAIBADBFMQ...FS6aKdZeGsysoCo4H9P",
              }),
              "signature": "uOrUfIIk5RyQ...nw62Ay1cl6AB"
            }
             """
        # finalize the shit
        print("order url_: ", order_url)
        for url_ in order_url:
            self.poll_status(url_,"")

        # Create payload
        encoded_der = base64enc(der)
        #print("DER: ", der)
        payload = {"csr": encoded_der}

        # Sign the body
        protected, payload, sig = self.get_body(finalize_url, payload)

        body = json.dumps({"protected": protected, "payload": payload, "signature": sig})
        print("This is bodyy of finalizing: ", body)

        response = self.client.post(finalize_url, data=body, headers=self.JOSE_Header, verify = self.cert)
        print("This is the response from the poll: ", response.json())
        if response.status_code == 200:
            print("This is response: ", response.json())
            for url_ in order_url:
                self.poll_status(url_, "")
            return True



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
        cert_url = self.directory["revokeCert"]
        #Create encoded url for cert
        encoded_cert = base64enc(cert)
        payload = {"certificate": encoded_cert, "reason": 4}
        #Create the JWS header, is this protected? I think it's protected
        protected, payload, sig = self.get_body(cert_url, payload)
        # Get the full body
        body = json.dumps({"protected": protected, "payload": payload, "signature": sig})
        print("This is bodyy of revoking certt: ", body)
        #Send the request
        response = requests.post(url=cert_url, data=body, headers=self.JOSE_Header, verify = self.cert)  # Does this work? Should be JWS
        print("This is the revokation response: ", response)
        if response.status_code == 200:
            print("Certificate revoked")
            return True



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
    def poll_status(self, url_, payload):
        while True:
            new_nonce = self.get_nonce()
            protected = base64enc(json.dumps({"alg": "ES256",
                                              "kid": self.kid,
                                              "nonce": new_nonce,  # Get the nonce from the server
                                              "url": url_}))
            # Sign the body
            sig, _ = self.sign_body(protected, payload)

            # Get the full body
            body = json.dumps({"protected": protected, "payload": payload, "signature": sig})
            response = self.client.post(url=url_, data=body, headers=self.JOSE_Header,
                                        verify=self.cert)  # Does this work? Should be JWS

            print("This is the response from the poll: ", response.json())
            if response.status_code == 200:
                status = response.json()["status"]
                if status in ["ready", "processing", "valid"]:
                    print("Valid")
                    break
                elif status == "pending":
                    print("Pending")
                    time.sleep(3)
                    continue
                else:
                    raise Exception("Invalid")
            else:
                raise Exception("Error getting URL, status code: {response.status_code}")


    def get_thumbnail(self):
        """
        Get the key authorization, used for the challenge
        Similar to jwk, the main difference is we need to hash them.
        :return:
        """
        #Get the key authorization
        key = {
            "crv": "P-256",
            "kty": "EC",
            "x": base64enc(self.account_key.pointQ.x.to_bytes()),
            "y": base64enc(self.account_key.pointQ.y.to_bytes()),
        }
        key_ = json.dumps(key, separators=(',', ':'))
        hash_key = H(data = key_, encoding='utf-8').digest()
        encoded_key = base64enc(hash_key).rstrip("=")
        return encoded_key


    def get_nonce(self):
        """
        Get the nonce from the server
        :return:
        """
        response = self.get_url_(self.directory["newNonce"])
        #print(response.json())
        nonce = response.headers["Replay-Nonce"]
        #print(nonce)
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
        url_ = self.client.get(url, headers=self.Header, verify='pebble.minica.pem')
        if url_.status_code == 200:
            #self.directory = url_.json()
            return url_.json()
        elif url_.status_code == 204:
            print(url_) #{}
            #self.directory = url_
            return url_  #Empty response
        else:
            raise Exception(f"Error getting URL, status code: {url_.status_code}")



    def sign_body(self, header, payload):
        """
        Sign the body of the request
        :param body:
        :return:
        """
        if payload:
            message = f"{header}.{payload}"
        else:
            message = "{}.{}".format(header, "")  #If there is no payload
        hashed_message = H(message, encoding='ascii')
        sign_message = self.sign.sign(hashed_message)
        return base64enc(sign_message), self.sign#Sign.sign, hate it, bugs are here
    def get_body_fin(self, url, payload):
        protected = {
            "alg": "ES256",
            "kid": self.kid,
            "nonce": self.get_nonce(),
            "url": url
        }

        enc_protected = base64enc(json.dumps(protected))
        enc_payload = base64enc(json.dumps(payload))


        sign, _ = self.sign_body(enc_protected, enc_payload)
        return enc_protected, enc_payload, sign
    def get_body(self, url, payload):
        protected = {
            "alg": "ES256",
            "kid": self.kid,
            "nonce": self.get_nonce(),
            "url": url
        }

        enc_protected = base64enc(json.dumps(protected))
        if payload:
            enc_payload = base64enc(json.dumps(payload))
        else:
            enc_payload = ""

        sign, _ = self.sign_body(enc_protected, enc_payload)
        return enc_protected, enc_payload, sign


    def http_challenge(self, challenge, key_authorization,http_server):#8.3
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
        #print("This is the whole challenge to be added: ", challenge)
        token = challenge["token"]
        #print("That's the token to be added: ", token)
        key_auth = f"{token}.{key_authorization}"
        #print("Should the key_authorization correct (http-01): ", key_auth)

        http_server.add_auth(challenge['token'], key_auth)
        response = http_server.get_challenge_response(token)
        #print("That's the string from the http server: ", response)
        return challenge["url"]



    def dns_challenge(self, response, challenge, key_authorization, dns_server): #8.4
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
        get_val = response.json()["identifier"]["value"]
        #print("get_val: ", get_val)
        dns_server.resolve_update(f"_acme-challenge.{get_val}", key_auth, "TXT")
        print("key auth: ", key_auth)
        return challenge["url"]
















#Run the dns server



#Stop the dns server
def stop_dns_server(server):
    server.shutdown_server()



def GenerateCSRForServer(domains):
    #Generate the key for the server
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COMMON_NAME, u"ACMEv2"), #Common name
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Netsec"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
        critical=False,
        # Sign the CSR with the private key.
    ).sign(key, hashes.SHA256())

    der = csr.public_bytes(serialization.Encoding.DER)
    return key, csr, der








def main():
    #Parse the arguments, use the comments from the header to test
    parse = argparse.ArgumentParser(description='ACME client')
    parse.add_argument('challenge', help='The challenge type you want to use', choices=['dns01', 'http01'])
    parse.add_argument('-u', '--dir', help='The directory you want to get certified', required=True)
    parse.add_argument('-c', '--record', help='Only challenge type', required=True)
    parse.add_argument('-d', '--domain', help='The domain you want to access.', action='append', required=True)
    parse.add_argument('-r', '--revoke',help='certificate revokation, for dns and https', action = argparse.BooleanOptionalAction, default=False)
    args = parse.parse_args()

    DNS_SERVER_PORT = 10053 #UDP port 10053
    CHALLENGE_SERVER_PORT = 5002 #TCP port 5002
    CHALLENGE_SERVER_SHUTDOWN_PORT = 5003 #TCP port 5003
    CERTIFICATE_PORT = 5001 #TCP port 5001



    IPAddr = "0.0.0.0" #Default IP address



    if args.challenge=="dns01":
        IPAddr = args.record
    elif args.challenge=="http01":
        IPAddr = args.record

    #---------------------Start the DNS server---------------------
    #print("DNS server starting........")
    dns_server = DNS_Server(args, DNS_SERVER_PORT, IPAddr)
    for domain in args.domain:
        #print("args.dir :", args.dir)
        dns_server.resolve_update(domain, args.record, "A")
    dns_server.start_server() #This doesn't work.
    print("DNS server started")

    #---------------------Start the challenge server---------------------
    print("Challenge server starting........")
    arguments = (CHALLENGE_SERVER_PORT, IPAddr)
    challenge_server = HTTPChallengeServer()
    #Use server thread instead of server, FAQ
    server_thread = Thread(target=challenge_server.start_server, args = arguments)
    server_thread.start()
    print("Challenge server started")

    print("Certificate server starting........")
    certificate_server = Certificate_HTTPS()
    shutdown_server = ShutdownHTTPServer()
    shutdown_thread = Thread(target=certificate_server.run_server, args = (CERTIFICATE_PORT, IPAddr))






    #---------------------Start the acme server---------------------
    #---------------------Start the acme server---------------------
    server = requests.Session()
    #server.verify = False
    server.verify = 'pebble.minica.pem'
    root_ca = 'pebble.minica.pem'
    #root_ca = False
    server.verify = root_ca
    # server_response = server.get(args.dir, verify = 'pebble.minica.pem')
    # print(server_response.json())

    acme = ACME_Client(server, root_ca)
    # Create account
    directory = acme.get_url_(args.dir)
    #Moved above

    if not directory:
        print("Error getting directory")
        return
    print("this is the directory", directory)
    account, _ = acme.create_account(directory)
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


    #Download certificate




    #Identifier authorization
    key_authorization = acme.get_thumbnail()
    #def authorization_and_challenge_response(self, urls, key_authorization, chal,  http_server, dns_server): #7.5
    state = acme.authorization_and_challenge_response(cert_order["authorizations"], key_authorization, args.challenge , challenge_server, dns_server)
    if not state:
        print("Authorization failed")
        return
    print("SUCCESS WITH AUTHORIZATION")
    #Finalize order
    #Generate CSR
    key, csr, der = GenerateCSRForServer(args.domain)
    #Finalize order
    print("CERT_URL: ", cert_url)
    #    #def finalize_order(self, order_url, finalize_url, der):
    state = acme.finalize_order(cert_order["authorizations"],cert_order["finalize"], der)
    if not state:
        print("Finalize order failed")
        return


    #Download Certificate
    cert_name = "cert.pem"
    key_name = "key.pem"
    cert = acme.download_cert(cert_url,key,  key_name, cert_name)
    if not cert:
        print("Certificate download failed")
        return
    print("SUCCESS WITH CERTIFICATE DOWNLOAD")

    #Revoke Certificate
    if args.revoke:
        #print(" THat'0s  the cert: ", cert)
        cert = x509.load_pem_x509_certificate(cert)
        print("This is the cert: ", cert)
        revoke_state = acme.revokeCert(cert.public_bytes(serialization.Encoding.DER))
        if not revoke_state:
            print("Certificate revocation failed")
            return
        print("SUCCESS WITH CERTIFICATE REVOCATION")


    #---------------------Start the certificate server---------------------
    #Start the certificate server
    certificate_server.run_server(host= IPAddr,port = CERTIFICATE_PORT, key = key_name, cert = cert_name)
    shutdown_thread.start()




    print("Certificate server shutting down........")










    #certificate_path = "project/pebble.minica.pem"
    #certificate_server = Certificate_HTTPS(IPAddr, CERTIFICATE_PORT)


    # ---------------------shutdown the DNS server---------------------
    print("DNS server shutting down........")
    stop_dns_server(dns_server)
    print("DNS server shut down")


    #-------------- shutdown the challenge server, why tf 21P?---------------------X
    print("Challenge server shutting down........")

    shutdown_server.shutdown_server(CHALLENGE_SERVER_SHUTDOWN_PORT, IPAddr)
    print("Challenge server shut down")









warnings.filterwarnings("ignore")
if __name__ == "__main__":
    main()

