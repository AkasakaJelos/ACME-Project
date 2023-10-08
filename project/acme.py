"""



Allowed libraries:
cryptography
click
dacite
Django
dnslib
Flask
falcon
gunicorn
PyCryptodome
pycrypto
pyopenssl
requests
tornado


"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import json
import requests
import dnslib
import http.server as httpserver
import ssl
import flask
import socket

#Used to generate the public private key pair to prove the client is controlling it



"""
A JWS object sent as the body of an ACME request MUST meet the
following additional criteria:

o  The JWS MUST be in the Flattened JSON Serialization [RFC7515]

o  The JWS MUST NOT have multiple signatures

o  The JWS Unencoded Payload Option [RFC7797] MUST NOT be used

o  The JWS Unprotected Header [RFC7515] MUST NOT be used

o  The JWS Payload MUST NOT be detached

o  The JWS Protected Header MUST include the following fields:

  *  "alg" (Algorithm)

     +  This field MUST NOT contain "none" or a Message
        Authentication Code (MAC) algorithm (e.g. one in which the
        algorithm registry description mentions MAC/HMAC).

  *  "nonce" (defined in Section 6.5)

  *  "url" (defined in Section 6.4)

  *  Either "jwk" (JSON Web Key) or "kid" (Key ID) as specified
     below
     
     
Used for message size transport and convert the message into UTF-8

"""
class JWS:
    def __init__(self):
        pass
    def encapsulationJWS(self, data):
        pass



    def convertUTF8(self, data):
        #Converts the data into UTF-8
        return data.encode('utf-8')


class Certificate_HTTPS:
    def __init__(self):
        self.key = self.generateKey()
        self.Certificate = x509()
        self.HTTP_server = 5002 #Challenge HTTP server
        self.HTTPS_server = 5001 #Certificate HTTP server
        self.HTTPS_shutDown = 5003 #Certificate HTTP server shutdown


    def startHTTPServer(self):
        #Starts the HTTP server

        pass

    def GenerateCSRForServer(self, key):
        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"), #Country
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"), #State
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"PfaeffikonZH"), #Locality
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NetSecProject"), #Organization
            x509.NameAttribute(NameOID.COMMON_NAME, u"newtwitter.ch"), #Common name
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName(u"newtwitter.ch"), #DNS name
            ]),
            critical=False,
            # Sign the CSR with the private key.
        ).sign(key, hashes.SHA256())
        return csr

    def stopHTTPServer(self):
        #Stops the HTTP server
        pass

    def GenerateRSAKeyPair(self):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )





class DNS_Server:
    """
    Setup my own dns server

    Domain name: newtwitter.ch

    """
    def __init__(self, HTTP_resolver):
        self.dnsport = 10053 #DNS port on specification
        self.domain = "newtwitter.ch" #Domain name
        self.ipAddr = "127.0.0.1"
        self.server = dnslib.DNSServer(
            HTTP_resolver,
            port=self.dnsport,
            address=self.ipAddr
        )
        self.SOA_record = dnslib.SOA(
            mname="ns1.newtwitter.ch", # primary name server
            rname="admin.newtwitter.ch", # email of admin
            times=(
                2017010101,  # serial number
                60,  # refresh
                60,  # retry
                60,  # expire
                60,  # minimum
            )
        )

    def startServer(self):
        pass

    def stopServer(self):
        pass

    def getRecord(self):
        return self.SOA_record[dnslib.NS("ns1.newtwitter.ch"), dnslib.NS("ns2.newtwitter.ch")]

    def getHTTPChallenge(self, challenge):
        #Get the HTTP challenge
        print("Challenge: ", challenge)
        if (challenge == "http-01"):
            return self.getHTTPChallengeRecord() #Get the HTTP challenge record
        elif (challenge == "dns-01"):
            return self.getDNSChallengeRecord() #Get the DNS challenge record
        else:
            raise Exception("Challenge not supported")

    def getChallenge(self):
        pass

    def setChallenge(self):
        pass

    def getChallengeRecord(self):
        pass

    def setChallengeRecord(self):
        pass






"""
Main implementation of the ACME client
-------------------------------------------

"""
class ACME_Client:
    def __init__(self):
        pass

    def setupServer(self):
        pass

    def placeCertOrder(self):
        pass

    def checkChallengeValid(self, challenge):
        pass


    def placeCSR(self):
        pass

    def getCert(self):
        pass




cert = Certificate_HTTPS()
key = cert.GenerateRSAKeyPair()
csr = cert.GenerateCSRForServer(key)
print("Key: ", key)
print("CSR: ", csr)