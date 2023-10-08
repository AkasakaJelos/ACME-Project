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
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import json
import requests
import dnslib

#Used to generate the public private key pair to prove the client is controlling it

def GenerateRSAKeyPair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )




class RequestSignature:
    pass


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

"""
class JWS:
    def __init__(self):
        pass
    def encapsulationJWS(self, data):
        pass


class ACMEClient:
    pass
