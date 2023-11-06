"""
A small implementation of JWS defined in RFC 7515


JWS sign and verify for the message of the ACME protocol


"""
from Crypto.Hash import SHA256

class JWS:
    def __init__(self):
        #TODO: Implement the init function
        pass

    def sign(self, data):
        #TODO: Implement the Sign function
        pass

    def verify(self, data, key):
        #TODO: Implement the verify function
        pass

    def H(self, data, encoding):
        # hash function using SHA256 encoding, used for the DNS challenge and more
        #TODO: Test
        Hash = SHA256.new((data.encode(encoding)))
        print(Hash)
        return Hash

