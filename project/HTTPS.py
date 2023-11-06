"""
The Certificate HTTPS server uses a certificate obtained by the ACME client


"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

class Certificate_HTTPS:
    def __init__(self, ip, port):
        self.IP = ip
        self.port = port

    def startHTTPServer(self):
        #TODO: Start the HTTP server
        pass
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
        #TODO: Start the HTTP server
        #Stops the HTTP server
        pass
    def manage_certificate(self):
    #TODO: Manage the certificate
        pass


