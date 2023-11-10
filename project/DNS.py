"""

DNS server: A DNS server which resolves the DNS Queries of the ACME Server.
Set up the god damn DNS server
Oh my goodness was this a pain

"""
import copy

import dnslib
from dnslib.server import DNSServer, DNSLogger
from dnslib import dns




class DNS_Resolver:
    """
    Setup my own dns resolver.  Goal is to implement a resolver of the dns server given request and handler

    """
    def __init__(self):
        self.zones = []

    def resolve(self, request, handler): #The name resolve is important and has to be resolve!
        reply = request.reply()
        for z in self.zones:
            a = copy.copy(z)
            a.rname = request.q.qname
            reply.add_answer(a)

        return reply

    #Debugging purposes
   # def return_zones(self):#
   #    return self.zones
class DNS_Server:
    """
    Setup my own dns server

    """
    def __init__(self, args, port, addr):
        self.args = args
        self.port = port
        self.resolver = DNS_Resolver()
        self.server = DNSServer(resolver=self.resolver, port=port, address=addr, logger=DNSLogger())


    def resolve_update(self, domain,zone,tp):
        #print("This is the zones of the server (in DNS code):", self.return_zones())
        if tp == "A":
            self.resolver.zones.append(dns.RR(domain, dns.QTYPE.A, rdata=dns.A(zone), ttl = 500))
        if tp == "TXT":
            self.resolver.zones.append(dns.RR(domain, dns.QTYPE.TXT, rdata=dns.TXT(zone), ttl = 500))


    def start_server(self):
        self.server.start_thread()
    def shutdown_server(self):  #Shutting down the server
        self.server.server.server_close()


    #Debugger
    def is_running(self):
        return self.server.isAlive()

    def return_args(self):
        return self.args

    def return_zones(self):
        return self.resolver.zones



