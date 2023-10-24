import dnslib
from dnslib.server import DNSServer, DNSLogger




class DNS_Resolver:
    """
    Setup my own dns resolver.  Goal is to implement a resolver of the dns server given request and handler

    """
    def __init__(self):
        self.zones = []

    def dns_resolve(self, request, handler):
        reply = request.reply()
        for z in self.zones:
            reply.add_answer(*dnslib.RR.fromZone(z))
        return reply
class DNS_Server:
    """
    Setup my own dns server

    """
    def __init__(self, args):
        self.args = args
        self.server = DNSServer(resolver=DNS_Resolver(), port=10053, address="0.0.0.0", logger=DNSLogger(prefix = False))


    def resolve_update(self, domain,zone,tp):
        if tp == "A":
            self.server.resolver.zones.append(dnslib.RR(domain, dnslib.QTYPE.A, rdata=dnslib.A(zone), ttl = 400))
        elif tp == "TXT":
            self.server.resolver.zones.append(dnslib.RR(domain, dnslib.QTYPE.TXT, rdata=dnslib.TXT(zone), ttl = 400))


    def start_server(self):
        self.server.start_thread()
    def shutdown_server(self):
        self.server.shutdown()

    #Debugger
    def is_running(self):
        return self.server.is_running

    def return_args(self):
        return self.args

    def return_zones(self):
        return self.server.resolver.zones



