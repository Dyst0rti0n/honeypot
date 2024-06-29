import binascii
import time
import random
import string
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.web.server import Site
from twisted.web.resource import Resource
import logging
from database import log_to_db
from geolocation import get_geolocation

# Configure logging
logging.basicConfig(filename='honeypot.log', level=logging.INFO)

INTERFACE = '0.0.0.0'

# Correct byte strings for responses
VNC_RFB_RESPONSE = b"RFB 003.008\n"
FTP_RESPONSE = b"220 Welcome to FTPD 1.3.0a Server (ProFTPD Anonymous Server) [192.168.1.231]\r\n"
TELNET_RESPONSE = b'\xff\xfd\x25'

active_connections = {}

def log_message(protocol, address, port, details):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    country, city = get_geolocation(address)
    log_msg = f"{timestamp} {protocol} connection from: {address} ({port}/TCP) - {details} [{city}, {country}]"
    logging.info(log_msg)
    print(log_msg)
    log_to_db(timestamp, protocol, address, port, details)

class RealTelnetProtocol(Protocol):
    def connectionMade(self):
        client_address = self.transport.getPeer().host
        log_message("TELNET", client_address, self.transport.getPeer().port, "Connection made")
        
        connection_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        active_connections[connection_id] = {'protocol': 'TELNET', 'address': client_address}
        
        self.transport.write(TELNET_RESPONSE)
        log_message("TELNET", client_address, self.transport.getPeer().port, "Sending response")

    def connectionLost(self, reason):
        client_address = self.transport.getPeer().host
        connection_id = next((id for id, details in active_connections.items() if details['protocol'] == 'TELNET' and details['address'] == client_address), None)
        if connection_id:
            del active_connections[connection_id]
            log_message("TELNET", client_address, self.transport.getPeer().port, "Connection closed")

class RealFTPProtocol(Protocol):
    def connectionMade(self):
        client_address = self.transport.getPeer().host
        log_message("FTP", client_address, self.transport.getPeer().port, "Connection made")
        
        connection_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        active_connections[connection_id] = {'protocol': 'FTP', 'address': client_address}
        
        self.transport.write(FTP_RESPONSE)
        log_message("FTP", client_address, self.transport.getPeer().port, "Sending response")

    def connectionLost(self, reason):
        client_address = self.transport.getPeer().host
        connection_id = next((id for id, details in active_connections.items() if details['protocol'] == 'FTP' and details['address'] == client_address), None)
        if connection_id:
            del active_connections[connection_id]
            log_message("FTP", client_address, self.transport.getPeer().port, "Connection closed")

class RealVNCProtocol(Protocol):
    def connectionMade(self):
        client_address = self.transport.getPeer().host
        log_message("VNC", client_address, self.transport.getPeer().port, "Connection made")
        
        connection_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        active_connections[connection_id] = {'protocol': 'VNC', 'address': client_address}
        
        self.transport.write(VNC_RFB_RESPONSE)
        log_message("VNC", client_address, self.transport.getPeer().port, "Sending response")

    def connectionLost(self, reason):
        client_address = self.transport.getPeer().host
        connection_id = next((id for id, details in active_connections.items() if details['protocol'] == 'VNC' and details['address'] == client_address), None)
        if connection_id:
            del active_connections[connection_id]
            log_message("VNC", client_address, self.transport.getPeer().port, "Connection closed")

class RealHTTPResource(Resource):
    isLeaf = True

    def render_GET(self, request):
        client_address = request.getClientIP()
        log_message("HTTP", client_address, request.getHost().port, "GET request received")
        connection_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        active_connections[connection_id] = {'protocol': 'HTTP', 'address': client_address}
        return b"<html><body><h1>Welcome to the Honeypot</h1></body></html>"

def start_honeypot():
    log_message("SYSTEM", "localhost", 0, "Starting up honeypot python program")
    
    reactor.listenTCP(5900, Factory.forProtocol(RealVNCProtocol), interface=INTERFACE)
    reactor.listenTCP(21, Factory.forProtocol(RealFTPProtocol), interface=INTERFACE)
    reactor.listenTCP(23, Factory.forProtocol(RealTelnetProtocol), interface=INTERFACE)
    
    resource = RealHTTPResource()
    factory = Site(resource)
    reactor.listenTCP(80, factory, interface=INTERFACE)
    
    reactor.run()
    log_message("SYSTEM", "localhost", 0, "Shutting down honeypot python program")

if __name__ == "__main__":
    start_honeypot()
