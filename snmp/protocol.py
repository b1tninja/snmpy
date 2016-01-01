import asyncio
import binascii

from snmp.datagram import SNMPDatagram


class SNMPProtocol(asyncio.Protocol):
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, datagram, addr):
        print("Received from:", addr, binascii.hexlify(datagram))
        snmp = SNMPDatagram.decode(datagram)
        print(snmp)

    def sendto(self, datagram, addr):
        if not isinstance(datagram, bytes):
            datagram = bytes(datagram)

        self.transport.sendto(datagram, (addr, 161))
        print("Sent:", binascii.hexlify(datagram))

    def error_received(self, exc):
        print('Error received:', exc)

    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        loop = asyncio.get_event_loop()
        loop.stop()
