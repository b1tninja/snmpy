import asyncio
import binascii

from snmp.datagram import SNMPDatagram
from snmp.mib import system
from snmp.pdus import GetNextRequest


class SNMPProtocol(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.requests = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, datagram, addr):
        (host, port) = addr
        datagram = SNMPDatagram.decode(datagram)
        # print(datagram)
        # TODO: implement object comparison/equivalence testing
        key = (host, datagram.pdu.request_id.value)
        if key in self.requests:
            # TODO: consider including the host in the result?
            self.requests[key].set_result(datagram)
        else:
            print("Unexpected packet from:", host, binascii.hexlify(datagram))

    def error_received(self, exc):
        print('Error received:', exc)

    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        loop = asyncio.get_event_loop()
        loop.stop()

    def get_next(self, host, oid=system, port=161):
        pdu = GetNextRequest.from_oid(oid)
        datagram = SNMPDatagram(pdu=pdu)
        # print(datagram)
        encoded = bytes(datagram)
        future = asyncio.Future()
        # TODO: resolve hostname before using as key?
        self.requests[(host, pdu.request_id.value)] = future
        # print("Sending:", binascii.hexlify(datagram))
        self.transport.sendto(encoded, (host, port))
        return future
