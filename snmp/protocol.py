import asyncio
import binascii
import logging

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
        try:
            datagram = SNMPDatagram.decode(datagram)
        except:
            print("Malformed packet from:", host, binascii.hexlify(bytes(datagram)))
        else:
            # TODO: implement object comparison/equivalence testing
            key = (host, datagram.pdu.request_id.value)
            if key in self.requests:
                self.requests[key].set_result(datagram)
            else:
                logging.warning("Unexpected SNMP datagram from %s: %s.", host, datagram)
                logging.debug("%s", self.requests)

    def error_received(self, exc):
        logging.error(exc)

    def connection_lost(self, exc):
        logging.debug("Socket closed. Cancelling any pending futures")
        for fut in self.requests.values():
            fut.cancel()

    def sendto(self, datagram, host, port=161):
        assert isinstance(datagram, SNMPDatagram)
        # print("Sending %s:%d: %s" % (host, port, datagram))
        encoded = bytes(datagram)
        response = asyncio.Future()
        # print((host, datagram.pdu.request_id.value))
        key = (host, datagram.pdu.request_id.value)
        self.requests[key] = response
        response.add_done_callback(lambda fn: self.requests.__delitem__(key) if key in self.requests else None)
        self.transport.sendto(encoded, (host, port))
        # print("Sent:", binascii.hexlify(encoded))
        return response

    def get_next(self, host, oid=system, port=161):
        pdu = GetNextRequest.from_oid(oid)
        datagram = SNMPDatagram(pdu=pdu)
        return self.sendto(datagram, host, port)

