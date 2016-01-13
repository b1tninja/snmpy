import asyncio
import logging

import binascii

from snmp.datagram import SNMPDatagram
from snmp.mib import system
from snmp.pdus import GetNextRequest, GetResponse


class ExceededRetries(Exception):
    pass

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
                try:
                    self.requests[key].set_result(datagram)
                except asyncio.InvalidStateError:
                    del self.requests[key]
            else:
                logging.debug("Unexpected SNMP datagram from %s: %s.", host, datagram)
                logging.debug("%s", self.requests)

    def error_received(self, exc):
        logging.error(exc)

    def connection_lost(self, exc):
        logging.critical("UDP Socket closed?!")
        # for fut in self.requests.values():
        #     fut.cancel()

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
        """Creates GetNextResponse PDU / datagram and returns a Future"""
        pdu = GetNextRequest.from_oid(oid)
        datagram = SNMPDatagram(pdu=pdu)
        return self.sendto(datagram, host, port)

    @asyncio.coroutine
    def walk(self, host, starting_oid=None, port=161, timeout=10, max_initial_failures=1, max_consequtive_failures=3):
        """Walks the MIB from the given starting oid, returns a list of (oid, object) tuples"""
        # TODO: perhaps an OrderedDict is more appropriate?
        responses = []
        attempts_remaining = max_initial_failures
        datagram = SNMPDatagram(pdu=GetNextRequest.from_oid(starting_oid))
        while attempts_remaining:
            future = self.sendto(datagram, host, port)
            try:
                response = yield from asyncio.wait_for(future, timeout=timeout)
            except asyncio.TimeoutError:
                logging.debug("Timeout for GetNextRequest(%s, %s)", host, datagram.pdu.oid)
                if isinstance(attempts_remaining, int):
                    attempts_remaining -= 1
            else:
                assert isinstance(response.pdu, GetResponse)
                attempts_remaining = max_consequtive_failures
                logging.debug("Response from host %s: %s=%s", host, response.pdu.oid, response.pdu.response)
                if datagram.pdu.oid == response.pdu.oid:
                    # end of mib condition
                    break
                else:
                    responses.append((response.pdu.oid, response.pdu.response))
                    pdu = GetNextRequest.from_oid(response.pdu.oid)
                    datagram = SNMPDatagram(pdu=pdu)
        # else:
        #     raise ExceededRetries('Maximum retries exceeded')
        return responses
