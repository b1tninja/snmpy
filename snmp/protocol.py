import asyncio
import binascii

from snmp.datagram import SNMPDatagram
from snmp.mib import system
from snmp.pdus import GetNextRequest, GetResponse


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
                future = self.requests.pop(key)
                future.set_result(datagram)
            else:
                print("Unexpected SNMP datagram from:", host, datagram)
                print(self.requests)

    def error_received(self, exc):
        print('Error received:', exc)

    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        loop = asyncio.get_event_loop()
        loop.stop()

    def sendto(self, datagram, host, port=161):
        assert isinstance(datagram, SNMPDatagram)
        # print("Sending %s:%d: %s" % (host, port, datagram))
        encoded = bytes(datagram)
        response = asyncio.Future()
        # print((host, datagram.pdu.request_id.value))
        self.requests[(host, datagram.pdu.request_id.value)] = response
        self.transport.sendto(encoded, (host, 161))
        # print("Sent:", binascii.hexlify(encoded))
        return response

    def get_next(self, host, oid=system, port=161):
        pdu = GetNextRequest.from_oid(oid)
        datagram = SNMPDatagram(pdu=pdu)
        return self.sendto(datagram, host, port)

    @asyncio.coroutine
    def walk(self, host, oid=system, port=161, timeout=2):
        # TODO: max retries
        datagram = SNMPDatagram(pdu=GetNextRequest.from_oid(oid))
        end_of_mib = False
        result = []
        while not end_of_mib:
            future = self.sendto(datagram, host, port)
            try:
                response = yield from asyncio.wait_for(future, timeout=2)
            except asyncio.TimeoutError:
                print("Request timed out... resending")
            else:
                assert isinstance(response.pdu, GetResponse)
                # print("Got response:", response.pdu.response)
                if datagram.pdu.oid == response.pdu.oid:
                    return result
                    # TODO: save to database?
                else:
                    result.append((response.pdu.oid, response.pdu.response))
                    # print("Get-Next OID:", response.pdu.oid)
                    pdu = GetNextRequest.from_oid(response.pdu.oid)
                    datagram = SNMPDatagram(pdu=pdu)
