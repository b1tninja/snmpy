import asyncio
import binascii

from snmp.datagram import SNMPDatagram
from snmp.pdus import GetNextRequest
from snmp.protocol import SNMPProtocol

if __name__ == '__main__':

    loop = asyncio.get_event_loop()
    snmp_protocol_startup_task = loop.create_datagram_endpoint(SNMPProtocol, local_addr=('127.0.0.1', 0))
    transport, protocol = loop.run_until_complete(snmp_protocol_startup_task)
    # startup complete

    get_next_request = SNMPDatagram(pdu=GetNextRequest())
    print(get_next_request)
    try:
        datagram = bytes(get_next_request)
        print("Sending:", binascii.hexlify(datagram))
        transport.sendto(datagram, ('127.0.0.1', 161))
        loop.run_forever()

    finally:
        transport.close()
        loop.close()
