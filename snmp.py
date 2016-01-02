import asyncio

from snmp.pdus import GetResponse
from snmp.protocol import SNMPProtocol

if __name__ == '__main__':

    loop = asyncio.get_event_loop()
    snmp_protocol_startup_task = loop.create_datagram_endpoint(SNMPProtocol, local_addr=('127.0.0.1', 0))
    transport, protocol = loop.run_until_complete(snmp_protocol_startup_task)
    try:
        assert isinstance(protocol, SNMPProtocol)
        task = protocol.get_next('127.0.0.1')
        loop.run_until_complete(asyncio.wait_for(task, timeout=5))
        if task.cancelled():
            print("Timed out...")
        else:
            response = task.result()
            assert isinstance(response.pdu, GetResponse)
            print("Got response:", response.pdu.response)
            print("Get Next OID:", response.pdu.oid)
            # loop.run_forever()

    finally:
        transport.close()
        loop.close()
