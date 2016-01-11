import asyncio

from snmp.protocol import SNMPProtocol

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    snmp_protocol_startup_task = loop.create_datagram_endpoint(SNMPProtocol, local_addr=('127.0.0.1', 0))
    transport, protocol = loop.run_until_complete(snmp_protocol_startup_task)
    try:
        assert isinstance(protocol, SNMPProtocol)
        try:
            task = asyncio.wait_for(protocol.get_next('127.0.0.1'), timeout=120)
            result = loop.run_until_complete(task)
        except asyncio.TimeoutError:
            print("Task timed out...")
        else:
            print("Done, result: ", result)

    finally:
        transport.close()
        loop.close()
