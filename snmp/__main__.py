import argparse
import asyncio
import logging
from .mib import SystemOID

logging.basicConfig(level=logging.DEBUG)
# logging.basicConfig(level=logging.WARNING)

from snmp.protocol import SNMPProtocol

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--local_host', action='store', help="Local IP for UDP socket", default='0.0.0.0')
    parser.add_argument('--local_port', action='store', help="Local port for UDP socket", default=0, type=int)
    # TODO: parser.add_argument('--version')
    # parser.add_argument('--community', action='store', help='Community string', default='public')
    parser.add_argument('--host', action='store', help='Host of destination', default='demo.snmplabs.net', nargs='?')
    # TODO: parser.add_argument('--port')
    parser.add_argument('--oid', action='store', help='Object identifier to get', default=SystemOID, nargs='?')

    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    snmp_protocol_startup_task = loop.create_datagram_endpoint(SNMPProtocol,
                                                               local_addr=(args.local_host, args.local_port))

    transport, protocol = loop.run_until_complete(snmp_protocol_startup_task)
    try:
        assert isinstance(protocol, SNMPProtocol)
        try:
            task = asyncio.wait_for(protocol.get_next(args.host, oid=args.oid), timeout=10)
            result = loop.run_until_complete(task)
        except asyncio.TimeoutError:
            print("Task timed out...")
        else:
            print("Done, result: ", result)

    finally:
        transport.close()
        loop.close()
