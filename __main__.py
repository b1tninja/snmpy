import argparse
import asyncio
import logging
import sys

from snmp import DEFAULT_PORT

from snmp.protocol import SNMPProtocol


def get(host='127.0.0.1', oid=None, port=DEFAULT_PORT):
    loop = asyncio.get_event_loop()
    snmp_protocol_startup_task = loop.create_datagram_endpoint(SNMPProtocol, local_addr=('0.0.0.0', 0))
    transport, protocol = loop.run_until_complete(snmp_protocol_startup_task)
    try:
        assert isinstance(protocol, SNMPProtocol)
        try:
            task = asyncio.wait_for(protocol.get(host, oid=oid, port=port), timeout=5)
            result = loop.run_until_complete(task)
        except asyncio.TimeoutError:
            print("Task timed out...")
        else:
            print("Done, result: ", result)

    finally:
        transport.close()
        loop.close()


if __name__ == '__main__':

    logger = logging.getLogger()

    parser = argparse.ArgumentParser(description='snmpy')
    parser.add_argument('-H', '--host', default='127.0.0.1')
    parser.add_argument('-P', '--port', type=int, default=DEFAULT_PORT)

    parser.add_argument('oid', nargs='?', help='Object Identifier')
    try:
        args = parser.parse_args()
    except Exception:
        parser.print_help(sys.stderr)
    else:
        get(args.host, args.oid, args.port)
