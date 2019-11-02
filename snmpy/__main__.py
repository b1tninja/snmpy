import argparse
import asyncio
import logging
from typing import Optional
from .mib import SystemOID

logging.basicConfig(level=logging.DEBUG)
# logging.basicConfig(level=logging.WARNING)

from .protocol import SNMPProtocol

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--local_host', action='store', help="Local IP for UDP socket", default=SNMPAgent.local_host)
    parser.add_argument('--local_port', action='store', help="Local port for UDP socket", default=SNMPAgent.local_port, type=int)
    # TODO: parser.add_argument('--version')
    # parser.add_argument('--community', action='store', help='Community string', default='public')
    parser.add_argument('--host', action='store', help='Host of destination', default='demo.snmplabs.net', nargs='?')
    # TODO: parser.add_argument('--port')
    parser.add_argument('--oid', action='store', help='Object identifier to get', default=SystemOID, nargs='?')


class SNMPAgent:
    local_host: str = '0.0.0.0'
    local_port: int = 0

    def __init__(self, local_host: Optional[str], local_port: Optional[int], debug=False):
        if local_host:
            self.local_host = local_host

        if local_port:
            self.local_port = local_port

        self.loop = asyncio.new_event_loop()

        self.transport, self.protocol = self._create_datagram_endpoint(local_host, local_port)

    def __del__(self):
        self.transport.close()
        self.loop.close()
        logging.error()

    def _create_datagram_endpoint(self, local_host, local_port):
        endpoint_coro = self.loop.create_datagram_endpoint(SNMPProtocol, local_addr=(local_host, local_port))
        return self.loop.run_until_complete(endpoint_coro)

    async def _get(self, oid, host='demo.snmplabs.net',  port=161):
        datagram = await self.protocol.get(oid)
        self.transport.sendto()

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


    except asyncio.TimeoutError:
        print("Task timed out...")
    else:
        print("Done, result: ", result)


    args = parser.parse_args()

