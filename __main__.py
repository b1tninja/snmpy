"""SNMPy - A Python SNMP library built with asyncio."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Optional

from snmp import DEFAULT_PORT
from snmp.protocol import SNMPProtocol


logger = logging.getLogger(__name__)


async def get(
    host: str = "127.0.0.1",
    oid: Optional[str] = None,
    port: int = DEFAULT_PORT,
) -> None:
    """Connect to an SNMP device and retrieve the specified OID.

    Args:
        host: Target host/IP address.
        oid: SNMP Object Identifier to retrieve.
        port: SNMP port number.
    """
    loop = asyncio.get_event_loop()
    snmp_protocol_startup_task = loop.create_datagram_endpoint(
        SNMPProtocol,
        local_addr=("0.0.0.0", 0),
    )
    transport, protocol = await asyncio.ensure_future(snmp_protocol_startup_task)

    try:
        assert isinstance(protocol, SNMPProtocol)
        try:
            task = asyncio.wait_for(
                protocol.get(host, oid=oid, port=port),
                timeout=5,
            )
            result = await asyncio.ensure_future(task)
        except asyncio.TimeoutError:
            print("Task timed out...")
        else:
            print("Done, result: ", result)

    finally:
        transport.close()
        loop.close()


def main() -> None:
    """Entry point for the snmpy CLI."""
    logger.setLevel(logging.DEBUG)

    parser = argparse.ArgumentParser(description="snmpy - SNMP utility tool")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Target hostname or IP address")
    parser.add_argument("-P", "--port", type=int, default=DEFAULT_PORT, help="SNMP port (default: 161)")
    parser.add_argument("oid", nargs="?", help="Object Identifier to query")

    args = parser.parse_args()
    asyncio.run(get(args.host, args.oid, args.port))


if __name__ == "__main__":
    main()