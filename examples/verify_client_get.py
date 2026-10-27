"""Verify SNMPClientImpl GET against a host (default: Brother at 192.168.1.71).

Usage:
    python -m examples.verify_client_get
    python -m examples.verify_client_get 192.168.1.71
    python -m examples.verify_client_get 127.0.0.1   # with a local agent

Live check (LAN printer)::

    python -m examples.verify_client_get 192.168.1.71

Regression without hardware::

    python -m snmp.test_client_impl
"""

from __future__ import annotations

import asyncio
import sys

from snmp.client import SNMPClientImpl
from snmp.enums import SNMPVersion

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.71"
OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "challenge": "1.3.6.1.4.1.2435.2.4.3.2435.5.100.10.1.0",
}


def _fmt(val) -> str:
    if val is None:
        return "None"
    inner = getattr(val, "value", val)
    if isinstance(inner, (bytes, bytearray)):
        b = bytes(inner)
        return f"OctetString len={len(b)} hex={b.hex()[:64]}{'...' if len(b) > 32 else ''}"
    return repr(val)[:200]


async def main() -> int:
    client = SNMPClientImpl(
        community="public",
        version=SNMPVersion.v2c,
        timeout=2.0,
        retries=2,
    )
    print(f"SNMPClientImpl -> {HOST}:161 community=public version=v2c")
    ok = True
    for name, oid in OIDS.items():
        val = await client.get(HOST, oid)
        print(f"  {name}: {_fmt(val)}")
        if val is None:
            ok = False
    await client.close()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
