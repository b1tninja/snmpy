"""Session demo — blocking SNMPv1/v2c client against an in-process agent.

Starts ``MockSNMPServer`` (asyncio UDP, loopback) with a few extra
Printer MIB values registered, then drives it with the synchronous
``Session`` API from a worker thread (Session blocks, the server needs
the event loop — so ``asyncio.to_thread`` bridges the two).

Run:  python examples/session_demo.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root

import snmp.mib_printer  # noqa: F401 — registers "printer-mib" pack
from snmp import Session, SNMPVersion
from snmp.mib_system import sysDescr, sysName
from snmp.server import MockSNMPServer

HOST = "127.0.0.1"
PORT = 1161

# Extra values served on top of MockSNMPServer's built-in system group.
# Printer MIB instances per RFC 3805 (device 1, marker 1, supply 1).
EXTRA = {
    "1.3.6.1.2.1.43.11.1.1.7.1.1": 42,                   # prtMarkerSuppliesLevel
    "1.3.6.1.2.1.43.11.1.1.11.1.1": "Demo Toner Cartridge",  # ...Description
}

# Writable scalar: DynamicValueHandler keeps SET values in this dict.
PRINTER_NAME_OID = "1.3.6.1.2.1.43.5.1.1.16.1"  # prtGeneralPrinterName
_printer_name = {"value": "snmpy-demo-printer"}


def session_demo() -> None:
    """Blocking client side — runs in a worker thread."""
    with Session(HOST, port=PORT, community="public",
                 set_community="private", version=SNMPVersion.v2c,
                 timeout=2.0, retries=2) as snmp:
        print("-- GET (typed helpers) --------------------------------------")
        print(f"sysDescr   : {snmp.get_str(sysDescr)}")
        print(f"sysName    : {snmp.get_str(sysName)}")
        print(f"printerName: {snmp.get_str('printer-mib:prtGeneralPrinterName')}")

        print("\n-- GET table instance -----------------------------------------")
        print(f"supply level: {snmp.get_int('1.3.6.1.2.1.43.11.1.1.7.1.1')}%")

        print("\n-- WALK (iterative GETNEXT, RFC 3416 4.2.2) -------------------")
        for oid, value in snmp.walk("1.3.6.1.2.1.43"):
            print(f"  {oid} = {value}")

        print("\n-- SET (write community, then read back) -----------------------")
        ok = snmp.set(PRINTER_NAME_OID, "renamed-printer")
        print(f"set printerName -> {ok}; "
              f"read back: {snmp.get_str(PRINTER_NAME_OID)}")

        print("\n-- Missing OID (behavior depends on agent) ---------------------")
        try:
            value = snmp.get_str("1.3.6.1.2.1.99.0")
            print(f"agent returned empty value: {value!r}")
        except LookupError as exc:
            print(f"LookupError (RFC 3416 4.1.6 exception value): {exc}")


async def main() -> None:
    server = MockSNMPServer(community="public", community_rw="private")
    for oid, value in EXTRA.items():
        server.register_static(oid, value)
    server.register_dynamic(
        PRINTER_NAME_OID,
        getter=lambda oid: _printer_name["value"],
        setter=lambda oid, value: _printer_name.update(
            {"value": value.decode() if isinstance(value, bytes) else value}) or True,
        access="readwrite",
    )

    await server.start(host=HOST, port=PORT)
    print(f"MockSNMPServer listening on {HOST}:{PORT} ({server!r})\n")
    try:
        await asyncio.to_thread(session_demo)
    finally:
        await server.stop()
        print("\nServer stopped — demo complete.")


if __name__ == "__main__":
    asyncio.run(main())


