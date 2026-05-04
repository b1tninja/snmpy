"""SNMP Trap/Notification demo - RFC 1157 Section 4.1.6, RFC 1905 Section 2.10.

Demonstrates:
1. Trap receptor - UDP listener on port 162 for incoming SNMP traps (ABC interface)
2. Trap generation - Send all 5 SNMPv1 trap types
3. SNMPv2-Trap-PDU - Send traps using SNMPv2 format
4. Data contract - Use typed notification dataclasses for structured data

Run with: python -m examples.trap_demo
"""

from __future__ import annotations

import asyncio
import socket
from abc import ABC, abstractmethod
from typing import Optional

from ber.object import ObjectIdentifier, Integer, OctetString, Sequence

from snmp.datagram import SNMPDatagram
from snmp.pdus import Trap, SNMPv2Trap
from snmp.traps import TrapReceptor, TrapProtocol
from snmp.notifications import TrapNotification, SNMPv2Notification, decode_notification


# ==============================================================================
# ConsoleTrapReceptor — Example concrete implementation
# ==============================================================================

class ConsoleTrapReceptor(TrapReceptor):
    """Concrete trap receptor that prints trap data to the console.

    Demonstrates the TrapReceptor interface by implementing on_trap_received()
    to format and display incoming trap data.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 162) -> None:
        """Initialize the console trap receptor.

        Args:
            host: Bind address for the UDP listener.
            port: Bind port for the UDP listener.
        """
        super().__init__(host=host, port=port)

    def on_trap_received(self, pdu, source: str) -> None:
        """Handle a received trap by printing to the console.

        Args:
            pdu: A decoded PDU object (Trap or SNMPv2Trap).
            source: Source IP address.
        """
        self._format_trap_output(pdu)


# ==============================================================================
# Trap sending utilities
# ==============================================================================

async def demonstrate_trap_sending(receptor: TrapReceptor) -> None:
    """Send traps directly into the receptor's protocol for guaranteed delivery."""
    if receptor._protocol is None:
        print("  [No protocol available - using raw socket fallback]")
        # Fall back to raw socket (these go out to OS but won't loop back)
        await _send_via_socket()
        return

    print("  [Sending traps directly to receptor protocol]")

    def _send_to_protocol(datagram: SNMPDatagram) -> None:
        receptor._protocol.data.append(bytes(datagram))
        receptor._protocol.event.set()

    print("\n  --- Sending SNMPv1 Traps ---")

    # coldStart
    _send_to_protocol(SNMPDatagram(
        version=Integer.from_int(0).get_object(),
        community=OctetString(b"public").get_object(),
        pdu=Trap.from_trap_type(trap_type=Trap.COLD_START, enterprise="1.3.6.1.4.1.0",
            agent_addr="0.0.0.0", time_stamp=Integer.from_int(0).get_object(),
            variables=[("1.3.6.1.2.1.1.3", Integer.from_int(0)),
                       ("1.3.6.1.2.1.1.1", OctetString(b"System cold start"))]),
    ))
    print("  1. Sent coldStart trap")

    # warmStart
    _send_to_protocol(SNMPDatagram(
        version=Integer.from_int(0).get_object(),
        community=OctetString(b"public").get_object(),
        pdu=Trap.from_trap_type(trap_type=Trap.WARM_START, enterprise="1.3.6.1.4.1.0",
            agent_addr="0.0.0.0", time_stamp=Integer.from_int(0).get_object(),
            variables=[("1.3.6.1.2.1.1.3", Integer.from_int(100)),
                       ("1.3.6.1.2.1.1.1", OctetString(b"System warm restart"))]),
    ))
    print("  2. Sent warmStart trap")

    # linkDown
    _send_to_protocol(SNMPDatagram(
        version=Integer.from_int(0).get_object(),
        community=OctetString(b"public").get_object(),
        pdu=Trap.from_trap_type(trap_type=Trap.LINK_DOWN, enterprise="1.3.6.1.4.1.0",
            agent_addr="0.0.0.0", time_stamp=Integer.from_int(0).get_object(),
            variables=[("1.3.6.1.2.1.1.3", Integer.from_int(200)),
                       ("1.3.6.1.2.1.2.2.1.2", OctetString(b"eth0")),
                       ("1.3.6.1.2.1.2.2.1.8", Integer.from_int(2))]),
    ))
    print("  3. Sent linkDown trap")

    # linkUp
    _send_to_protocol(SNMPDatagram(
        version=Integer.from_int(0).get_object(),
        community=OctetString(b"public").get_object(),
        pdu=Trap.from_trap_type(trap_type=Trap.LINK_UP, enterprise="1.3.6.1.4.1.0",
            agent_addr="0.0.0.0", time_stamp=Integer.from_int(0).get_object(),
            variables=[("1.3.6.1.2.1.1.3", Integer.from_int(300)),
                       ("1.3.6.1.2.1.2.2.1.2", OctetString(b"eth0")),
                       ("1.3.6.1.2.1.2.2.1.8", Integer.from_int(1))]),
    ))
    print("  4. Sent linkUp trap")

    # authFailure
    _send_to_protocol(SNMPDatagram(
        version=Integer.from_int(0).get_object(),
        community=OctetString(b"public").get_object(),
        pdu=Trap.from_trap_type(trap_type=Trap.AUTHENTICATION_FAILURE, enterprise="1.3.6.1.4.1.0",
            agent_addr="0.0.0.0", time_stamp=Integer.from_int(0).get_object(),
            variables=[("1.3.6.1.2.1.1.3", Integer.from_int(400))]),
    ))
    print("  5. Sent authenticationFailure trap")

    print("\n  --- Sending SNMPv2-Trap-PDU Traps ---")

    # coldStart v2
    v2_vars_1 = Sequence.from_list([
        Sequence.from_list([ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0").get_object(),
                           ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.1").get_object()]),
        Sequence.from_list([ObjectIdentifier.from_string("1.3.6.1.2.1.1.3").get_object(),
                           Integer.from_int(500).get_object()]),
    ])
    _send_to_protocol(SNMPDatagram(
        version=Integer.from_int(1).get_object(),
        community=OctetString(b"public").get_object(),
        pdu=SNMPv2Trap(variable_bindings=v2_vars_1),
    ))
    print("  6. Sent coldStart v2 trap")

    # linkDown v2
    v2_vars_2 = Sequence.from_list([
        Sequence.from_list([ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0").get_object(),
                           ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.3").get_object()]),
        Sequence.from_list([ObjectIdentifier.from_string("1.3.6.1.2.1.1.3").get_object(),
                           Integer.from_int(600).get_object()]),
        Sequence.from_list([ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.2").get_object(),
                           OctetString(b"eth1").get_object()]),
    ])
    _send_to_protocol(SNMPDatagram(
        version=Integer.from_int(1).get_object(),
        community=OctetString(b"public").get_object(),
        pdu=SNMPv2Trap(variable_bindings=v2_vars_2),
    ))
    print("  7. Sent linkDown v2 trap")


async def _send_via_socket() -> None:
    """Fallback: send all traps via raw socket."""
    import socket as _sock

    traps_data = [
        # (version, community, pdu, desc)
        (Integer.from_int(0).get_object(), OctetString(b"public").get_object(),
         Trap.from_trap_type(Trap.COLD_START, "1.3.6.1.4.1.0", "0.0.0.0",
                             Integer.from_int(0).get_object(),
                             [("1.3.6.1.2.1.1.3", Integer.from_int(0)),
                              ("1.3.6.1.2.1.1.1", OctetString(b"System cold start"))]),
         "1. coldStart"),
        (Integer.from_int(0).get_object(), OctetString(b"public").get_object(),
         Trap.from_trap_type(Trap.WARM_START, "1.3.6.1.4.1.0", "0.0.0.0",
                             Integer.from_int(0).get_object(),
                             [("1.3.6.1.2.1.1.3", Integer.from_int(100)),
                              ("1.3.6.1.2.1.1.1", OctetString(b"System warm restart"))]),
         "2. warmStart"),
    ]
    for ver, comm, pdu, desc in traps_data:
        try:
            sock = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.sendto(bytes(SNMPDatagram(version=ver, community=comm, pdu=pdu)),
                       ("127.0.0.1", 162))
            sock.close()
            print(f"  {desc} sent")
        except Exception as e:
            print(f"  {desc} error: {e}")


async def _send_all_traps() -> None:
    """Fallback: send all traps via raw socket."""
    cold_start_vars = [
        ("1.3.6.1.2.1.1.3", Integer.from_int(0)),
        ("1.3.6.1.2.1.1.1", OctetString(b"System cold start")),
    ]
    trap = Trap.from_trap_type(
        trap_type=Trap.COLD_START, enterprise="1.3.6.1.4.1.0",
        agent_addr="0.0.0.0", time_stamp=Integer.from_int(0).get_object(),
        variables=cold_start_vars,
    )
    datagram = SNMPDatagram(
        version=Integer.from_int(0).get_object(),
        community=OctetString(b"public").get_object(),
        pdu=trap,
    )
    await _send_trap_direct(datagram, "127.0.0.1", 162)
    print("  1. Sent coldStart trap")

    warm_start_vars = [
        ("1.3.6.1.2.1.1.3", Integer.from_int(100)),
        ("1.3.6.1.2.1.1.1", OctetString(b"System warm restart")),
    ]
    trap = Trap.from_trap_type(
        trap_type=Trap.WARM_START, enterprise="1.3.6.1.4.1.0",
        agent_addr="0.0.0.0", time_stamp=Integer.from_int(0).get_object(),
        variables=warm_start_vars,
    )
    datagram = SNMPDatagram(
        version=Integer.from_int(0).get_object(),
        community=OctetString(b"public").get_object(),
        pdu=trap,
    )
    await _send_trap_direct(datagram, "127.0.0.1", 162)
    print("  2. Sent warmStart trap")


async def _send_trap_direct(datagram: SNMPDatagram, host: str, port: int) -> None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(bytes(datagram), (host, port))
        sock.close()
    except Exception as e:
        print(f"    [Send error: {e}]")


async def main() -> None:
    print("=" * 70)
    print("SNMP Trap/Notification Demonstration")
    print("=" * 70)

    print("\n--- 1. Starting Trap Receptor ---")
    receptor = ConsoleTrapReceptor(host="127.0.0.1", port=162)
    await receptor.start()

    if receptor._transport:
        await asyncio.sleep(0.5)

        print("\n--- 2. Sending Traps ---")
        await demonstrate_trap_sending(receptor)

        await asyncio.sleep(1.0)
        print("\n--- 3. Received Traps ---")
        pdus = await receptor.receive_pdus(timeout=2.0)

        # Also demonstrate the new notification-based interface
        print("\n--- 4. Using Notification Data Contracts ---")
        notifications = await receptor.receive_notifications(timeout=1.0)
        if notifications:
            print(f"\n  [receive_notifications() returned {len(notifications)} notifications]")
            for i, notif in enumerate(notifications, 1):
                if isinstance(notif, TrapNotification):
                    print(f"\n  Notification #{i}:")
                    print(f"    Type: SNMPv1 Trap")
                    print(f"    Trap Type: {notif.trap_type}")
                    print(f"    Enterprise: {notif.enterprise}")
                    print(f"    Agent Addr: {notif.agent_addr}")
                    print(f"    Time Stamp: {notif.time_stamp}")
                    print(f"    Variables ({len(notif.variables)}):")
                    for var in notif.variables:
                        print(f"      {var.oid} = {var.value}")
                elif isinstance(notif, SNMPv2Notification):
                    print(f"\n  Notification #{i}:")
                    print(f"    Type: SNMPv2c Trap")
                    print(f"    Trap OID: {notif.trap_oid}")
                    print(f"    Variables ({len(notif.variables)}):")
                    for var in notif.variables:
                        print(f"      {var.oid} = {var.value}")
        else:
            print("  No notifications received via receive_notifications() (notifications were captured by on_trap_received)")

        await receptor.stop()
    else:
        print("  Trap receptor failed to start. Cannot proceed.")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    asyncio.run(main())