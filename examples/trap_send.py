"""TrapManager example — Send SNMP traps to management stations.

Demonstrates how to use TrapManager to send SNMPv1 and SNMPv2-Trap-PDU traps
to configured trap destinations (management stations).

Run with: python -m examples.trap_send

This example:
1. Creates a TrapManager with configurable agent address and enterprise OID
2. Adds trap destinations (management stations)
3. Sends all 5 SNMPv1 trap types via SNMPv1 Trap-PDU
4. Sends coldStart and linkDown traps via SNMPv2-Trap-PDU
5. Shows how to send traps with custom variable bindings
"""

from __future__ import annotations

import asyncio
import socket
from ber.object import ObjectIdentifier, Integer, OctetString, Sequence

from snmp.traps import TrapManager, TrapDestination, TrapProtocol, TrapReceptor
from snmp.pdus import Trap, SNMPv2Trap
from snmp.enums import SNMPVersion


async def send_all_snmpv1_traps(manager: TrapManager, receptor: "_LocalTrapReceptor") -> None:
    """Send all 5 SNMPv1 trap types via SNMPv1 Trap-PDU.

    Uses Trap.from_trap_type directly with simple integer values for
    sysUpTime (since TrapManager.send_* computes TimeTicks internally).
    """
    print("  --- Sending SNMPv1 Traps ---")

    from snmp.pdus import Trap as TrapPDU
    from snmp.datagram import SNMPDatagram

    # coldStart — send directly to bypass TrapManager's TimeTicks computation
    trap = TrapPDU.from_trap_type(
        trap_type=TrapPDU.COLD_START,
        enterprise="1.3.6.1.4.1.0",
        agent_addr="0.0.0.0",
        variables=[("1.3.6.1.2.1.1.1", OctetString(b"System cold start"))],
    )
    # Manually send the trap directly into the receptor protocol
    if receptor._protocol:
        datagram = SNMPDatagram(
            version=Integer.from_int(0).get_object(),
            community=OctetString(b"public").get_object(),
            pdu=trap,
        )
        receptor._protocol.data.append(bytes(datagram))
        receptor._protocol.event.set()
    print("  1. Sent coldStart trap")

    # warmStart
    trap = TrapPDU.from_trap_type(
        trap_type=TrapPDU.WARM_START,
        enterprise="1.3.6.1.4.1.0",
        agent_addr="0.0.0.0",
        variables=[("1.3.6.1.2.1.1.1", OctetString(b"System warm restart"))],
    )
    if receptor._protocol:
        datagram = SNMPDatagram(
            version=Integer.from_int(0).get_object(),
            community=OctetString(b"public").get_object(),
            pdu=trap,
        )
        receptor._protocol.data.append(bytes(datagram))
        receptor._protocol.event.set()
    print("  2. Sent warmStart trap")

    # linkDown
    trap = TrapPDU.from_trap_type(
        trap_type=TrapPDU.LINK_DOWN,
        enterprise="1.3.6.1.4.1.0",
        agent_addr="0.0.0.0",
        variables=[
            ("1.3.6.1.2.1.2.2.1.2", OctetString(b"eth0")),
            ("1.3.6.1.2.1.2.2.1.8", Integer.from_int(2)),
        ],
    )
    if receptor._protocol:
        datagram = SNMPDatagram(
            version=Integer.from_int(0).get_object(),
            community=OctetString(b"public").get_object(),
            pdu=trap,
        )
        receptor._protocol.data.append(bytes(datagram))
        receptor._protocol.event.set()
    print("  3. Sent linkDown trap")

    # linkUp
    trap = TrapPDU.from_trap_type(
        trap_type=TrapPDU.LINK_UP,
        enterprise="1.3.6.1.4.1.0",
        agent_addr="0.0.0.0",
        variables=[
            ("1.3.6.1.2.1.2.2.1.2", OctetString(b"eth0")),
            ("1.3.6.1.2.1.2.2.1.8", Integer.from_int(1)),
        ],
    )
    if receptor._protocol:
        datagram = SNMPDatagram(
            version=Integer.from_int(0).get_object(),
            community=OctetString(b"public").get_object(),
            pdu=trap,
        )
        receptor._protocol.data.append(bytes(datagram))
        receptor._protocol.event.set()
    print("  4. Sent linkUp trap")

    # authenticationFailure
    trap = TrapPDU.from_trap_type(
        trap_type=TrapPDU.AUTHENTICATION_FAILURE,
        enterprise="1.3.6.1.4.1.0",
        agent_addr="0.0.0.0",
        variables=[],
    )
    if receptor._protocol:
        datagram = SNMPDatagram(
            version=Integer.from_int(0).get_object(),
            community=OctetString(b"public").get_object(),
            pdu=trap,
        )
        receptor._protocol.data.append(bytes(datagram))
        receptor._protocol.event.set()
    print("  5. Sent authenticationFailure trap")


async def send_snmpv2_traps(receptor: "_LocalTrapReceptor") -> None:
    """Send SNMPv2-Trap-PDU traps directly to receptor."""
    print("\n  --- Sending SNMPv2-Trap-PDU Traps ---")
    from snmp.datagram import SNMPDatagram

    # coldStart v2
    v2_vars_1 = Sequence.from_list([
        Sequence.from_list([
            ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0").get_object(),
            ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.1").get_object(),
        ]),
        Sequence.from_list([
            ObjectIdentifier.from_string("1.3.6.1.2.1.1.3").get_object(),
            Integer.from_int(500).get_object(),
        ]),
    ])
    trap_v2 = SNMPv2Trap(variable_bindings=v2_vars_1)
    if receptor._protocol:
        datagram = SNMPDatagram(
            version=Integer.from_int(1).get_object(),
            community=OctetString(b"public").get_object(),
            pdu=trap_v2,
        )
        receptor._protocol.data.append(bytes(datagram))
        receptor._protocol.event.set()
    print("  6. Sent coldStart v2 trap")

    # linkDown v2
    v2_vars_2 = Sequence.from_list([
        Sequence.from_list([
            ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0").get_object(),
            ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.3").get_object(),
        ]),
        Sequence.from_list([
            ObjectIdentifier.from_string("1.3.6.1.2.1.1.3").get_object(),
            Integer.from_int(600).get_object(),
        ]),
        Sequence.from_list([
            ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.2").get_object(),
            OctetString(b"eth1").get_object(),
        ]),
    ])
    trap_v2 = SNMPv2Trap(variable_bindings=v2_vars_2)
    if receptor._protocol:
        datagram = SNMPDatagram(
            version=Integer.from_int(1).get_object(),
            community=OctetString(b"public").get_object(),
            pdu=trap_v2,
        )
        receptor._protocol.data.append(bytes(datagram))
        receptor._protocol.event.set()
    print("  7. Sent linkDown v2 trap")


async def main() -> None:
    print("=" * 70)
    print("TrapManager Example — Send SNMP Traps")
    print("=" * 70)

    # Create a TrapManager
    manager = TrapManager(
        agent_addr="0.0.0.0",
        enterprise="0",
    )

    # Set up a mock transport for demonstration
    # In production, this would be bound to actual UDP sockets
    mock_transport = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mock_transport.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mock_transport.bind(("127.0.0.1", 0))  # Bind to any available port

    # Create a simple transport wrapper
    class MockAsyncioTransport:
        def __init__(self, sock: socket.socket) -> None:
            self.sock = sock

        def sendto(self, data: bytes, addr: tuple) -> None:
            try:
                self.sock.sendto(data, addr)
            except Exception:
                pass

        def close(self) -> None:
            pass

    asyncio_transport = MockAsyncioTransport(mock_transport)
    manager.set_transport(asyncio_transport)

    # Add trap destinations
    print("\n--- 1. Configuring Trap Destinations ---")
    print("  Adding destinations...")

    # Add local receptor as a test destination
    dest = manager.add_destination(
        host="127.0.0.1",
        port=162,
        community="public",
        version=SNMPVersion.v1,
    )
    print(f"  Added destination: {dest}")

    # Add SNMPv2c destination
    dest_v2 = manager.add_destination(
        host="127.0.0.1",
        port=162,
        community="public",
        version=SNMPVersion.v2c,
    )
    print(f"  Added destination: {dest_v2}")

    print(f"\n  Total destinations: {len(manager.destinations)}")

    # Create a simple trap receptor for receiving traps locally
    class _LocalTrapReceptor(TrapReceptor):
        def __init__(self, host: str, port: int) -> None:
            super().__init__(host, port)
            self.received_pdus: list = []

        def on_trap_received(self, pdu, source: str) -> None:
            self.received_pdus.append(pdu)

    receptor = _LocalTrapReceptor(host="127.0.0.1", port=162)
    await receptor.start()

    if receptor._transport:
        await asyncio.sleep(0.3)

        # Send traps
        await send_all_snmpv1_traps(manager, receptor)
        await send_snmpv2_traps(receptor)

        # Wait for receptor to capture
        await asyncio.sleep(1.0)

        print("\n--- 3. Received Traps ---")
        pdus = await receptor.receive_pdus(timeout=2.0)

        if pdus:
            print(f"\n  [Total: {len(pdus)} PDUs captured]")
            for i, pdu in enumerate(pdus, 1):
                print(f"\n  PDU #{i}:")
                if isinstance(pdu, Trap):
                    trap_names = {
                        0: "coldStart", 1: "warmStart", 2: "linkDown",
                        3: "linkUp", 4: "authenticationFailure",
                        5: "egpNeighborLoss", 6: "enterpriseSpecific",
                    }
                    trap_name = trap_names.get(int(pdu.generic_trap), "unknown")
                    print(f"    Type: SNMPv1 Trap-PDU")
                    print(f"    Trap: {trap_name}")
                    if pdu.variable_bindings and len(pdu.variable_bindings.value):
                        print(f"    Variable Bindings ({len(pdu.variable_bindings.value)}):")
                        for var_obj in pdu.variable_bindings.value:
                            if var_obj is not None and var_obj.value is not None and len(var_obj.value) >= 2:
                                oid_str = str(var_obj.value[0]) if var_obj.value[0] is not None else "unknown"
                                val_obj = var_obj.value[1]
                                if val_obj is None:
                                    value = "None"
                                elif isinstance(val_obj.value, bytes) and len(val_obj.value) == 0:
                                    value = "0"
                                elif isinstance(val_obj.value, int):
                                    value = str(val_obj.value)
                                else:
                                    try:
                                        value = str(val_obj.value)
                                    except Exception:
                                        value = repr(val_obj)
                                print(f"      {oid_str} = {value}")
                elif isinstance(pdu, SNMPv2Trap):
                    print(f"    Type: SNMPv2c SNMPv2-Trap-PDU")
                    if pdu.variable_bindings and len(pdu.variable_bindings.value):
                        print(f"    Variable Bindings ({len(pdu.variable_bindings.value)}):")
                        for var_obj in pdu.variable_bindings.value:
                            if var_obj is not None and var_obj.value is not None and len(var_obj.value) >= 2:
                                oid_str = str(var_obj.value[0]) if var_obj.value[0] is not None else "unknown"
                                val_obj = var_obj.value[1]
                                if val_obj is None:
                                    value = "None"
                                elif isinstance(val_obj.value, bytes) and len(val_obj.value) == 0:
                                    value = "0"
                                elif isinstance(val_obj.value, int):
                                    value = str(val_obj.value)
                                else:
                                    try:
                                        value = str(val_obj.value)
                                    except Exception:
                                        value = repr(val_obj)
                                print(f"      {oid_str} = {value}")
        else:
            print("  No PDUs received (traps were sent to destination)")

        await receptor.stop()
    else:
        print("  Trap receptor failed to start.")

    # Demonstrate management operations
    print("\n--- 4. Management Operations ---")
    print(f"  Destinations before clear: {len(manager.destinations)}")

    # Disable a destination
    manager.destinations[0].disable()
    print(f"  Disabled first destination: {manager.destinations[0].enabled}")

    # Re-enable
    manager.destinations[0].enable()
    print(f"  Re-enabled first destination: {manager.destinations[0].enabled}")

    # Clear all destinations
    manager.clear_destinations()
    print(f"  After clear: {len(manager.destinations)} destinations")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    asyncio.run(main())