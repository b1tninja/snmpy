"""Trap and Notification Management — RFC 1157 §4.1.6, RFC 1905 §2.10.

Provides:
- Trap destination management (configurable trap targets)
- Trap generation with variable bindings
- SNMPv1 and SNMPv2-Trap-PDU support
- Automatic trap generation for common events (coldStart, warmStart, linkDown, linkUp)

Usage:
    >>> from snmp.traps import TrapManager, send_trap
    >>> trap_mgr = TrapManager()
    >>> trap_mgr.add_destination("192.168.1.100", community="public")
    >>> trap_mgr.send_cold_start(agent_addr="192.168.1.1")
    >>> trap_mgr.send_link_down(if_index=1, if_desc="eth0")
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Optional

from ber.object import ObjectIdentifier, Integer, OctetString, Null, Sequence

from snmp.datagram import SNMPDatagram
from snmp.pdus import PDU, Trap, SNMPv2Trap, InformRequest, Report
from snmp.notifications import decode_notification, TrapNotificationType
from snmp.enums import SNMPVersion
from snmp.statistics import get_statistics


# =============================================================================
# Trap Destinations
# =============================================================================

class TrapDestination:
    """A trap destination (management station).

    Attributes:
        host: IP address of the management station.
        port: UDP port (default 162).
        community: Community name for authentication.
        version: SNMP version (v1 by default).
    """

    def __init__(
        self,
        host: str,
        port: int = 162,
        community: str = "public",
        version: SNMPVersion = SNMPVersion.v1,
    ) -> None:
        """Initialize trap destination.

        Args:
            host: IP address of the management station.
            port: UDP port (default 162 for traps).
            community: Community name for authentication.
            version: SNMP version (v1 or v2c).
        """
        self.host = host
        self.port = port
        self.community = community
        self.version = version
        self._enabled: bool = True
        self._last_send_time: float = 0.0
        self._send_failures: int = 0

    @property
    def enabled(self) -> bool:
        """Whether this destination is enabled."""
        return self._enabled

    def enable(self) -> None:
        """Enable trap sending to this destination."""
        self._enabled = True

    def disable(self) -> None:
        """Disable trap sending to this destination."""
        self._enabled = False

    def record_send(self, success: bool) -> None:
        """Record a send attempt.

        Args:
            success: True if the send was successful.
        """
        self._last_send_time = time.time()
        if not success:
            self._send_failures += 1

    def reset_failures(self) -> None:
        """Reset failure counter."""
        self._send_failures = 0

    def __repr__(self) -> str:
        status = "enabled" if self._enabled else "disabled"
        return f"TrapDestination({self.host}:{self.port} [{status}])"


class TrapManager:
    """Manages trap destinations and trap generation.

    RFC 1157 §4.1.6 (Trap-PDU), RFC 1905 §2.10 (SNMPv2-Trap-PDU)

    Attributes:
        destinations: List of configured trap destinations.
        agent_addr: Agent's IP address for trap messages.
        enterprise: Enterprise OID for trap messages.
    """

    def __init__(
        self,
        agent_addr: str = "0.0.0.0",
        enterprise: str = "0",
    ) -> None:
        """Initialize trap manager.

        Args:
            agent_addr: Agent IP address used in trap messages.
            enterprise: Enterprise OID identifying the device.
        """
        self.destinations: list[TrapDestination] = []
        self.agent_addr = agent_addr
        self.enterprise = enterprise
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._stats = get_statistics()

    def set_transport(self, transport: asyncio.DatagramTransport) -> None:
        """Set the transport for sending traps.

        Args:
            transport: The UDP transport for sending traps.
        """
        self._transport = transport

    def add_destination(
        self,
        host: str,
        port: int = 162,
        community: str = "public",
        version: SNMPVersion = SNMPVersion.v1,
    ) -> TrapDestination:
        """Add a trap destination.

        Args:
            host: IP address of the management station.
            port: UDP port (default 162).
            community: Community name.
            version: SNMP version.

        Returns:
            The created TrapDestination.
        """
        dest = TrapDestination(host, port, community, version)
        self.destinations.append(dest)
        return dest

    def remove_destination(self, host: str) -> bool:
        """Remove a trap destination by host.

        Args:
            host: Host IP address to remove.

        Returns:
            True if found and removed.
        """
        for dest in self.destinations:
            if dest.host == host:
                self.destinations.remove(dest)
                return True
        return False

    def clear_destinations(self) -> None:
        """Remove all configured trap destinations."""
        self.destinations.clear()

    # ======================================================================
    # Trap Generation
    # ======================================================================

    def send_trap(
        self,
        pdu: Trap,
    ) -> None:
        """Send an SNMPv1 Trap-PDU to all configured destinations.

        Implements RFC 1157 §4.1.6.

        Args:
            pdu: The Trap-PDU to send.
        """
        if not self._transport:
            return

        stats = self._stats
        for dest in self.destinations:
            if not dest.enabled:
                continue

            try:
                datagram = SNMPDatagram(
                    version=Integer.from_int(0).get_object(),  # SNMPv1
                    community=OctetString(dest.community.encode()).get_object(),
                    pdu=pdu,
                )
                encoded = bytes(datagram)
                self._transport.sendto(encoded, (dest.host, dest.port))
                dest.record_send(success=True)
            except Exception:
                dest.record_send(success=False)
                stats.record_silent_drop()

        stats.record_trap_sent()

    def send_trap_v2(
        self,
        pdu: SNMPv2Trap,
    ) -> None:
        """Send an SNMPv2-Trap-PDU to all configured destinations.

        Implements RFC 1905 §2.10.

        Args:
            pdu: The SNMPv2-Trap-PDU to send.
        """
        if not self._transport:
            return

        stats = self._stats
        for dest in self.destinations:
            if not dest.enabled:
                continue

            try:
                # SNMPv2c uses version=1
                version_val = 1 if dest.version == SNMPVersion.v2c else 0
                datagram = SNMPDatagram(
                    version=Integer.from_int(version_val).get_object(),
                    community=OctetString(dest.community.encode()).get_object(),
                    pdu=pdu,
                )
                encoded = bytes(datagram)
                self._transport.sendto(encoded, (dest.host, dest.port))
                dest.record_send(success=True)
            except Exception:
                dest.record_send(success=False)
                stats.record_silent_drop()

        stats.record_trap_sent()

    # ======================================================================
    # Convenience Trap Generation Methods
    # ======================================================================

    def send_cold_start(
        self,
        variables: Optional[list[tuple[str, object]]] = None,
    ) -> Trap:
        """Generate and send a coldStart trap.

        coldStart (generic_trap=0) signifies that the SNMP entity is
        reinitializing itself and its configuration may have been altered.

        RFC 1157 §4.1.6.1

        Args:
            variables: Optional list of (oid, value) tuples for additional
                      variable bindings included in the trap.

        Returns:
            The generated Trap-PDU.
        """
        from snmp.smi import TimeTicks
        uptime = TimeTicks(int((time.time() % (2**32)) * 100))

        trap_vars = variables or []
        # Add sysUpTime and sysDescr by default
        trap_vars = [
            ("1.3.6.1.2.1.1.3", uptime),  # sysUpTime
            ("1.3.6.1.2.1.1.1", b"System rebooting"),  # sysDescr
        ] + trap_vars

        pdu = Trap.from_trap_type(
            trap_type=Trap.COLD_START,
            enterprise=self.enterprise,
            agent_addr=self.agent_addr,
            time_stamp=uptime.value if isinstance(uptime.value, int) else 0,  # type: ignore[arg-type]
            variables=trap_vars,
        )
        self.send_trap(pdu)
        return pdu

    def send_warm_start(
        self,
        variables: Optional[list[tuple[str, object]]] = None,
    ) -> Trap:
        """Generate and send a warmStart trap.

        warmStart (generic_trap=1) signifies that the SNMP entity is
        reinitializing itself but its configuration is unaltered.

        RFC 1157 §4.1.6.2

        Args:
            variables: Optional list of (oid, value) tuples.

        Returns:
            The generated Trap-PDU.
        """
        from snmp.smi import TimeTicks

        uptime = TimeTicks(int((time.time() % (2**32)) * 100))
        trap_vars = variables or []

        pdu = Trap.from_trap_type(
            trap_type=Trap.WARM_START,
            enterprise=self.enterprise,
            agent_addr=self.agent_addr,
            time_stamp=uptime.value if isinstance(uptime.value, int) else 0,  # type: ignore[arg-type]
            variables=trap_vars,
        )
        self.send_trap(pdu)
        return pdu

    def send_link_down(
        self,
        if_index: int = 1,
        if_desc: str = "unknown",
        variables: Optional[list[tuple[str, object]]] = None,
    ) -> Trap:
        """Generate and send a linkDown trap.

        linkDown (generic_trap=2) signifies that an interface went down.

        RFC 1157 §4.1.6.3

        Args:
            if_index: Interface index that went down.
            if_desc: Interface description.
            variables: Additional variable bindings.

        Returns:
            The generated Trap-PDU.
        """
        from snmp.smi import TimeTicks
        from snmp.mib import ifDescr, ifOperStatus

        uptime = TimeTicks(int((time.time() % (2**32)) * 100))
        trap_vars = variables or []

        # Add standard linkDown variables
        trap_vars = [
            ("1.3.6.1.2.1.1.3", uptime),  # sysUpTime
            (ifDescr, if_desc.encode()),  # ifDescr
            (ifOperStatus, b"\x02"),  # ifOperStatus = down(2)
        ] + trap_vars

        pdu = Trap.from_trap_type(
            trap_type=Trap.LINK_DOWN,
            enterprise=self.enterprise,
            agent_addr=self.agent_addr,
            time_stamp=uptime.value if isinstance(uptime.value, int) else 0,  # type: ignore[arg-type]
            variables=trap_vars,
        )
        self.send_trap(pdu)
        return pdu

    def send_link_up(
        self,
        if_index: int = 1,
        if_desc: str = "unknown",
        variables: Optional[list[tuple[str, object]]] = None,
    ) -> Trap:
        """Generate and send a linkUp trap.

        linkUp (generic_trap=3) signifies that an interface came up.

        RFC 1157 §4.1.6.4

        Args:
            if_index: Interface index that came up.
            if_desc: Interface description.
            variables: Additional variable bindings.

        Returns:
            The generated Trap-PDU.
        """
        from snmp.smi import TimeTicks
        from snmp.mib import ifDescr, ifOperStatus

        uptime = TimeTicks(int((time.time() % (2**32)) * 100))
        trap_vars = variables or []

        trap_vars = [
            ("1.3.6.1.2.1.1.3", uptime),  # sysUpTime
            (ifDescr, if_desc.encode()),  # ifDescr
            (ifOperStatus, b"\x01"),  # ifOperStatus = up(1)
        ] + trap_vars

        pdu = Trap.from_trap_type(
            trap_type=Trap.LINK_UP,
            enterprise=self.enterprise,
            agent_addr=self.agent_addr,
            time_stamp=uptime.value if isinstance(uptime.value, int) else 0,  # type: ignore[arg-type]
            variables=trap_vars,
        )
        self.send_trap(pdu)
        return pdu

    def send_authentication_failure(
        self,
        variables: Optional[list[tuple[str, object]]] = None,
    ) -> Trap:
        """Generate and send an authenticationFailure trap.

        authenticationFailure (generic_trap=4) signifies that an SNMP message
        could not be authenticated.

        RFC 1157 §4.1.6.5

        Only sent if snmpEnableAuthenTraps is enabled.

        Args:
            variables: Additional variable bindings.

        Returns:
            The generated Trap-PDU.
        """
        stats = self._stats
        if not stats.is_authen_traps_enabled():
            return Trap.from_trap_type(
                trap_type=Trap.AUTHENTICATION_FAILURE,
                enterprise=self.enterprise,
                agent_addr=self.agent_addr,
                variables=variables or [],
            )

        pdu = Trap.from_trap_type(
            trap_type=Trap.AUTHENTICATION_FAILURE,
            enterprise=self.enterprise,
            agent_addr=self.agent_addr,
            variables=variables or [],
        )
        self.send_trap(pdu)
        return pdu

    # ======================================================================
    # SNMPv2-Trap-PDU Convenience Methods
    # ======================================================================

    def send_cold_start_v2(
        self,
        variables: Optional[list[tuple[str, object]]] = None,
    ) -> SNMPv2Trap:
        """Generate and send a coldStart trap as SNMPv2-Trap-PDU.

        RFC 1905 §2.10

        Args:
            variables: List of (oid, value) tuples.

        Returns:
            The generated SNMPv2Trap-PDU.
        """
        from snmp.smi import TimeTicks
        uptime = TimeTicks(int((time.time() % (2**32)) * 100))

        trap_vars = variables or []
        trap_vars = [
            ("1.3.6.1.6.3.1.1.4.1.0.1", ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.1")),  # snmpTrapOID=coldStart
            ("1.3.6.1.2.1.1.3", uptime),  # sysUpTime
        ] + trap_vars

        var_bindings = Sequence.from_list([
            Sequence.from_list([
                oid if isinstance(oid, ObjectIdentifier) else ObjectIdentifier.from_string(oid).get_object(),
                val if isinstance(val, ObjectIdentifier) or isinstance(val, Integer) else OctetString(str(val).encode()).get_object(),
            ])
            for oid, val in trap_vars
        ])

        pdu = SNMPv2Trap(
            variable_bindings=var_bindings,
        )
        self.send_trap_v2(pdu)
        return pdu

    def send_link_down_v2(
        self,
        if_index: int,
        if_desc: str,
        variables: Optional[list[tuple[str, object]]] = None,
    ) -> SNMPv2Trap:
        """Generate and send a linkDown trap as SNMPv2-Trap-PDU.

        RFC 1905 §2.10

        Args:
            if_index: Interface index.
            if_desc: Interface description.
            variables: Additional variable bindings.

        Returns:
            The generated SNMPv2Trap-PDU.
        """
        from snmp.smi import TimeTicks
        uptime = TimeTicks(int((time.time() % (2**32)) * 100))

        trap_vars = variables or []
        trap_vars = [
            ("1.3.6.1.6.3.1.1.4.1.0.3", ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.3")),  # snmpTrapOID=linkDown
            ("1.3.6.1.2.1.1.3", uptime),  # sysUpTime
            ("1.3.6.1.2.1.2.2.1.2", if_desc.encode()),  # ifDescr
            ("1.3.6.1.2.1.2.2.1.8", b"\x02"),  # ifOperStatus = down
        ] + trap_vars

        var_bindings = Sequence.from_list([
            Sequence.from_list([
                oid if isinstance(oid, ObjectIdentifier) else ObjectIdentifier.from_string(oid).get_object(),
                val if isinstance(val, ObjectIdentifier) or isinstance(val, Integer) else OctetString(str(val).encode()).get_object(),
            ])
            for oid, val in trap_vars
        ])

        pdu = SNMPv2Trap(
            variable_bindings=var_bindings,
        )
        self.send_trap_v2(pdu)
        return pdu


# =============================================================================
# Trap Protocol — UDP Datagram Receiver
# =============================================================================

class TrapProtocol(asyncio.DatagramProtocol):
    """Asyncio DatagramProtocol for receiving SNMP trap datagrams.

    Buffers raw BER-encoded bytes and signals new data via asyncio.Event.
    """

    def __init__(self) -> None:
        """Initialize the trap protocol."""
        self.data: list[bytes] = []
        self.event = asyncio.Event()

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        """Handle received datagram.

        Args:
            data: Raw bytes received.
            addr: Source address (host, port).
        """
        self.data.append(data)
        self.event.set()

    def error_received(self, exc: Exception) -> None:
        """Handle error received.

        Args:
            exc: The exception that occurred.
        """
        print(f"  [TrapProtocol error: {exc}]")


# =============================================================================
# TrapReceptor — Abstract Base Class for Trap Reception
# =============================================================================

class TrapReceptor(ABC):
    """Abstract base class for SNMP trap receptors.

    Implements RFC 1157 Section 4.1.6 - Trap-PDU reception.
    Listens on UDP port 162 (the well-known port for SNMP traps).

    Subclasses MUST implement:
        - on_trap_received(pdu, source) — Trap notification callback for PDU objects

    Subclasses MAY override:
        - _on_datagram_received(datagram, source) — Hook for datagram-level processing
        - _format_trap_output(pdu) — Custom trap display formatting
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 162) -> None:
        """Initialize the trap receptor.

        Args:
            host: Bind address for the UDP listener.
            port: Bind port for the UDP listener.
        """
        self.host = host
        self.port = port
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional[TrapProtocol] = None
        self._last_processed_count: int = 0

    async def start(self) -> None:
        """Start the UDP listener.

        Concrete implementation shared by all TrapReceptor subclasses.
        Creates an asyncio DatagramEndpoint listening on (host, port).
        """
        loop = asyncio.get_event_loop()

        self._protocol = TrapProtocol()

        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                lambda: self._protocol,
                local_addr=(self.host, self.port),
            )
        except OSError as e:
            print(f"  [TrapReceptor bind failed: {e}]")
            print("  Another process may be listening on port 162.")
            return

        print(f"  Trap receptor listening on {self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop the UDP listener."""
        if self._transport:
            self._transport.close()
            self._transport = None

    async def receive_pdus(self, timeout: float = 2.0) -> list[PDU]:
        """Receive and decode trap PDUs that arrived since the last call.

        Args:
            timeout: Seconds to wait for PDUs before returning.

        Returns:
            List of decoded PDU objects (Trap, SNMPv2Trap, etc.).
        """
        if not self._protocol:
            return []

        # Use the last processed count so we only return new data.
        initial_count = self._last_processed_count

        # Wait for the event (data may have been added before this call).
        try:
            await asyncio.wait_for(self._protocol.event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

        received: list[PDU] = []
        for raw_data in self._protocol.data[initial_count:]:
            pdu = self._decode_pdu(raw_data)
            if pdu is not None:
                received.append(pdu)
                # Invoke the abstract hook for each received PDU
                self.on_trap_received(pdu, self.host)

        # Update the processed count so next call only gets newer data.
        self._last_processed_count = len(self._protocol.data)

        return received

    async def receive_notifications(self, timeout: float = 2.0) -> list[TrapNotificationType]:
        """Receive and decode typed notification data contracts.

        This is the preferred method for application code that wants structured
        notification data. It calls _decode_pdu and then decode_notification
        to produce typed notification dataclass instances.

        Args:
            timeout: Seconds to wait for PDUs before returning.

        Returns:
            List of typed notification dataclass instances
            (TrapNotification, SNMPv2Notification, InformNotification, ReportNotification).
        """
        if not self._protocol:
            return []

        initial_count = self._last_processed_count

        try:
            await asyncio.wait_for(self._protocol.event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

        notifications: list[TrapNotificationType] = []
        for raw_data in self._protocol.data[initial_count:]:
            pdu = self._decode_pdu(raw_data)
            if pdu is not None:
                notification = decode_notification(pdu, source=self.host, community="public")
                notifications.append(notification)
                # Call on_trap_received with the typed notification
                self.on_notification_received(notification, self.host)

        self._last_processed_count = len(self._protocol.data)

        return notifications

    # =========================================================================
    # New abstract method — on_notification_received (replaces on_trap_received)
    # =========================================================================

    def on_notification_received(self, notification: TrapNotificationType, source: str) -> None:
        """Handle a received SNMP notification as a typed data contract.

        This is the preferred abstract method for subclasses that want to work
        with structured notification data. The old `on_trap_received(pdu, source)`
        is kept for backward compatibility.

        Args:
            notification: A typed notification dataclass.
            source: Source IP address.
        """
        # Default: delegate to old interface for backward compat
        if isinstance(notification, Trap):
            self.on_trap_received(notification, source)
        # Subclasses can override this method to handle notifications

    # =========================================================================
    # Abstract method — MUST be implemented by subclasses
    # =========================================================================

    @abstractmethod
    def on_trap_received(self, pdu: PDU, source: str) -> None:
        """Handle a received SNMP trap PDU.

        This is the primary extension point for subclasses. Override to
        customize trap handling, logging, storage, or alerting behavior.

        Args:
            pdu: A decoded PDU object — Trap (SNMPv1) or SNMPv2Trap (SNMPv2c).
            source: Source IP address.
        """
        ...

    # =========================================================================
    # Hook methods — optional override by subclasses
    # =========================================================================

    def _decode_pdu(self, data: bytes) -> Optional[PDU]:
        """Decode raw bytes into an SNMP PDU.

        Default implementation uses SNMPDatagram.decode() to properly handle
        BER encoding, then extracts the PDU. Subclasses may override to
        customize decoding.

        Args:
            data: Raw SNMP datagram bytes.

        Returns:
            Decoded PDU object, or None on failure.
        """
        try:
            datagram = SNMPDatagram.decode(data)
        except Exception:
            return None

        return datagram.pdu

    def _format_trap_output(self, pdu: PDU) -> None:
        """Format and display trap PDU to the console.

        Default implementation prints formatted trap info. Subclasses
        may override to customize output (e.g., JSON logging, alerting).

        Uses Python's magic methods (__str__, __int__, __bool__) for value extraction.
        """
        trap_names = {
            0: "coldStart",
            1: "warmStart",
            2: "linkDown",
            3: "linkUp",
            4: "authenticationFailure",
            5: "egpNeighborLoss",
            6: "enterpriseSpecific",
        }

        if isinstance(pdu, Trap):
            trap_name = trap_names.get(int(pdu.generic_trap), "unknown")
            print(f"\n  Trap received (SNMPv1): {trap_name}")
        elif isinstance(pdu, SNMPv2Trap):
            print(f"\n  Trap received (SNMPv2c SNMPv2-Trap-PDU)")
        elif isinstance(pdu, InformRequest):
            print(f"\n  PDU received (SNMPv2c InformRequest): request_id={int(pdu.request_id)}")
        elif isinstance(pdu, Report):
            print(f"\n  PDU received (SNMPv2c Report): error_status={int(pdu.error_status)}")
        else:
            print(f"\n  PDU received: {type(pdu).__name__}")

        # Print variable bindings using magic methods for value extraction
        if pdu.variable_bindings and len(pdu.variable_bindings.value):
            print(f"    Variable Bindings ({len(pdu.variable_bindings.value)}):")
            for var_obj in pdu.variable_bindings.value:
                if var_obj is not None and var_obj.value is not None and len(var_obj.value) >= 2:
                    oid_obj = var_obj.value[0]
                    val_obj = var_obj.value[1]
                    oid_str = str(oid_obj) if oid_obj is not None else "unknown"
                    # Handle BER value extraction
                    # Use `is not None` — BER Objects with zero/null values are falsy
                    if val_obj is None:
                        value = "None"
                    elif isinstance(val_obj.value, bytes) and len(val_obj.value) == 0:
                        # Empty bytes = zero Integer (Integer.from_int(0))
                        value = "0"
                    elif isinstance(val_obj.value, int):
                        value = str(val_obj.value)
                    else:
                        try:
                            value = str(val_obj.value)
                        except Exception:
                            value = repr(val_obj)
                    print(f"      {oid_str} = {value}")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(host={self.host}, port={self.port})"


# =============================================================================
# Global Trap Manager
# =============================================================================

_trap_manager: Optional[TrapManager] = None


def get_trap_manager() -> TrapManager:
    """Get the global TrapManager singleton."""
    global _trap_manager
    if _trap_manager is None:
        _trap_manager = TrapManager()
    return _trap_manager


def reset_trap_manager() -> None:
    """Reset the global TrapManager singleton."""
    global _trap_manager
    _trap_manager = None
