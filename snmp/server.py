"""Abstract base classes for SNMP servers.

Provides:
- SNMPServer ABC with concrete handle_request(), start(), stop() methods
- Hook methods for subclasses: lookup_mib(), lookup_mib_next(), set_mib(), get_mib_keys()
- MockSNMPServer concrete implementation

RFC 1157 §4.1 (Protocol Entity), RFC 1901 §3 (Community-based Framework)
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Optional, Union

from snmp.datagram import SNMPDatagram
from snmp.pdus import (
    GetRequest,
    GetNextRequest,
    GetResponse,
    SetRequest,
    Trap,
    SNMPv2Trap,
    InformRequest,
    GetBulkRequest,
)
from snmp.enums import SNMPVersion, ErrorStatus
from snmp.handlers import (
    OIDHandler,
    StaticValueHandler,
    DynamicValueHandler,
    TableHandler,
    CounterHandler,
    CompoundHandler,
)
from snmp.mib_registry import MIBEntry, MIBRegistry
from snmp.security import CommunityDatabase, CommunityPolicy, AuthenticationService
from snmp.exceptions import BERDecodeError, SNMPProtocolError
from snmp.statistics import get_statistics
from snmp.traps import get_trap_manager, TrapManager
import logging

from ber.object import OctetString, Integer, ObjectIdentifier, Null, Sequence, Object

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type aliases for SNMP server operations
# ---------------------------------------------------------------------------

MibValue = object  # Any BER Object, bytes, int, str, or None


class SNMPServer(ABC):
    """Abstract base class for SNMP servers.

    Subclasses must implement:
    - lookup_mib(oid) — MIB value lookup by OID
    - lookup_mib_next(oid) — Lexicographic successor lookup
    - set_mib(oid, value) — MIB write operation
    - get_mib_keys() — All OID keys in the MIB

    Subclasses MAY override:
    - validate_community(community, source) — Authentication hook
    - get_response_version(datagram) — Version negotiation hook
    - _on_trap(pdu) — Trap notification callback
    """

    def __init__(self) -> None:
        """Initialize the SNMP server base.

        Creates a MIBRegistry instance for OID handler registration
        and a TrapManager for trap notifications.
        """
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._listened = False
        self.mib_registry: MIBRegistry = MIBRegistry()
        self._trap_mgr: Optional[TrapManager] = None
        self._trap_destinations: list[tuple[str, int, str]] = []

    # =========================================================================
    # Abstract methods — MUST be implemented by subclasses
    # =========================================================================

    @abstractmethod
    def lookup_mib(self, oid: str) -> Optional[object]:
        """Look up a MIB value by OID instance.

        Called by GetRequest handler (RFC 3416 §4.2.1).

        Args:
            oid: Full instance OID (e.g., "1.3.6.1.2.1.1.1.0").

        Returns:
            MIB value, or None if not found.
        """
        ...

    @abstractmethod
    def lookup_mib_next(self, oid: str) -> Optional[str]:
        """Find the lexicographic successor of an OID.

        Called by GetNextRequest handler (RFC 3416 §4.2.2).

        Args:
            oid: The OID to find successor for.

        Returns:
            The next OID in the MIB, or None.
        """
        ...

    @abstractmethod
    def set_mib(self, oid: str, value: object) -> bool:
        """Set a MIB value.

        Called by SetRequest handler (RFC 3416 §4.2.5).

        Args:
            oid: The OID to set.
            value: The value to set.

        Returns:
            True if successful, False otherwise.
        """
        ...

    @abstractmethod
    def get_mib_keys(self) -> list[str]:
        """Get all OIDs in the MIB.

        Called by Walk and by GetNext to enumerate successors.

        Returns:
            List of all OID strings in the MIB.
        """
        ...

    # =========================================================================
    # Convenience registration methods — can be overridden by subclasses
    # =========================================================================

    def _register_no_check(
        self,
        oid: str,
        handler: OIDHandler,
        access: str = "read",
        priority: int = 0,
    ) -> None:
        """Register without conflict checking (for internal use only)."""
        entry = MIBEntry(oid=oid, handler=handler, access=access, priority=priority)
        self.mib_registry._entries.append(entry)

    def register(
        self,
        oid: str,
        handler: OIDHandler,
        access: str = "read",
        priority: int = 0,
    ) -> None:
        """Register a handler for an OID.

        Convenience method that delegates to the MIBRegistry.

        Args:
            oid: The OID this handler is responsible for.
            handler: The OIDHandler instance.
            access: "read", "write", or "readwrite".
            priority: Higher priority wins on exact-match conflicts.
        """
        self._register_no_check(oid, handler, access=access, priority=priority)

    def register_static(
        self,
        oid: str,
        value: object,
        access: str = "read",
    ) -> StaticValueHandler:
        """Register a static (immutable) value.

        Args:
            oid: The OID for this static value.
            value: The constant value.
            access: Always set to "read".

        Returns:
            The created StaticValueHandler.
        """
        handler = StaticValueHandler(oid, value, access="read")
        self.register(oid, handler, access="read")
        return handler

    def register_dynamic(
        self,
        oid: str,
        getter: object,  # Callable[[str], object]
        setter: object = None,  # Optional[Callable[[str, object], bool]]
        access: str = "read",
    ) -> DynamicValueHandler:
        """Register a dynamically computed value.

        Args:
            oid: The OID for this dynamic value.
            getter: Callable(oid) -> value called on each GetRequest.
            setter: Optional callable(oid, value) -> bool called on SetRequest.
            access: "read" or "readwrite".

        Returns:
            The created DynamicValueHandler.
        """
        handler = DynamicValueHandler(oid, getter, setter, access=access)
        self.register(oid, handler, access=access)
        return handler

    def register_table(
        self,
        base_oid: str,
        rows: Optional[list[dict[str, object]]] = None,
        columns: Optional[list[str]] = None,
        access: str = "read",
    ) -> TableHandler:
        """Register a table handler.

        Args:
            base_oid: The base OID for the table.
            rows: List of row dictionaries.
            columns: Column names in order.
            access: "read" or "readwrite".

        Returns:
            The created TableHandler.
        """
        handler = TableHandler(base_oid, rows=rows, columns=columns, access=access)
        self.register(base_oid, handler, access=access)
        return handler

    def register_counter(
        self,
        oid: str,
        initial_value: int = 0,
        max_value: int = 0xFFFFFFFF,
        access: str = "read",
    ) -> CounterHandler:
        """Register a counter handler.

        Args:
            oid: The OID for this counter.
            initial_value: Starting counter value.
            max_value: Maximum value before wrapping.
            access: "read" (counters are typically read-only).

        Returns:
            The created CounterHandler.
        """
        handler = CounterHandler(oid, initial_value=initial_value, max_value=max_value, access=access)
        self.register(oid, handler, access=access)
        return handler

    def unregister(self, oid: str) -> bool:
        """Unregister a handler by OID.

        Args:
            oid: The OID to unregister.

        Returns:
            True if removed, False if not found.
        """
        return self.mib_registry.unregister(oid)

    def list_handlers(self) -> list[tuple[str, OIDHandler]]:
        """List all registered handlers.

        Returns:
            List of (oid, handler) tuples.
        """
        return self.mib_registry.list_handlers()

    def list_oids(self) -> list[str]:
        """List all registered OIDs."""
        return self.mib_registry.list_oids()

    def clear_mib(self) -> None:
        """Clear all registered handlers."""
        self.mib_registry.clear()

    # =========================================================================
    # Hook methods — optional override by subclasses
    # =========================================================================

    def validate_community(self, community: str, source: str = "127.0.0.1") -> bool:
        """Validate community name for authentication.

        Default implementation allows all communities. Override to
        implement community-based or user-based authentication.

        Args:
            community: Community name from the request.
            source: Source IP address.

        Returns:
            True if the community is valid.
        """
        return True

    def validate_access(
        self,
        community: str,
        oid: str,
        access: str,  # "read" or "write"
    ) -> bool:
        """Validate access permissions for an OID.

        Default implementation allows all access. Override to
        implement read/write access control per community.

        Args:
            community: Community name.
            oid: OID being accessed.
            access: "read" or "write".

        Returns:
            True if access is granted.
        """
        return True

    def get_response_version(self, datagram: SNMPDatagram) -> SNMPVersion:
        """Determine response version from request datagram.

        Default returns v1. Override for version-specific handling.

        Args:
            datagram: The request datagram.

        Returns:
            SNMPVersion for the response.
        """
        try:
            version_val = self._decode_version_value(datagram.version)
        except (ValueError, TypeError, AttributeError):
            return SNMPVersion.v1

        if version_val == 1:
            return SNMPVersion.v2c
        return SNMPVersion.v1

    def _on_trap(self, pdu: Object, source: str) -> None:
        """Callback invoked when a trap is received.

        Override to log traps, forward them, or trigger alerts.

        Args:
            pdu: The trap PDU (Trap, SNMPv2Trap, or InformRequest).
            source: Source IP address.
        """
        pass

    def _init_trap_manager(self) -> TrapManager:
        """Initialize the trap manager.

        Called from __init__ by subclasses. Subclasses may override to
        configure additional trap destinations or settings.

        Returns:
            The initialized TrapManager instance.
        """
        self._trap_mgr = get_trap_manager()
        return self._trap_mgr

    def get_trap_manager(self) -> Optional[TrapManager]:
        """Get the TrapManager for this server.

        Returns:
            The TrapManager instance, or None if not initialized.
        """
        return self._trap_mgr

    def _send_authentication_failure_trap(self, source: str, community: str) -> None:
        """Send an authenticationFailure trap when community validation fails.

        Per RFC 1157 §4.1.6.5 and RFC 3418 §6.7, when snmpEnableAuthenTraps is
        enabled (1.3.6.1.2.1.11.30), the server sends an authenticationFailure
        trap (1.3.6.1.6.3.1.1.4.1.0.5) to registered management stations when
        a request fails community validation.

        Args:
            source: Source IP address of the failed request.
            community: The community name that failed authentication.
        """
        if self._trap_mgr is None:
            return

        stats = get_statistics()
        if not stats.is_authen_traps_enabled():
            return

        from snmp.traps import get_trap_manager
        trap_mgr = get_trap_manager()
        if trap_mgr is None:
            return

        try:
            trap_mgr.send_authentication_failure(
                variables=[
                    ("1.3.6.1.2.1.1.1", f"Auth failure: community={community}".encode()),
                    ("1.3.6.1.2.1.4.3", source.encode()),
                ]
            )
        except (OSError, ValueError, TypeError, KeyError):
            logger.debug("Failed to send authenticationFailure trap: community=%s", community)

    # =========================================================================
    # Concrete template methods
    # =========================================================================

    def _extract_community(self, datagram: SNMPDatagram) -> str:
        """Extract community name from datagram.

        Per RFC 2576 §5.3: The community string is extracted from the
        SNMPDatagram and used to look up the matching snmpCommunityTable entry.
        BER Objects (OctetString, Object) implement __str__ so str() coercion
        works natively — no hasattr inspection needed.

        Returns:
            The community name as a string.
        """
        try:
            community = datagram.community
            # community is an OctetString/Object — use __str__ directly
            return str(community)
        except Exception:
            return "public"

    def _decode_version_value(self, version_obj: object) -> int:
        """Decode the SNMP version integer from a datagram's version field.

        BER Objects (Integer, Object) implement __int__ so int() coercion
        works natively — no hasattr inspection needed.

        Args:
            version_obj: The version field from an SNMPDatagram.

        Returns:
            The SNMP version number (0=v1, 1=v2c, 3=v3), or 0 on failure.
        """
        try:
            return int(version_obj)
        except (ValueError, TypeError):
            return 0

    def _normalize_value(self, val: object) -> Object:
        """Convert a raw Python value to a BER Object suitable for SNMP encoding.

        Type mapping (per RFC 1902 SMIV2):
          - Object → returned as-is
          - bytes → OctetString
          - int → Integer (Counter32, Gauge32, TimeTicks, Unsigned32)
          - str → OctetString
          - anything else → Null

        Args:
            val: Raw Python value (bytes, int, str) or BER Object.

        Returns:
            BER Object (OctetString, Integer, Null) or the original if already an Object.
        """
        if isinstance(val, Object):
            return val
        if isinstance(val, bytes):
            return OctetString(val).get_object()
        if isinstance(val, int):
            return Integer.from_int(val)
        if isinstance(val, str):
            return OctetString(val.encode()).get_object()
        return Null().get_object()

    def _build_response(
        self,
        request_id: object,
        variables: list[tuple[str, object]],
        error_status: ErrorStatus = ErrorStatus.no_error,
        error_index: int = 0,
        version: Optional[SNMPVersion] = None,
    ) -> GetResponse:
        """Build a GetResponse PDU from variables.

        Args:
            request_id: Request ID from the original request.
            variables: List of (oid, value) tuples. Values may be raw
                (bytes, int) or already BER Objects.
            error_status: Error status code.
            error_index: Error index (1-based).
            version: Optional version (uses first variable's OID version).

        Returns:
            A configured GetResponse PDU.
        """
        response_vars_obj = Sequence.from_list([
            Sequence.from_list([
                ObjectIdentifier.from_string(oid).get_object(),
                self._normalize_value(val),
            ])
            for oid, val in variables
        ])

        return GetResponse(
            request_id=request_id,
            error_status=Integer.from_int(error_status).get_object(),
            error_index=Integer.from_int(error_index).get_object(),
            variable_bindings=response_vars_obj,
        )

    def _encode_response(
        self,
        response_pdu: GetResponse,
        community: str,
        version: SNMPVersion,
    ) -> SNMPDatagram:
        """Encode a GetResponse PDU into an SNMPDatagram."""
        return SNMPDatagram(
            version=Integer.from_int(version.value),
            community=OctetString(community.encode()),
            pdu=response_pdu,
        )

    def handle_datagram(
        self,
        datagram: SNMPDatagram,
        source: str = "127.0.0.1",
    ) -> Optional[SNMPDatagram]:
        """Handle an SNMP request and produce a response.

        This is the main entry point for processing incoming SNMP requests.
        It validates the community, dispatches to the appropriate handler,
        and encodes the response.

        On community validation failure, sends an authenticationFailure trap
        if snmpEnableAuthenTraps is enabled (RFC 1157 §4.1.6.5).

        Args:
            datagram: The received SNMP datagram.
            source: Source IP address (for logging/hooks).

        Returns:
            Response SNMP datagram, or None if no response (e.g., trap).
        """
        # Extract and validate community
        community = self._extract_community(datagram)
        if not self.validate_community(community, source):
            # Send authenticationFailure trap if enabled
            self._send_authentication_failure_trap(source, community)
            # Track the bad community name
            get_statistics().record_bad_community_name()
            return None

        version = self.get_response_version(datagram)
        pdu = datagram.pdu

        # Dispatch by PDU type
        if isinstance(pdu, GetRequest):
            return self._handle_get(pdu, community, version)
        if isinstance(pdu, GetNextRequest):
            return self._handle_get_next(pdu, community, version)
        if isinstance(pdu, SetRequest):
            return self._handle_set(pdu, community, version)
        if isinstance(pdu, GetBulkRequest):
            return self._handle_get_bulk(pdu, community, version)
        if isinstance(pdu, Trap):
            self._handle_trap_v1(pdu, community, version, source)
            return None  # Traps are fire-and-forget
        if isinstance(pdu, SNMPv2Trap):
            self._handle_trap_v2(pdu, community, version, source)
            return None
        if isinstance(pdu, InformRequest):
            return self._handle_inform(pdu, community, version)

        return None

    def _handle_get(
        self,
        pdu: GetRequest,
        community: str,
        version: SNMPVersion,
    ) -> SNMPDatagram:
        """Handle GetRequest-PDU (RFC 3416 §4.2.1)."""
        response_vars: list[tuple[str, object]] = []

        for oid, value in pdu:
            oid_str = str(oid)

            if not self.validate_access(community, oid_str, "read"):
                response_vars.append((oid_str, Null().get_object()))
                continue

            mib_value = self.lookup_mib(oid_str)
            if mib_value is not None:
                response_vars.append((oid_str, mib_value))
            else:
                response_vars.append((oid_str, Null().get_object()))

        response_pdu = self._build_response(pdu.request_id, response_vars, version=version)
        return self._encode_response(response_pdu, community, version)

    def _handle_get_next(
        self,
        pdu: GetNextRequest,
        community: str,
        version: SNMPVersion,
    ) -> SNMPDatagram:
        """Handle GetNextRequest-PDU (RFC 3416 §4.2.2)."""
        response_vars: list[tuple[str, object]] = []

        for oid, _value in pdu:
            oid_str = str(oid)

            successor = self.lookup_mib_next(oid_str)
            if successor is not None:
                mib_value = self.lookup_mib(successor)
                if mib_value is not None:
                    response_vars.append((successor, mib_value))
                else:
                    response_vars.append((successor, Null().get_object()))
            else:
                response_vars.append((oid_str, Null().get_object()))

        response_pdu = self._build_response(pdu.request_id, response_vars, version=version)
        return self._encode_response(response_pdu, community, version)

    def _handle_set(
        self,
        pdu: SetRequest,
        community: str,
        version: SNMPVersion,
    ) -> SNMPDatagram:
        """Handle SetRequest-PDU (RFC 3416 §4.2.5)."""
        response_vars: list[tuple[str, object]] = []
        errors: list[tuple[str, ErrorStatus]] = []

        for oid, value_obj in pdu:
            oid_str = str(oid)
            value = value_obj

            if not self.validate_access(community, oid_str, "write"):
                errors.append((oid_str, ErrorStatus.read_only))
                continue

            if self.set_mib(oid_str, value):
                errors.append((oid_str, ErrorStatus.no_error))
            else:
                errors.append((oid_str, ErrorStatus.no_such_name))

            response_vars.append((oid_str, value))

        error_status = ErrorStatus.no_error
        error_index = 0
        for i, (oid, err) in enumerate(errors):
            if err != ErrorStatus.no_error:
                error_status = err
                error_index = i + 1
                break

        response_pdu = self._build_response(
            pdu.request_id, response_vars,
            error_status=error_status,
            error_index=error_index,
            version=version,
        )
        return self._encode_response(response_pdu, community, version)

    def _handle_get_bulk(
        self,
        pdu: GetBulkRequest,
        community: str,
        version: SNMPVersion,
    ) -> SNMPDatagram:
        """Handle GetBulkRequest-PDU (RFC 1905 §2.7, RFC 1906 §3)."""
        response_vars: list[tuple[str, object]] = []

        # non_repeaters and max_repetitions are Integer objects — use __int__ directly
        non_repeaters = int(pdu.non_repeaters)
        max_repetitions = int(pdu.max_repetitions)

        try:
            for i, (oid, _value) in enumerate(pdu):
                oid_str = str(oid)

                if i < non_repeaters:
                    # Non-repeater: treat like GET — return single successor
                    successor = self.lookup_mib_next(oid_str)
                    if successor is not None:
                        value = self.lookup_mib(successor)
                        if value is not None:
                            response_vars.append((successor, value))
                        else:
                            response_vars.append((successor, Null().get_object()))
                    else:
                        response_vars.append((oid_str, Null().get_object()))
                else:
                    # Repeater: repeat up to max_repetitions times
                    current_oid = oid_str
                    for _ in range(max_repetitions):
                        successor = self.lookup_mib_next(current_oid)
                        if successor is None:
                            break
                        value = self.lookup_mib(successor)
                        if value is not None:
                            response_vars.append((successor, value))
                            current_oid = successor
                        else:
                            response_vars.append((successor, Null().get_object()))
                            break
        except (OSError, ValueError, TypeError, KeyError):
            logger.debug("GetBulk PDU processing failed for community=%s", community)

        response_pdu = self._build_response(pdu.request_id, response_vars, version=version)
        return self._encode_response(response_pdu, community, version)

    def _handle_trap_v1(
        self,
        pdu: Trap,
        community: str,
        version: SNMPVersion,
        source: str,
    ) -> None:
        """Handle Trap-PDU. No response sent."""
        self._on_trap(pdu, source)

    def _handle_trap_v2(
        self,
        pdu: SNMPv2Trap,
        community: str,
        version: SNMPVersion,
        source: str,
    ) -> None:
        """Handle SNMPv2-Trap-PDU. No response sent."""
        self._on_trap(pdu, source)

    def _handle_inform(
        self,
        pdu: InformRequest,
        community: str,
        version: SNMPVersion,
    ) -> SNMPDatagram:
        """Handle InformRequest-PDU (RFC 3416 §4.2.7).

        InformRequest requires a GetResponse acknowledgment.
        """
        self._on_trap(pdu, "127.0.0.1")

        response_vars: list[tuple[str, object]] = []
        for oid, value in pdu:
            response_vars.append((str(oid), value))

        response_pdu = self._build_response(pdu.request_id, response_vars, version=version)
        return self._encode_response(response_pdu, community, version)

    async def start(self, host: str = "127.0.0.1", port: int = 1161) -> None:
        """Start the UDP listener.

        Concrete implementation shared by all SNMPServer subclasses.

        Args:
            host: Bind address.
            port: Bind port.
        """
        loop = asyncio.get_event_loop()

        class _ServerProtocol(asyncio.DatagramProtocol):
            def __init__(self, server: SNMPServer) -> None:
                self.server = server
                self.transport: Optional[asyncio.DatagramTransport] = None

            def connection_made(self, transport: asyncio.DatagramTransport) -> None:
                self.transport = transport

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                try:
                    logger.debug("datagram_received: %d bytes from %s", len(data), addr)
                    logger.debug("raw bytes: %s", data.hex())
                    datagram = SNMPDatagram.decode(data)
                    logger.debug("Decoded datagram: version=%s, community=%s, pdu=%s",
                                 datagram.version, datagram.community, datagram.pdu)
                    response = self.server.handle_datagram(datagram, source=addr[0])
                    if response is not None and self.transport:
                        # Send response back to the address that sent the request
                        self.transport.sendto(bytes(response), addr)
                        logger.debug("Response sent to %s", addr)
                except Exception as e:
                    logger.error("SNMP request error from %s: %s (type: %s, raw data: %s)",
                                 addr, e, type(e).__name__, data.hex())

        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _ServerProtocol(self),
            local_addr=(host, port),
        )
        self._listened = True

    async def stop(self) -> None:
        """Stop the UDP listener."""
        if self._transport:
            self._transport.close()
            self._transport = None
            self._listened = False

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(mib_size={len(self.get_mib_keys())})"


class MockSNMPServer(SNMPServer):
    """Mock SNMP agent for testing with registration-based MIB.

    Uses MIBRegistry internally to dispatch requests to registered handlers.
    Supports SNMPv1 and SNMPv2c community-based authentication.

    RFC 1157 §4.1 (Protocol Entity), RFC 1901 §3 (Community-based Framework)
    """

    def __init__(
        self,
        community: str = "public",
        community_rw: str = "private",
        port: int = 1161,
        device_type: str = "Mock SNMP Device v0.1",
        trap_destinations: Optional[list[tuple[str, int, str]]] = None,
    ) -> None:
        """Initialize the mock SNMP server.

        Args:
            community: Read-only community name (SNMPv1/v2c).
            community_rw: Read-write community name (SNMPv1/v2c).
            port: UDP port to listen on.
            device_type: Device description for sysDescr.
            trap_destinations: List of (host, port, community) tuples for trap targets.
        """
        super().__init__()
        self.port = port
        self.device_type = device_type
        self._trap_destinations = trap_destinations

        # Build community database
        self._build_community_db(community, community_rw)

        # Track server start time for sysUpTime
        self._start_time: float = 0.0
        self._sys_contact: str = "root@localhost"
        self._contact_setter_called: bool = False
        self._sys_contact_oids: dict[str, str] = {"1.3.6.1.2.1.1.4.0": self._sys_contact}

        # Initialize MIB with default entries using registration system
        self._init_mib()

        # Initialize trap manager
        self._trap_mgr = get_trap_manager()
        self._trap_mgr.agent_addr = device_type if device_type else "0.0.0.0"
        self._trap_mgr.enterprise = "0"

        # Configure trap destinations if provided
        if trap_destinations:
            for dest in trap_destinations:
                if len(dest) == 3:
                    self._trap_mgr.add_destination(dest[0], dest[1], dest[2])
                elif len(dest) == 2:
                    self._trap_mgr.add_destination(dest[0], dest[1])

    def _init_mib(self) -> None:
        """Initialize the MIB with real system information using handlers.

        Uses:
        - DynamicValueHandler for dynamic scalar values (sysUpTime, sysName)
        - EnumerableHandler for table-based data (ifTable)
        - CounterHandler for snmpGroup statistics (RFC 1907 §2.2)

        The EnumerableHandler uses lazy iteration — get_next() returns the
        next OID in lexicographic order, enabling clients to enumerate
        interfaces one at a time via GetNextRequest.
        """
        # Import providers
        try:
            from snmp.providers import SystemInfoProvider, NetworkInterfaceProvider
        except ImportError:
            from snmp.server import SystemInfoProvider, NetworkInterfaceProvider

        # ── System Group (RFC 1156) ──────────────────────────────────────

        # sysUpTime — dynamic scalar (computed at request time)
        self._sys_info = SystemInfoProvider()
        self._register_no_check(
            "1.3.6.1.2.1.1.3",
            DynamicValueHandler(
                "1.3.6.1.2.1.1.3",
                getter=lambda oid: self._sys_info.get_sys_up_time(),
                access="read",
            ),
        )

        # sysName — dynamic scalar (real hostname)
        self._register_no_check(
            "1.3.6.1.2.1.1.5",
            DynamicValueHandler(
                "1.3.6.1.2.1.1.5",
                getter=lambda oid: self._sys_info.get_sys_name(),
                access="read",
            ),
        )

        # sysDescr — dynamic scalar (real platform info)
        self.register_static(
            "1.3.6.1.2.1.1.1",
            self._sys_info.get_sys_descr(),
            access="read",
        )

        # sysContact — handled via direct storage in lookup_mib/set_mib
        # sysLocation — static
        self.register_static("1.3.6.1.2.1.1.6", self._sys_info.get_sys_location(), access="read")

        # ── SNMP Group (RFC 1907 §2.2) — Statistics Counters ────────────
        # These are wired to the global statistics singleton so they reflect
        # actual SNMP protocol activity tracked in snmp/statistics.py.
        stats = get_statistics()

        # Inbound counters (RFC 1907 snmpGroup — snmpIn*)
        self.register_static("1.3.6.1.2.1.11.1", stats.snmp_in_pkts.get, access="read")  # snmpInPkts
        self.register_static("1.3.6.1.2.1.11.3", stats.snmp_in_bad_versions.get, access="read")  # snmpInBadVersions
        self.register_static("1.3.6.1.2.1.11.4", stats.snmp_in_bad_community_names.get, access="read")  # snmpInBadCommunityNames
        self.register_static("1.3.6.1.2.1.11.5", stats.snmp_in_bad_community_uses.get, access="read")  # snmpInBadCommunityUses
        self.register_static("1.3.6.1.2.1.11.6", stats.snmp_in_asn_parse_errs.get, access="read")  # snmpInASNParseErrs

        # Outbound counters (RFC 1907 snmpOut*)
        self.register_static("1.3.6.1.2.1.11.20", stats.snmp_out_too_bigs.get, access="read")  # snmpOutTooBigs
        self.register_static("1.3.6.1.2.1.11.21", stats.snmp_out_no_such_names.get, access="read")  # snmpOutNoSuchNames
        self.register_static("1.3.6.1.2.1.11.22", stats.snmp_out_bad_values.get, access="read")  # snmpOutBadValues
        self.register_static("1.3.6.1.2.1.11.24", stats.snmp_out_gen_errs.get, access="read")  # snmpOutGenErrs
        self.register_static("1.3.6.1.2.1.11.25", stats.snmp_out_get_requests.get, access="read")  # snmpOutGetRequests
        self.register_static("1.3.6.1.2.1.11.26", stats.snmp_out_get_nexts.get, access="read")  # snmpOutGetNexts
        self.register_static("1.3.6.1.2.1.11.27", stats.snmp_out_set_requests.get, access="read")  # snmpOutSetRequests
        self.register_static("1.3.6.1.2.1.11.28", stats.snmp_out_get_responses.get, access="read")  # snmpOutGetResponses
        self.register_static("1.3.6.1.2.1.11.29", stats.snmp_out_traps.get, access="read")  # snmpOutTraps

        # Control: snmpEnableAuthenTraps
        # We use a DynamicValueHandler since this needs getter/setter
        self.register(
            "1.3.6.1.2.1.11.30",
            DynamicValueHandler(
                "1.3.6.1.2.1.11.30",
                getter=lambda oid: stats._snmp_enable_authen_traps.get(),
                setter=lambda oid, val: (stats.set_authen_traps_enabled(val == 1), 1 if val == 1 else 2)[1],
                access="readwrite",
            ),
        )

        # RFC 3418 framework statistics (SNMPv3)
        self.register_static("1.3.6.1.6.3.10.1.3.1", stats.snmp_unknown_security_levels.get, access="read")
        self.register_static("1.3.6.1.6.3.10.1.3.2", stats.snmp_invalid_msgs.get, access="read")
        self.register_static("1.3.6.1.6.3.10.1.3.3", stats.snmp_sec_failed_snmp_entities.get, access="read")

        # ── Interfaces Group (RFC 1156/1212) ─────────────────────────────

        # ifNumber — actual interface count
        rows = self._build_interface_rows()
        self.register_static("1.3.6.1.2.1.2.1", len(rows), access="read")

        # ifTable — EnumerableHandler with lazy iteration
        columns: dict[str, str] = {
            "ifDescr": ".2",
            "ifType": ".3",
            "ifMtu": ".4",
            "ifSpeed": ".9",
            "ifPhysAddress": ".6",
            "ifAdminStatus": ".7",
            "ifOperStatus": ".8",
            "ifLastChange": ".10",
            "ifInOctets": "10",
            "ifOutOctets": ".14",
            "ifInUcastPkts": ".11",
            "ifOutUcastPkts": ".15",
            "ifInNUcastPkts": ".12",
            "ifInDiscards": ".13",
            "ifOutDiscards": ".16",
            "ifInErrors": ".17",
            "ifOutErrors": ".18",
        }

        from snmp.handlers import EnumerableHandler
        self._if_table_handler = EnumerableHandler(
            base_oid="1.3.6.1.2.1.2.2.1",
            items=rows,
            columns=columns,
            access="read",
        )

    def _build_interface_rows(self) -> list[dict[str, object]]:
        """Build interface rows for the ifTable.

        Returns:
            List of dicts with keys matching the columns dict.
        """
        rows: list[dict[str, object]] = []

        # Try psutil for real system data
        try:
            import psutil
        except ImportError:
            rows = self._get_fallback_interfaces()
            return rows

        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except (OSError, ImportError, AttributeError):
            rows = self._get_fallback_interfaces()
            return rows

        import socket as _socket
        import time as _time

        index = 0
        for name in sorted(addrs.keys()):
            index += 1
            try:
                stat = stats.get(name, None)
                if stat is None:
                    continue

                # Skip loopback for ifTable rows
                if stat.loopback:
                    continue

                addr_list = addrs.get(name, [])

                # Detect type
                lower = name.lower()
                if "loopback" in lower or "lo" == lower:
                    type_ = 24  # softwareLoopback
                elif "ethernet" in lower or "eth" in lower or "net" in lower:
                    type_ = 6  # ethernetCsmacd
                elif "wi-fi" in lower or "wlan" in lower:
                    type_ = 6
                else:
                    type_ = 6  # default

                # Get MAC and IP
                mac = ""
                ip = ""
                for addr in addr_list:
                    if addr.family == _socket.AF_LINK:
                        mac = addr.address
                    elif addr.family in (_socket.AF_INET, _socket.AF_INET6):
                        ip = addr.address

                is_up = stat.is_up and not stat.loopback
                admin_status = 1 if is_up else 2
                oper_status = 1 if is_up else 2

                speed = 0
                if hasattr(stat, 'speed') and stat.speed:
                    speed = stat.speed * 1_000_000

                mtu = stat.mtu if hasattr(stat, 'mtu') else 1500

                rows.append({
                    "ifDescr": name,
                    "ifType": type_,
                    "ifMtu": mtu,
                    "ifSpeed": speed,
                    "ifPhysAddress": mac,
                    "ifAdminStatus": admin_status,
                    "ifOperStatus": oper_status,
                    "ifLastChange": 0,
                    "ifInOctets": 0,
                    "ifOutOctets": 0,
                    "ifInUcastPkts": 0,
                    "ifOutUcastPkts": 0,
                    "ifInNUcastPkts": 0,
                    "ifInDiscards": 0,
                    "ifOutDiscards": 0,
                    "ifInErrors": 0,
                    "ifOutErrors": 0,
                })

            except (OSError, AttributeError, KeyError, TypeError):
                continue

        if not rows:
            rows = self._get_fallback_interfaces()

        return rows

    def _get_fallback_interfaces(self) -> list[dict[str, object]]:
        """Fallback interface data when psutil is not available."""
        import socket as _socket  # noqa: F811
        try:
            hostname = _socket.gethostname()
        except (OSError, AttributeError):
            hostname = "unknown"
        return [{
            "ifDescr": hostname,
            "ifType": 24,  # softwareLoopback
            "ifMtu": 65536,
            "ifSpeed": 0,
            "ifPhysAddress": "",
            "ifAdminStatus": 1,
            "ifOperStatus": 1,
            "ifLastChange": 0,
            "ifInOctets": 0,
            "ifOutOctets": 0,
            "ifInUcastPkts": 0,
            "ifOutUcastPkts": 0,
            "ifInNUcastPkts": 0,
            "ifInDiscards": 0,
            "ifOutDiscards": 0,
            "ifInErrors": 0,
            "ifOutErrors": 0,
        }]

    def _build_community_db(
        self,
        ro_community: str,
        rw_community: str,
    ) -> None:
        """Build the community database with read-only and read-write communities."""
        self._db = CommunityDatabase()

        ro_policy = CommunityPolicy(
            name=ro_community,
            read_only=["*"],
            read_write=[],
        )
        self._db.add_policy(ro_policy)

        rw_policy = CommunityPolicy(
            name=rw_community,
            read_write=["1.3.6.1.2.1"],
        )
        self._db.add_policy(rw_policy)

        self._auth = AuthenticationService()
        self._start_time = 0.0  # Will be set by start()

    def _set_contact(self, value: object) -> bool:
        """Set sysContact value."""
        if isinstance(value, bytes):
            self._sys_contact = value.decode('utf-8', errors='replace')
        elif isinstance(value, str):
            self._sys_contact = value
        self._contact_setter_called = True
        return True

    @property
    def _mib(self) -> dict:
        """Backward compat property for old test code."""
        return {}

    # =========================================================================
    # Abstract method implementations
    # =========================================================================

    def lookup_mib(self, oid: str) -> Optional[object]:
        """Look up a MIB value by OID instance via MIBRegistry + table handler."""
        # Check direct storage first for sysContact
        if oid in self._sys_contact_oids:
            return self._sys_contact_oids[oid].encode()

        # Check if-table handler for table lookups
        if hasattr(self, '_if_table_handler'):
            result = self._if_table_handler.get(oid)
            if result is not None:
                return result

        return self.mib_registry.lookup(oid)

    def lookup_mib_next(self, oid: str) -> Optional[str]:
        """Find the lexicographic successor of an OID via MIBRegistry + table handler."""
        # Check if-table handler for table lookups first
        if hasattr(self, '_if_table_handler'):
            result = self._if_table_handler.get_next(oid)
            if result is not None:
                return result

        return self.mib_registry.lookup_next(oid)

    def set_mib(self, oid: str, value: object) -> bool:
        """Set a MIB value by OID via MIBRegistry."""
        # Handle sysContact directly
        if oid in self._sys_contact_oids:
            self._set_contact(value)
            self._sys_contact_oids[oid] = self._sys_contact
            return True
        set_result = self.mib_registry.get_set_handler(oid, "private")
        if set_result is None:
            return False
        handler, error_status = set_result
        if error_status != ErrorStatus.no_error:
            return False
        status = handler.set(oid, value)
        return status == ErrorStatus.no_error

    def get_mib_keys(self) -> list[str]:
        """Get all OIDs in the MIB via MIBRegistry + table handler + direct storage."""
        keys = self.mib_registry.list_oids()
        # Add sysContact
        for oid in self._sys_contact_oids:
            if oid not in keys:
                keys.append(oid)
        # Add if-table cells
        if hasattr(self, '_if_table_handler'):
            cells = self._if_table_handler.get_all_cells()
            for oid, _ in cells:
                if oid not in keys:
                    keys.append(oid)
        return keys

    # =========================================================================
    # Hook overrides
    # =========================================================================

    def validate_community(self, community: str, source: str = "127.0.0.1") -> bool:
        """Validate community against the community database."""
        try:
            self._auth.validate_community(community, source)
            return True
        except Exception:
            return False

    def validate_access(
        self,
        community: str,
        oid: str,
        access: str,
    ) -> bool:
        """Check if community has read/write access to this OID."""
        try:
            policy = self._db.get_policy(community)
            if policy is None:
                return False

            if access == "read":
                allowed = policy.read_only
            else:
                allowed = policy.read_write

            if "*" in allowed:
                return True

            for prefix in allowed:
                if oid.startswith(prefix):
                    return True
            return False
        except Exception:
            return False

    def get_response_version(self, datagram: SNMPDatagram) -> SNMPVersion:
        """Determine response version from the request datagram."""
        try:
            version_val = self._decode_version_value(datagram.version)
        except Exception:
            return SNMPVersion.v1

        if version_val == 1:
            return SNMPVersion.v2c
        return SNMPVersion.v1

    def _on_trap(self, pdu: Object, source: str) -> None:
        """Log trap notifications."""
        print(f"SNMP trap received from {source}: {pdu}")

    def get_trap_manager(self) -> Optional[TrapManager]:
        """Get the TrapManager for this server.

        Returns:
            The TrapManager instance.
        """
        return self._trap_mgr

    def __repr__(self) -> str:
        return f"MockSNMPServer(port={self.port}, mib_size={len(self.get_mib_keys())})"

    # =========================================================================
    # Convenience methods for backward compatibility
    # =========================================================================

    def get_mib_value(self, oid: str) -> Optional[object]:
        """Get a MIB value by OID. Convenience wrapper for lookup_mib."""
        return self.lookup_mib(oid)

    def set_mib_value(self, oid: str, value: object) -> bool:
        """Set a MIB value by OID. Convenience wrapper for set_mib."""
        return self.set_mib(oid, value)

    def _find_next_oid(self, oid: str) -> Optional[str]:
        """Find lexicographic successor. Alias for lookup_mib_next."""
        return self.lookup_mib_next(oid)