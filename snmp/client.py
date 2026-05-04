"""Abstract base classes and concrete implementation for SNMP clients.

Provides:
- SNMPClient ABC with class-level defaults and concrete get/get_next/walk/set/send_trap()
- SNMPClientImpl concrete implementation (UDP transport with retries)

RFC 1157 §4.1 (Protocol Operations), RFC 1905 §2 (PDU Types), RFC 3416 §4.2
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Optional

from snmp.datagram import SNMPDatagram
from snmp.pdus import (
    GetRequest,
    GetNextRequest,
    SetRequest,
    Trap,
    GetBulkRequest,
    InformRequest,
    SNMPv2Trap,
)
from snmp.enums import SNMPVersion, ErrorStatus
from snmp.exceptions import SNMPTimeoutError, SNMPProtocolError, BERDecodeError
# Type aliases imported from snmp.types for documentation only
# VarBind, WalkResult, SNMPValue are defined in snmp/types.py
from ber.object import Integer, Object, ObjectIdentifier, OctetString, Null
from snmp.factories import make_var_bind, make_var_binds, _to_snmp_value as _to_snmp_value_factory

# ---------------------------------------------------------------------------
# Network error handling
# ---------------------------------------------------------------------------

# Tuple of exception classes for retry logic across all request methods.
# Each method catches these, retries up to self.retries, then returns
# None/false to signal failure.
_NETWORK_ERRORS = (
    SNMPTimeoutError,
    SNMPProtocolError,
    BERDecodeError,
    OSError,
    asyncio.TimeoutError,
)


class SNMPClient(ABC):
    """Abstract base class for SNMP clients.

    Class-level attributes define defaults — override them via inheritance
    instead of passing through ``__init__``. This makes creating custom or
    test clients straightforward:

    .. code-block:: python

        class TestClient(SNMPClient):
            community = "test"
            timeout = 0.5

            async def _send_receive(self, datagram, host, port):
                return b"mock response"

    Subclasses must implement ``_send_receive()`` to handle the UDP send/receive
    transport. All other methods (get, get_next, walk, set, send_trap) are
    concrete template methods built on top of ``_send_receive()``.

    RFC 1157 §4.1 (Protocol Operations), RFC 3416 §4.2 (PDU Operations)
    """

    # =========================================================================
    # Class-level configuration — override via inheritance
    # =========================================================================

    community: str = "public"
    """Community name for SNMP authentication."""

    version: SNMPVersion = SNMPVersion.v1
    """SNMP protocol version (v1 or v2c)."""

    timeout: float = 5.0
    """Request timeout in seconds."""

    retries: int = 3
    """Number of retries on timeout/failure."""

    # =========================================================================
    # Abstract method — MUST be implemented by subclasses
    # =========================================================================

    @abstractmethod
    async def _send_receive(
        self,
        datagram: SNMPDatagram,
        host: str,
        port: int,
    ) -> Optional[bytes]:
        """Send an SNMP datagram and receive the response.

        This is the core transport method that subclasses MUST implement.
        It handles UDP socket creation, datagram sending, response receiving,
        and error handling.

        Args:
            datagram: The SNMP datagram to send.
            host: Target host address.
            port: Target UDP port.

        Returns:
            Raw response bytes, or None on failure.
        """
        ...

    # =========================================================================
    # Concrete methods — built on top of _send_receive()
    # =========================================================================

    async def get(
        self,
        host: str,
        oid: str,
        port: int = 161,
    ) -> Optional[Object]:
        """Get a single OID value from an agent.

        Implements GetRequest-PDU (RFC 3416 §4.2.1).

        Args:
            host: Target host address.
            oid: Object Identifier to retrieve.
            port: UDP port (default 161).

        Returns:
            The value Object, or None on failure.
        """
        return await self._send_request(
            host, port, lambda: GetRequest.from_oid(oid)
        )

    async def get_next(
        self,
        host: str,
        oid: str,
        port: int = 161,
    ) -> Optional[Object]:
        """Get the lexicographic successor of an OID.

        Implements GetNextRequest-PDU (RFC 3416 §4.2.2).

        Args:
            host: Target host address.
            oid: Starting Object Identifier.
            port: UDP port (default 161).

        Returns:
            The next OID's value, or None on failure.
        """
        return await self._send_request(
            host, port, lambda: GetNextRequest.from_oid(oid)
        )

    async def walk(
        self,
        host: str,
        starting_oid: str,
        port: int = 161,
        stop_oid: Optional[str] = None,
    ) -> list[tuple[str, Object]]:
        """Walk a subtree of OIDs using GetNext requests.

        Implements GetNextRequest-PDU (RFC 3416 §4.2.2) iteratively.

        Args:
            host: Target host address.
            starting_oid: Starting OID.
            port: UDP port (default 161).
            stop_oid: Optional OID to stop at (subtree boundary).

        Returns:
            List of (oid_string, value) tuples.
        """
        results: list[tuple[str, Object]] = []
        current_oid = starting_oid

        while True:
            try:
                datagram = self._build_datagram(GetNextRequest.from_oid(current_oid))
                response_bytes = await self._send_receive(datagram, host, port)
                if response_bytes is None:
                    break

                resp_datagram = SNMPDatagram.decode(response_bytes)
                resp_pdu = resp_datagram.pdu

                # PDU IS a dict — iterate directly
                if not resp_pdu:
                    break

                # Get first item
                first_item = next(iter(resp_pdu.items()))
                oid_str = str(first_item[0])

                # Check if we've moved past the desired subtree
                if not oid_str.startswith(starting_oid):
                    break

                # Check if we've reached the end — server returned the same
                # OID it requested, meaning no successor exists
                if oid_str == current_oid:
                    break

                results.append((oid_str, first_item[1]))
                current_oid = oid_str

            except _NETWORK_ERRORS:
                break

        return results

    async def bulk_get(
        self,
        host: str,
        oids: list[str],
        non_repeaters: int = 0,
        max_repetitions: int = 10,
        port: int = 161,
    ) -> list[tuple[str, Object]]:
        """Bulk get multiple OIDs using GetBulkRequest-PDU.

        Implements GetBulkRequest-PDU (RFC 3416 §4.2.3). This method is optimized
        for efficient retrieval of large amounts of data, including entire MIB tables
        in a single request rather than multiple sequential GetNextRequest operations.

        Args:
            host: Target host address.
            oids: List of OIDs to retrieve.
            non_repeaters: Number of non-repeating OIDs (treated like GET operations).
            max_repetitions: Maximum number of repetitions per repeating OID.
            port: UDP port (default 161).

        Returns:
            List of (oid_string, value) tuples.

        Raises:
            SNMPTimeoutError: If no response is received within timeout.
            SNMPProtocolError: If the response cannot be parsed.
            BERDecodeError: If BER decoding fails.
        """
        for attempt in range(self.retries):
            try:
                # Build variable bindings for GetBulk using factory helper
                var_bind_array = make_var_binds(
                    [(oid, None) for oid in oids]
                )

                pdu = GetBulkRequest(
                    request_id=Integer.from_int(hash(self.community) & 0x7FFFFFFF).get_object(),
                    non_repeaters=Integer.from_int(non_repeaters).get_object(),
                    max_repetitions=Integer.from_int(max_repetitions).get_object(),
                    variable_bindings=var_bind_array,
                )

                response_bytes = await self._send_receive(
                    self._build_datagram(pdu), host, port
                )
                if response_bytes is None:
                    continue

                resp_datagram = SNMPDatagram.decode(response_bytes)
                resp_pdu = resp_datagram.pdu

                results: list[tuple[str, Object]] = []
                for oid, value in resp_pdu:
                    results.append((str(oid), value))

                return results

            except _NETWORK_ERRORS:
                if attempt < self.retries - 1:
                    continue
                return []

    async def set(
        self,
        host: str,
        oid: str,
        value: object,
        port: int = 161,
    ) -> bool:
        """Set a MIB value on an agent.

        Implements SetRequest-PDU (RFC 3416 §4.2.5).

        Args:
            host: Target host address.
            oid: Object Identifier to set.
            value: Value to set (int, str, bytes, or BER Object).
            port: UDP port (default 161).

        Returns:
            True if the set was successful.
        """
        for attempt in range(self.retries):
            try:
                # Build the variable binding using factory helper
                var_bind = make_var_bind(oid, value)

                pdu = SetRequest(variable_bindings=var_bind)

                response_bytes = await self._send_receive(
                    self._build_datagram(pdu), host, port
                )
                if response_bytes is None:
                    continue

                resp_datagram = SNMPDatagram.decode(response_bytes)
                resp_pdu = resp_datagram.pdu

                return int(resp_pdu.error_status) == ErrorStatus.no_error

            except _NETWORK_ERRORS:
                if attempt < self.retries - 1:
                    continue
                return False

    async def send_trap(
        self,
        host: str,
        trap_type: int = Trap.COLD_START,
        variables: Optional[list[tuple[str, object]]] = None,
        port: int = 162,
    ) -> bool:
        """Send a trap to a management station.

        Implements Trap-PDU (RFC 1157 §4.1.6) and SNMPv2-Trap-PDU (RFC 3416 §4.2.4).

        Args:
            host: Management station address.
            trap_type: Trap type constant (coldStart=0, warmStart=1, etc.).
            variables: List of (oid, value) tuples to include.
            port: UDP port (default 162).

        Returns:
            True if the trap was sent successfully.
        """
        try:
            if variables is None:
                variables = []

            if self.version == SNMPVersion.v2c or self.version == SNMPVersion.v3:
                # SNMPv2-trap-PDU
                trap = SNMPv2Trap.from_trap(
                    trap_type=trap_type,
                    variables=variables,
                    enterprise=ObjectIdentifier.from_string("1.3.6.1.2.1.1"),
                )
            else:
                # SNMPv1 Trap-PDU
                trap = Trap.from_trap_type(
                    trap_type=trap_type,
                    variables=variables,
                )

            await self._send_receive(self._build_datagram(trap), host, port)
            return True

        except _NETWORK_ERRORS:
            return False

    async def send_inform(
        self,
        host: str,
        trap_type: int,
        variables: Optional[list[tuple[str, object]]] = None,
        port: int = 162,
    ) -> bool:
        """Send an InformRequest-PDU (requires acknowledgment).

        Implements InformRequest-PDU (RFC 3416 §4.2.6).

        Args:
            host: Management station address.
            trap_type: Trap type identifier.
            variables: List of (oid, value) tuples.
            port: UDP port (default 162).

        Returns:
            True if acknowledgment received.
        """
        try:
            if variables is None:
                variables = []

            # Build variable bindings using factory helper
            var_bind_list = make_var_binds(variables)

            pdu = InformRequest(
                request_id=Integer.from_int(hash(self.community) & 0x7FFFFFFF).get_object(),
                variable_bindings=var_bind_list,
            )

            response_bytes = await self._send_receive(
                self._build_datagram(pdu), host, port
            )
            return response_bytes is not None

        except _NETWORK_ERRORS:
            return False

    # =========================================================================
    # Helper methods
    # =========================================================================

    def _build_datagram(self, pdu: Object) -> SNMPDatagram:
        """Build an SNMP datagram with configured version and community.

        This helper reduces boilerplate in every public method.  Each call
        constructs an SNMPDatagram containing the configured SNMP version,
        community string, and the provided PDU.

        RFC 1157 §4.1 (Protocol Operations), RFC 3416 §4.2 (PDU Operations)

        Args:
            pdu: The PDU object to wrap in a datagram.

        Returns:
            A fully configured SNMPDatagram instance.
        """
        return SNMPDatagram(
            version=Integer.from_int(self.version.value),
            community=OctetString(self.community.encode()).get_object(),
            pdu=pdu,
        )

    async def _send_request(
        self,
        host: str,
        port: int,
        pdu_factory,
    ) -> Optional[Object]:
        """Send an SNMP request with retry logic and return the first successful response.

        This is the core request helper used by ``get()`` and ``get_next()``.
        It handles:

        1. Building the datagram via ``pdu_factory()``
        2. Sending with retry logic on transient failures
        3. Decoding the response and extracting the first variable binding

        Args:
            host: Target host address.
            port: UDP port.
            pdu_factory: Callable that returns a PDU object (called once per retry).

        Returns:
            The value Object from the first variable binding, or None on failure.
        """
        for attempt in range(self.retries):
            try:
                datagram = self._build_datagram(pdu_factory())
                response_bytes = await self._send_receive(datagram, host, port)
                if response_bytes is None:
                    continue

                resp_datagram = SNMPDatagram.decode(response_bytes)
                resp_pdu = resp_datagram.pdu

                # Iterate over PDU directly (PDU IS a dict)
                for _, value in resp_pdu:
                    return value

                return None

            except _NETWORK_ERRORS:
                if attempt < self.retries - 1:
                    continue
                return None

    # Alias for shared value conversion logic from snmp.factories
    _to_snmp_value = _to_snmp_value_factory


class _SNMPClientProtocol(asyncio.DatagramProtocol):
    """Custom DatagramProtocol that captures received UDP data.

    This protocol is used by SNMPClientImpl to receive SNMP responses.
    It sets an event when data arrives so that ``_send_receive`` can wait.
    """

    def __init__(self) -> None:
        """Initialize the protocol."""
        self.response_data: list[bytes] = []
        self.response_event = asyncio.Event()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost."""
        self.response_event.set()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Called when a datagram is received.

        Args:
            data: Raw datagram bytes.
            addr: (host, port) of the sender.
        """
        self.response_data.append(data)
        self.response_event.set()

    def error_received(self, exc: Exception) -> None:
        """Called when an error occurs during receive."""
        self.response_event.set()