"""SNMP protocol implementation using asyncio.

Implements RFC 1157 §4 (SNMPv1) and RFC 1905 (SNMPv2) Protocol Specifications
with UDP port enforcement.

SNMPv1 PDU types (RFC 1157): GetRequest, GetNextRequest, GetResponse, SetRequest, Trap
SNMPv2 PDU types (RFC 1905): GetBulkRequest, InformRequest, SNMPv2-Trap, Report

- Agents listen on UDP port 161 for requests/responses
- Agents listen on UDP port 162 for traps
- Authentication service validates community names (RFC 1157 §4.1, §8)
"""

from __future__ import annotations

import asyncio
import logging
import random as randint_mod
from typing import Any, Optional

import binascii

from ber.object import Object
from snmp import DEFAULT_PORT
from snmp.statistics import get_statistics
from snmp.datagram import SNMPDatagram
from snmp.mib import system, sysDescr
from snmp.pdus import (
    GetRequest,
    GetNextRequest,
    GetResponse,
    SetRequest,
    Trap,
    GetBulkRequest,
    InformRequest,
    SNMPv2Trap,
    Report,
)
from snmp.security import (
    AuthenticationError,
    get_authentication_service,
    MessageSizeLimit,
)
from snmp.mpm import MessageProcessor, SNMPv3Message
from snmp.enums import SNMPVersion
from snmp.exceptions import BERDecodeError, SNMPProtocolError
from snmp.vacm import VACMAccessControl

logger = logging.getLogger(__name__)

# RFC 1157 §4: UDP port assignments
SNMP_AGENT_PORT = 161  # All messages except traps
SNMP_TRAP_PORT = 162   # Trap messages only

# Default engine ID (RFC 3411 §5)
_DEFAULT_ENGINE_ID = b"\x00\x00\x00\x01\x01"


class ExceededRetries(Exception):
    """Raised when maximum retries are exceeded."""


class SNMPProtocol(asyncio.DatagramProtocol):
    """SNMP protocol handler using asyncio.
    
    RFC 1157 §4 (SNMPv1) and RFC 3412 §3 (SNMPv3 Message Processing):
    - Agents listen on UDP port 161 for requests/responses
    - Agents listen on UDP port 162 for traps
    - Message Processing Model dispatches incoming messages by version
    - VACM access control validates read/write access per community/user
    """

    def __init__(
        self,
        engine_id: bytes = _DEFAULT_ENGINE_ID,
        vacm: Optional[VACMAccessControl] = None,
    ) -> None:
        """Initialize SNMP protocol handler.
        
        Args:
            engine_id: SNMP engine ID for SNMPv3 (RFC 3411 §5).
            vacm: View-based Access Control model for access control.
        """
        self.transport: asyncio.DatagramTransport | None = None
        self.requests: dict[tuple[str, int], asyncio.Future[SNMPDatagram]] = {}
        self.engine_id: bytes = engine_id
        self._vacm: VACMAccessControl = vacm or VACMAccessControl()
        self._message_processor: Optional[MessageProcessor] = None

    @property
    def message_processor(self) -> MessageProcessor:
        """Get or create the MessageProcessor for SNMPv3.
        
        RFC 3412 §3: The MPM is responsible for processing incoming
        and outgoing SNMP messages based on the version.
        """
        if self._message_processor is None:
            from snmp.usm import USMUserDatabase
            self._message_processor = MessageProcessor(
                engine_id=self.engine_id,
                user_db=USMUserDatabase(),
            )
        return self._message_processor

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """Called when UDP socket is created."""
        self.transport = transport

    def get_version_from_datagram(self, data: bytes) -> SNMPVersion:
        """Detect the SNMP version from a datagram's version field.

        BER Objects (Integer, Object) implement __int__ so int() coercion
        works natively — no hasattr inspection needed.

        Args:
            data: Raw datagram bytes.

        Returns:
            The detected SNMP version.
        """
        try:
            obj, _ = Object.decode(data, 0)
            if hasattr(obj, 'value') and len(obj.value) >= 1:
                version_val = int(obj.value[0])  # Integer implements __int__
                if version_val == 0:
                    return SNMPVersion.v1
                elif version_val == 1:
                    return SNMPVersion.v2c
                elif version_val == 3:
                    return SNMPVersion.v3
        except (BERDecodeError, ValueError, TypeError):
            pass
        return SNMPVersion.v1

    def _process_incoming(self, data: bytes, addr: tuple[str, int]) -> SNMPDatagram:
        """Process incoming data through the MessageProcessor.
        
        RFC 3412 §3: The MPM processes incoming messages and determines
        which security model and message format to use.
        
        Args:
            data: Raw datagram bytes.
            addr: Source address.
            
        Returns:
            Decoded SNMPDatagram for v1/v2c, or SNMPv3Message for v3.
        """
        version = self.get_version_from_datagram(data)
        
        if version == SNMPVersion.v1:
            return self.message_processor.process_incoming(
                data, version, addr[0], addr[1]
            )
        elif version in (SNMPVersion.v2c, SNMPVersion.v2):
            return self.message_processor.process_incoming(
                data, version, addr[0], addr[1]
            )
        else:
            # SNMPv3 — decode through MPM
            msg = self.message_processor.process_incoming(
                data, version, addr[0], addr[1]
            )
            # Extract SNMPDatagram from SNMPv3Message for compatibility
            if isinstance(msg, SNMPv3Message) and msg.scoped_pdu and msg.scoped_pdu.pdu:
                # Create a synthetic datagram with the PDU for compatibility
                version_int = 3 if isinstance(msg, SNMPv3Message) else 0
                from snmp.pdus import GetRequest as GR
                if isinstance(msg.scoped_pdu.pdu, GR):
                    return SNMPDatagram(version=Integer.from_int(version_int).get_object(),
                                       community=OctetString(b"").get_object(),
                                       pdu=msg.scoped_pdu.pdu)
            return SNMPDatagram(version=Integer.from_int(version_int).get_object(),
                              community=OctetString(b"").get_object(),
                              pdu=msg.scoped_pdu.pdu if msg.scoped_pdu else None)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Called when a datagram is received.
        
        Implements RFC 1157 §4 port enforcement:
        - Messages on port 161: Standard request/response datagrams
        - Messages on port 162: Trap datagrams only
        - Message size enforcement per RFC 1157 §4 (484 octets)
        - Authentication service validation
        - Statistics tracking per RFC 1907 §2.2
        """
        host, port = addr
        stats = get_statistics()
        
        # RFC 1157 §4: Message size limit (484 octets)
        auth_service = get_authentication_service()
        if not auth_service.check_message_size(data):
            stats.record_silent_drop()
            logger.warning(
                "Message from %s exceeds size limit (%d > %d octets). "
                "Dropping.",
                host,
                len(data),
                auth_service.message_size_limit,
            )
            return
        
        # Port enforcement: validate correct port usage
        if port == SNMP_TRAP_PORT:
            # Port 162 should only receive Trap-PDU messages
            try:
                datagram = SNMPDatagram.decode(data)
                stats.increment_incoming()
                from snmp.pdus import Trap as TrapClass
                if not isinstance(datagram.pdu, TrapClass):  # type: ignore[union-attr]
                    logger.warning(
                        "Non-trap message received on trap port %s. "
                        "Dropping.",
                        host,
                    )
                    return
            except (BERDecodeError, SNMPProtocolError, UnicodeDecodeError):
                stats.record_asn_parse_error()
                logger.warning(
                    "BER decode failed for trap from %s on port %s: %s",
                    host,
                    port,
                    "malformed data",
                )
                return
        elif port == SNMP_AGENT_PORT or port > 1024:
            # Port 161 or ephemeral ports: standard request/response
            # Validate message is not a trap on agent port
            try:
                datagram = SNMPDatagram.decode(data)
                stats.increment_incoming()
                from snmp.pdus import Trap as TrapClass
                if isinstance(datagram.pdu, TrapClass):  # type: ignore[union-attr]
                    logger.warning(
                        "Trap received on agent port %d (use port %d). "
                        "Dropping.",
                        port,
                        SNMP_TRAP_PORT,
                    )
                    return
                # Track PDU type for statistics
                pdu = datagram.pdu  # type: ignore[union-attr]
                from snmp.pdus import GetRequest, GetNextRequest, SetRequest, GetBulkRequest
                if isinstance(pdu, GetRequest):
                    stats.record_get_request()
                elif isinstance(pdu, GetNextRequest):
                    stats.record_get_next_request()
                elif isinstance(pdu, SetRequest):
                    stats.record_set_request()
                elif isinstance(pdu, GetBulkRequest):
                    stats.record_get_next_request()  # Count GetBulk as GetNext
            except (BERDecodeError, SNMPProtocolError, UnicodeDecodeError):
                stats.record_asn_parse_error()
                logger.warning(
                    "BER decode failed for packet from %s on port %s: %s",
                    host,
                    port,
                    "malformed data",
                )
                return
            else:
                key = (host, int(datagram.pdu.request_id))  # type: ignore[union-attr]
                if key in self.requests:
                    try:
                        self.requests[key].set_result(datagram)
                    except asyncio.InvalidStateError:
                        del self.requests[key]
                else:
                    logger.debug(
                        "Unexpected SNMP datagram from %s: %s.", host, datagram
                    )
                    logger.debug("%s", self.requests)
        else:
            logger.warning(
                "Unexpected port %d from %s. "
                "SNMP uses ports 161 (requests) and 162 (traps).",
                port,
                host,
            )

    def error_received(self, exc: Exception) -> None:
        """Called when an error occurs."""
        logger.error(exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost."""
        if exc:
            logging.critical("UDP Socket closed: %s", exc)
        else:
            logging.critical("UDP Socket closed!")

    def sendto(
        self,
        datagram: SNMPDatagram,
        host: str,
        port: int = 161,
    ) -> asyncio.Future[SNMPDatagram]:
        """Send an SNMP datagram and return a Future for the response.

        Args:
            datagram: The SNMP datagram to send.
            host: Target host.
            port: Target port.

        Returns:
            A Future that resolves to the SNMP response.
        """
        assert isinstance(datagram, SNMPDatagram)
        encoded = bytes(datagram)
        response: asyncio.Future[SNMPDatagram] = asyncio.Future()
        key = (host, int(datagram.pdu.request_id))  # type: ignore[union-attr]
        self.requests[key] = response
        response.add_done_callback(
            lambda fn: self.requests.pop(key, None)
        )
        self.transport.sendto(encoded, (host, port))  # type: ignore[union-attr]
        return response

    async def get(
        self,
        host: str,
        oid: str = sysDescr,
        port: int = DEFAULT_PORT,
    ) -> SNMPDatagram:
        """Create a GetRequest PDU and return a Future.

        Args:
            host: Target host.
            oid: Object Identifier to get.
            port: Target port.

        Returns:
            A Future that resolves to the SNMP response.
        """
        pdu = GetRequest.from_oid(oid)
        datagram = SNMPDatagram(pdu=pdu)
        return await self.sendto(datagram, host, port)

    async def get_next(
        self,
        host: str,
        oid: str = system,
        port: int = DEFAULT_PORT,
    ) -> SNMPDatagram:
        """Create a GetNextRequest PDU and return a Future.

        Args:
            host: Target host.
            oid: Starting Object Identifier.
            port: Target port.

        Returns:
            A Future that resolves to the SNMP response.
        """
        pdu = GetNextRequest.from_oid(oid)
        datagram = SNMPDatagram(pdu=pdu)
        return await self.sendto(datagram, host, port)

    async def get_bulk(
        self,
        host: str,
        oids: list[str],
        non_repeaters: int = 0,
        max_repetitions: int = 256,
        port: int = DEFAULT_PORT,
        timeout: float = 10.0,
    ) -> list[tuple[str, Any]]:
        """Send a GetBulkRequest and collect the response.
        
        Implements RFC 1905 §4.2.3: GetBulkRequest-PDU processing.
        
        The GetBulkRequest-PDU enables managers to rapidly retrieve large
        amounts of data in a single request. It is especially efficient
        for retrieving large tables.
        
        Args:
            host: Target host.
            oids: List of OIDs to query. The first N OIDs are non-repeaters;
                  the remaining R OIDs are repeated up to M times.
            non_repeaters: Number of OIDs from the start that should return
                          at most one response each (like GetNext).
            max_repetitions: Maximum number of iterations for repeated OIDs.
                            For table walks, this controls how many rows
                            to retrieve per request.
            port: Target port.
            timeout: Request timeout in seconds.
        
        Returns:
            List of (oid, value) tuples from the response.
        
        Example:
            # Get 10 rows from ifTable
            results = await protocol.get_bulk(
                host="192.168.1.1",
                oids=["1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.10"],
                non_repeaters=0,
                max_repetitions=10,
            )
        """
        from snmp.pdus import GetBulkRequest as GBR
        from ber.object import Sequence, ObjectIdentifier, Null
        
        # Build the variable binding list for the request
        var_binds = Sequence.from_list(
            [
                Sequence.from_list([
                    ObjectIdentifier.from_string(oid).get_object() if isinstance(oid, str) else oid,
                    Null().get_object(),  # Request only the name, not the value
                ])
                for oid in oids
            ]
        )
        
        pdu = GetBulkRequest(
            non_repeaters=Integer.from_int(non_repeaters).get_object(),
            max_repetitions=Integer.from_int(max_repetitions).get_object(),
            variable_bindings=var_binds,
        )
        datagram = SNMPDatagram(pdu=pdu)
        
        response = await self.sendto(datagram, host, port)
        
        # Parse the response
        results: list[tuple[str, Any]] = []
        if isinstance(response.pdu, GetResponse):
            for var_bind in response.pdu.variable_bindings.value:  # type: ignore[union-attr]
                if len(var_bind.value) == 2:  # type: ignore[union-attr]
                    oid = var_bind.value[0].value  # type: ignore[union-attr]
                    value = var_bind.value[1]  # type: ignore[union-attr]
                    if isinstance(oid, ObjectIdentifier):
                        results.append((str(oid), value))
        
        return results

    async def walk(
        self,
        host: str,
        starting_oid: Optional[str] = None,
        port: int = DEFAULT_PORT,
        timeout: float = 10.0,
        max_initial_failures: int = 1,
        max_consequtive_failures: int = 3,
        use_walk_v2: bool = False,
    ) -> list[tuple[Any, Any]]:
        """Walk the MIB from the given starting OID.

        Args:
            host: Target host.
            starting_oid: Starting Object Identifier.
            port: Target port.
            timeout: Timeout in seconds for each request.
            max_initial_failures: Maximum initial failures before retry.
            max_consequtive_failures: Maximum consecutive failures before stop.

        Returns:
            A list of (oid, object) tuples.
        """
        responses: list[tuple[Any, Any]] = []
        attempts_remaining = max_initial_failures
        datagram = SNMPDatagram(pdu=GetNextRequest.from_oid(starting_oid))

        while attempts_remaining > 0:
            future = self.sendto(datagram, host, port)
            try:
                response = await asyncio.wait_for(future, timeout=timeout)
            except asyncio.TimeoutError:
                logger.debug(
                    "Timeout for GetNextRequest(%s, %s)",
                    host,
                    datagram.pdu.oid,  # type: ignore[union-attr]
                )
                if isinstance(attempts_remaining, int):
                    attempts_remaining -= 1
                continue

            assert isinstance(response.pdu, GetResponse)
            attempts_remaining = max_consequtive_failures
            logger.debug(
                "Response from host %s: %s=%s",
                host,
                response.pdu.oid,  # type: ignore[union-attr]
                response.pdu.response,  # type: ignore[union-attr]
            )

            if datagram.pdu.oid == response.pdu.oid:  # type: ignore[union-attr]
                # end of mib condition
                break

            responses.append((response.pdu.oid, response.pdu.response))  # type: ignore[union-attr]
            pdu = GetNextRequest.from_oid(response.pdu.oid)  # type: ignore[union-attr]
            datagram = SNMPDatagram(pdu=pdu)

        return responses

    async def walk_bulk(
        self,
        host: str,
        starting_oid: Optional[str] = None,
        port: int = DEFAULT_PORT,
        timeout: float = 10.0,
        max_repetitions: int = 256,
        max_iterations: int = 10000,
    ) -> list[tuple[Any, Any]]:
        """Walk the MIB using SNMPv2 GetBulkRequest for efficiency.
        
        Uses GetBulkRequest with non-repeaters=1 and max-repetitions=M to
        retrieve M rows per request. This is much more efficient than
        GetNextRequest for large table walks.
        
        RFC 1905 §4.2.3.1
        """
        from ber.object import ObjectIdentifier
        
        responses: list[tuple[Any, Any]] = []
        current_oid = starting_oid or system

        iteration = 0
        while iteration < max_iterations:
            iteration += 1

            # Send GetBulkRequest: non-repeaters=1, max-repetitions=M
            # First OID is the starting point, others are for repeated retrieval
            pdu = GetBulkRequest(
                non_repeaters=Integer.from_int(0).get_object(),
                max_repetitions=Integer.from_int(max_repetitions).get_object(),
                variable_bindings=Sequence.from_list(
                    [Sequence.from_list([
                        ObjectIdentifier.from_string(current_oid).get_object() if isinstance(current_oid, str) else current_oid,
                        Null().get_object(),
                    ])]
                ),
            )
            datagram = SNMPDatagram(pdu=pdu)
            datagram.pdu.request_id = Integer.from_int(randint(1 << 24, 1 << 31)).get_object()

            try:
                response = await asyncio.wait_for(
                    self.sendto(datagram, host, port),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.debug("Timeout for GetBulkRequest(%s, %s)", host, current_oid)
                break

            if not isinstance(response.pdu, GetResponse):
                logger.warning("Expected GetResponse for GetBulkRequest, got %s", type(response.pdu))
                break

            # Check for end of MIB condition
            found_data = False
            for var_bind in response.pdu.variable_bindings.value:  # type: ignore[union-attr]
                if len(var_bind.value) == 2:  # type: ignore[union-attr]
                    oid = var_bind.value[0].value  # type: ignore[union-attr]
                    value = var_bind.value[1]  # type: ignore[union-attr]
                    if isinstance(oid, ObjectIdentifier):
                        if hasattr(value, "tag") and hasattr(value.tag, "tag_id") and value.tag.tag_id == 2:  # endOfMibView
                            # Hit end of MIB for this branch
                            break
                        responses.append((oid, value))
                        found_data = True
                        current_oid = str(oid)

            if not found_data:
                break  # No more data

        return responses

    async def set(
        self,
        host: str,
        variables: list[tuple[str, Any]],
        port: int = DEFAULT_PORT,
    ) -> SNMPDatagram:
        """Create a SetRequest PDU and return a Future.
        
        Implements all-or-nothing semantics: either all variables are set,
        or none. The response's error-status indicates success or the type
        of error encountered.
        
        RFC 1157 §4.1.5

        Args:
            host: Target host.
            variables: List of (oid, value) tuples where value is an ASN.1 Object.
            port: Target port.

        Returns:
            A Future that resolves to the SNMP SetResponse.
            
        Raises:
            snmp.enums.ErrorStatus: If the response contains an error status.
        """
        from ber.object import Object, Sequence, ObjectIdentifier, Null
        from snmp.enums import ErrorStatus
        
        var_binds = Sequence.from_list(
            [
                Sequence.from_list([
                    oid if isinstance(oid, Object) else ObjectIdentifier.from_string(oid).get_object(),
                    value if isinstance(value, Object) else Null().get_object(),
                ])
                for oid, value in variables
            ]
        )
        pdu = SetRequest(variable_bindings=var_binds)
        datagram = SNMPDatagram(pdu=pdu)
        response = await self.sendto(datagram, host, port)
        
        # Validate the SetResponse for errors
        if isinstance(response.pdu, GetResponse):
            error_status = response.pdu.error_status.value  # type: ignore[union-attr]
            error_index = response.pdu.error_index.value  # type: ignore[union-attr]
            
            if error_status != ErrorStatus.no_error:
                # Map the integer error status back to the enum
                status = ErrorStatus(error_status)
                logger.error(
                    "SetRequest failed on %s: status=%s, error_index=%d",
                    host, status, error_index,
                )
                raise status
        
        return response

    async def send_trap(
        self,
        host: str,
        trap_type: int = Trap.COLD_START,
        enterprise: Optional[str] = None,
        agent_addr: Optional[str] = None,
        specific_code: int = 0,
        time_stamp: Optional[int] = None,
        variables: Optional[list[tuple[str, Any]]] = None,
        port: int = 162,
    ) -> SNMPDatagram:
        """Send a Trap-PDU to a management station.
        
        Traps are sent from the agent to the management station
        (not the reverse of request/response). They are asynchronous
        messages usually indicating some exceptional condition.
        
        RFC 1157 §4.1.6
        
        Args:
            host: Management station host to send trap to.
            trap_type: One of Trap.COLD_START(0), Trap.WARM_START(1),
                       Trap.LINK_DOWN(2), Trap.LINK_UP(3),
                       Trap.AUTHENTICATION_FAILURE(4), Trap.EGP_NEIGHBOR_LOSS(5),
                       or Trap.ENTERPRISE_SPECIFIC(6).
            enterprise: Object Identifier identifying the enterprise.
            agent_addr: IpAddress of the agent (interface that detected the trap).
            specific_code: Specific trap code for enterpriseSpecific traps.
            time_stamp: TimeTicks value (sysUpTime). If None, uses 0.
            variables: List of (oid_string, value) tuples for variable bindings.
            port: Target port (default 162 for traps).

        Returns:
            A Future that resolves to the SNMP datagram sent.
            Note: Traps are fire-and-forget; no response is expected.
        """
        trap = Trap.from_trap_type(
            trap_type=trap_type,
            enterprise=enterprise,
            agent_addr=agent_addr,
            specific_code=specific_code,
            time_stamp=time_stamp,
            variables=variables,
        )
        datagram = SNMPDatagram(pdu=trap)
        encoded = bytes(datagram)
        self.transport.sendto(encoded, (host, port))  # type: ignore[union-attr]
        # Traps are fire-and-forget - return immediately
        future: asyncio.Future[SNMPDatagram] = asyncio.Future()
        future.set_result(datagram)
        return await future
