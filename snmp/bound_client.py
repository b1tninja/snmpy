"""Bound SNMP Client — wrapper around SNMPClient bound to a specific destination.

Provides:
- BoundSNMPClient — Wraps an SNMPClient instance, pre-configured with (host, port)
  so all operations no longer require passing host/port on every call.

RFC 1157 §4.1 (Protocol Operations), RFC 3416 §4.2 (PDU Operations)

Usage:
    >>> from snmp.client import SNMPClientImpl
    >>> from snmp.bound_client import BoundSNMPClient
    >>> client = BoundSNMPClient(SNMPClientImpl(), "192.168.1.1", 161)
    >>> result = await client.get("1.3.6.1.2.1.1.1.0")
"""

from __future__ import annotations

from typing import Any, Optional

from snmp.client import SNMPClient
from snmp.enums import SNMPVersion
from snmp.types import SNMPValue
from ber.object import Object, ObjectIdentifier


class BoundSNMPClient:
    """An SNMP client bound to a specific (host, port) destination.

    This wrapper allows you to configure an SNMPClient once with a target host
    and port, then perform all operations without repeating the destination.

    It acts as a transparent wrapper — all attributes from the underlying
    SNMPClient are accessible via property accessors.

    RFC 1157 §4.1 (Protocol Operations), RFC 3416 §4.2 (PDU Operations)

    Attributes:
        client: The underlying SNMPClient instance.
        host: Target host address.
        port: Target UDP port.
    """

    def __init__(
        self,
        client: SNMPClient,
        host: str,
        port: int = 161,
    ) -> None:
        """Initialize the bound client.

        Args:
            client: An SNMPClient instance (e.g., SNMPClientImpl).
            host: Target host address (e.g., "192.168.1.1").
            port: Target UDP port (default 161 for SNMP agents, 162 for traps).
        """
        self.client = client
        self.host = host
        self.port = port

    # =========================================================================
    # Property accessors — mirror from wrapped client
    # =========================================================================

    @property
    def community(self) -> str:
        """Community name for SNMP authentication."""
        return self.client.community

    @property
    def version(self) -> SNMPVersion:
        """SNMP protocol version (v1 or v2c)."""
        return self.client.version

    @property
    def timeout(self) -> float:
        """Request timeout in seconds."""
        return self.client.timeout

    @property
    def retries(self) -> int:
        """Number of retries on timeout/failure."""
        return self.client.retries

    # =========================================================================
    # Core SNMP operations
    # =========================================================================

    async def get(self, oid: str) -> Optional[Object]:
        """Get a single OID value from the agent.

        Equivalent to ``client.get(self.host, oid, self.port)``.

        Args:
            oid: Object Identifier to retrieve (e.g., "1.3.6.1.2.1.1.1.0").

        Returns:
            The value Object, or None on failure.
        """
        return await self.client.get(self.host, oid, self.port)

    async def get_next(self, oid: str) -> Optional[Object]:
        """Get the lexicographic successor of an OID.

        Equivalent to ``client.get_next(self.host, oid, self.port)``.

        Args:
            oid: Starting Object Identifier.

        Returns:
            The next OID's value, or None on failure.
        """
        return await self.client.get_next(self.host, oid, self.port)

    async def walk(
        self,
        starting_oid: str,
        stop_oid: Optional[str] = None,
    ) -> list[tuple[str, Object]]:
        """Walk a subtree of OIDs using GetNext requests.

        Equivalent to ``client.walk(self.host, starting_oid, self.port, stop_oid)``.

        Args:
            starting_oid: Starting OID.
            stop_oid: Optional OID to stop at (subtree boundary).

        Returns:
            List of (oid_string, value) tuples.
        """
        return await self.client.walk(self.host, starting_oid, self.port, stop_oid)

    async def bulk_get(
        self,
        oids: list[str],
        non_repeaters: int = 0,
        max_repetitions: int = 10,
    ) -> list[tuple[str, Object]]:
        """Bulk get multiple OIDs using GetBulkRequest-PDU.

        Equivalent to ``client.bulk_get(self.host, oids, ...)``.

        Args:
            oids: List of OIDs to retrieve.
            non_repeaters: Number of non-repeating OIDs.
            max_repetitions: Max repetitions per repeating OID.

        Returns:
            List of (oid_string, value) tuples.
        """
        return await self.client.bulk_get(
            self.host, oids, non_repeaters, max_repetitions, self.port,
        )

    async def set(self, oid: str, value: SNMPValue) -> bool:
        """Set a MIB value on the agent.

        Equivalent to ``client.set(self.host, oid, value, self.port)``.

        Args:
            oid: Object Identifier to set.
            value: Value to set (int, str, bytes, BER Object, etc.).

        Returns:
            True if the set was successful.
        """
        return await self.client.set(self.host, oid, value, self.port)

    async def send_trap(
        self,
        trap_type: int = 0,  # coldStart
        variables: Optional[list[tuple[str, SNMPValue]]] = None,
    ) -> bool:
        """Send a trap to the management station.

        Equivalent to ``client.send_trap(self.host, trap_type, variables, self.port)``.

        Args:
            trap_type: Trap type constant (coldStart=0, warmStart=1, etc.).
            variables: List of (oid, value) tuples to include.

        Returns:
            True if the trap was sent successfully.
        """
        return await self.client.send_trap(
            self.host, trap_type, variables, self.port,
        )

    async def send_inform(
        self,
        trap_type: int,
        variables: Optional[list[tuple[str, SNMPValue]]] = None,
    ) -> bool:
        """Send an InformRequest-PDU (requires acknowledgment).

        Equivalent to ``client.send_inform(self.host, trap_type, variables, self.port)``.

        Args:
            trap_type: Trap type identifier.
            variables: List of (oid, value) tuples.

        Returns:
            True if acknowledgment received.
        """
        return await self.client.send_inform(
            self.host, trap_type, variables, self.port,
        )

    # =========================================================================
    # Lifecycle
    # =========================================================================

    async def close(self) -> None:
        """Close the underlying client."""
        await self.client.close()

    # =========================================================================
    # Convenience
    # =========================================================================

    def __repr__(self) -> str:
        """String representation."""
        return f"BoundSNMPClient(client={self.client.__class__.__name__}, host={self.host!r}, port={self.port})"