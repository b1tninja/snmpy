"""Type stub for snmp.bound_client module."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from snmp.enums import SNMPVersion
from snmp.types import SNMPValue

if TYPE_CHECKING:
    from snmp.client import SNMPClient
    from ber.object import Object


class BoundSNMPClient:
    """An SNMP client bound to a specific (host, port) destination."""

    client: SNMPClient
    host: str
    port: int

    def __init__(
        self,
        client: SNMPClient,
        host: str,
        port: int = 161,
    ) -> None:
        """Initialize the bound client."""
        ...

    @property
    def community(self) -> str:
        """Community name for SNMP authentication."""
        ...

    @property
    def version(self) -> SNMPVersion:
        """SNMP protocol version (v1 or v2c)."""
        ...

    @property
    def timeout(self) -> float:
        """Request timeout in seconds."""
        ...

    @property
    def retries(self) -> int:
        """Number of retries on timeout/failure."""
        ...

    async def get(self, oid: str) -> Optional[Object]:
        """Get a single OID value from the agent."""
        ...

    async def get_next(self, oid: str) -> Optional[Object]:
        """Get the lexicographic successor of an OID."""
        ...

    async def walk(
        self,
        starting_oid: str,
        stop_oid: Optional[str] = None,
    ) -> list[tuple[str, Object]]:
        """Walk a subtree of OIDs using GetNext requests."""
        ...

    async def bulk_get(
        self,
        oids: list[str],
        non_repeaters: int = 0,
        max_repetitions: int = 10,
    ) -> list[tuple[str, Object]]:
        """Bulk get multiple OIDs using GetBulkRequest-PDU."""
        ...

    async def set(self, oid: str, value: SNMPValue) -> bool:
        """Set a MIB value on the agent."""
        ...

    async def send_trap(
        self,
        trap_type: int = 0,
        variables: Optional[list[tuple[str, SNMPValue]]] = None,
    ) -> bool:
        """Send a trap to the management station."""
        ...

    async def send_inform(
        self,
        trap_type: int,
        variables: Optional[list[tuple[str, SNMPValue]]] = None,
    ) -> bool:
        """Send an InformRequest-PDU (requires acknowledgment)."""
        ...

    async def close(self) -> None:
        """Close the underlying client."""
        ...

    def __repr__(self) -> str:
        """String representation."""
        ...