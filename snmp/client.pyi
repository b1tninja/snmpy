"""Type stub for snmp.client module."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

from snmp.datagram import SNMPDatagram
from snmp.enums import SNMPVersion
from snmp.types import SNMPValue

if TYPE_CHECKING:
    from snmp.pdus import PDU
    from ber.object import Object


class SNMPClient(ABC):
    """Abstract base class for SNMP clients."""

    community: str
    version: SNMPVersion
    timeout: float
    retries: int

    @abstractmethod
    async def _send_receive(
        self,
        datagram: SNMPDatagram,
        host: str,
        port: int,
    ) -> Optional[bytes]:
        ...

    async def get(
        self,
        host: str,
        oid: str,
        port: int = 161,
    ) -> Optional[Object]:
        ...

    async def get_next(
        self,
        host: str,
        oid: str,
        port: int = 161,
    ) -> Optional[Object]:
        ...

    async def walk(
        self,
        host: str,
        starting_oid: str,
        port: int = 161,
        stop_oid: Optional[str] = None,
    ) -> list[tuple[str, Object]]:
        ...

    async def bulk_get(
        self,
        host: str,
        oids: list[str],
        non_repeaters: int = 0,
        max_repetitions: int = 10,
        port: int = 161,
    ) -> list[tuple[str, Object]]:
        ...

    async def set(
        self,
        host: str,
        oid: str,
        value: SNMPValue,
        port: int = 161,
    ) -> bool:
        ...

    async def send_trap(
        self,
        host: str,
        trap_type: int = 0,
        variables: Optional[list[tuple[str, SNMPValue]]] = None,
        port: int = 162,
    ) -> bool:
        ...

    async def send_inform(
        self,
        host: str,
        trap_type: int,
        variables: Optional[list[tuple[str, SNMPValue]]] = None,
        port: int = 162,
    ) -> bool:
        ...

    def _build_datagram(self, pdu: Object) -> SNMPDatagram:
        ...

    async def _send_request(
        self,
        host: str,
        port: int,
        pdu_factory,
    ) -> Optional[Object]:
        ...

    def _to_snmp_value(self, value: SNMPValue) -> Object:
        ...


class _SNMPClientProtocol(asyncio.DatagramProtocol):
    """Internal protocol for receiving SNMP responses."""

    response_data: list[bytes]
    response_event: asyncio.Event

    def __init__(self) -> None:
        ...

    def connection_lost(self, exc: Optional[Exception]) -> None:
        ...

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        ...

    def error_received(self, exc: Exception) -> None:
        ...