"""Type stub for snmp.datagram module."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ber.object import Object, ObjectTag

if TYPE_CHECKING:
    from snmp.pdus import PDU
    from snmp.enums import SNMPVersion


def _ensure_object(val: object) -> object:
    """Ensure a value is a full Object (not just an ObjectValue/bytes)."""
    ...


class SNMPDatagram(Object):
    """SNMP protocol datagram — BER-encoded SEQUENCE of version, community, and PDU."""

    snmp_version: int
    pdus: dict[int, type[PDU]]

    def __init__(
        self,
        version: Optional[Object] = None,
        community: Optional[Object] = None,
        pdu: Optional[PDU] = None,
    ) -> None:
        ...

    @property
    def version(self) -> Object:
        ...

    @property
    def community(self) -> Object:
        ...

    @property
    def pdu(self) -> PDU:
        ...

    @classmethod
    def decode(cls, buffer: bytes, offset: int = 0) -> SNMPDatagram:
        """Decode an SNMP datagram from raw bytes."""
        ...

    def encode(self) -> bytes:
        """Encode this datagram to BER bytes."""
        ...

    def __bytes__(self) -> bytes:
        ...

    def __repr__(self) -> str:
        ...