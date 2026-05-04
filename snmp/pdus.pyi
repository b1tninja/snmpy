"""Type stub for snmp.pdus module."""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterator, Optional, Type, TypeVar

from ber.object import Object, ObjectTag, ObjectIdentifier

if TYPE_CHECKING:
    from snmp.datagram import SNMPDatagram
    from snmp.enums import ErrorStatus


T = TypeVar("T", bound="PDU")


class PDU(Object, dict):
    """Base SNMP PDU class — dict[ObjectIdentifier, Object] + Object for BER encoding."""

    _ber_obj: Object

    tag_class: int
    is_constructed: bool
    tag_id: Optional[int]
    field_names: tuple[str, ...]

    @property
    def tag(self) -> ObjectTag:
        """Return the ASN.1 tag."""
        ...

    @property
    def value(self) -> object:
        """Return the BER value."""
        ...

    @classmethod
    def get_object_tag(cls) -> ObjectTag:
        """Get the ObjectTag for this PDU type."""
        ...

    @classmethod
    def from_object(cls: Type[T], obj: Object) -> T:
        """Create a PDU instance from a raw BER Object."""
        ...

    def __init__(
        self,
        tag: Optional[ObjectTag] = None,
        request_id: Optional[Object] = None,
        error_status: Optional[Object] = None,
        error_index: Optional[Object] = None,
        variable_bindings: Optional[Object] = None,
    ) -> None:
        ...

    def _populate_from_varbinds(self) -> None:
        """Populate dict from variable_bindings Sequence."""
        ...

    def __repr__(self) -> str:
        ...

    def __len__(self) -> int:
        """Return number of variable bindings."""
        ...

    def __iter__(self) -> Iterator[tuple[ObjectIdentifier, Object]]:
        """Iterate over (oid, value) pairs."""
        ...

    def __getitem__(self, key: object) -> Object:
        """Access variable binding by OID."""
        ...

    def __contains__(self, key: object) -> bool:
        """Check if OID is present."""
        ...

    def get(self, key: object, default: Optional[Object] = None) -> Optional[Object]:
        """Get a value by OID."""
        ...

    def __eq__(self, other: object) -> bool:
        """Compare PDU instances."""
        ...


class BulkPDU(PDU):
    """Base SNMP Bulk PDU class (SNMPv2)."""

    field_names: tuple[str, ...]

    def __init__(
        self,
        tag: Optional[ObjectTag] = None,
        request_id: Optional[Object] = None,
        non_repeaters: Optional[Object] = None,
        max_repetitions: Optional[Object] = None,
        variable_bindings: Optional[Object] = None,
    ) -> None:
        ...

    def __repr__(self) -> str:
        ...


class Request(PDU):
    """Base SNMP Request PDU."""

    @classmethod
    def from_oid(cls: Type[T], oid: Optional[str] = None) -> T:
        """Create a Request PDU from an OID string."""
        ...

    def __repr__(self) -> str:
        ...


class GetRequest(Request):
    """SNMP GetRequest PDU (tag_id=0)."""
    tag_id: int


class GetNextRequest(Request):
    """SNMP GetNextRequest PDU (tag_id=1)."""
    tag_id: int


class GetResponse(PDU):
    """SNMP GetResponse PDU (tag_id=2)."""

    tag_id: int
    oid: Object
    response: Object

    @classmethod
    def from_object(cls: Type[T], obj: Object) -> T:
        ...

    def __init__(
        self,
        tag: Optional[ObjectTag] = None,
        request_id: Optional[Object] = None,
        error_status: Optional[Object] = None,
        error_index: Optional[Object] = None,
        variable_bindings: Optional[Object] = None,
    ) -> None:
        ...

    def __repr__(self) -> str:
        ...


class SetRequest(Request):
    """SNMP SetRequest PDU (tag_id=3)."""
    tag_id: int


class GetBulkRequest(BulkPDU):
    """SNMP GetBulkRequest-PDU (tag_id=5)."""
    tag_id: int


class InformRequest(PDU):
    """SNMP InformRequest-PDU (tag_id=6)."""
    tag_id: int


class SNMPv2Trap(PDU):
    """SNMPv2-Trap-PDU (tag_id=7)."""
    tag_id: int


class Report(PDU):
    """Report-PDU (tag_id=8)."""
    tag_id: int


class Trap(PDU):
    """SNMP Trap-PDU (tag_id=4)."""

    tag_id: int
    field_names: tuple[str, ...]

    COLD_START: int
    WARM_START: int
    LINK_DOWN: int
    LINK_UP: int
    AUTHENTICATION_FAILURE: int
    EGP_NEIGHBOR_LOSS: int
    ENTERPRISE_SPECIFIC: int

    def __init__(
        self,
        tag: Optional[ObjectTag] = None,
        enterprise: Optional[Object] = None,
        agent_addr: Optional[Object] = None,
        generic_trap: Optional[Object] = None,
        specific_code: Optional[Object] = None,
        time_stamp: Optional[Object] = None,
        variable_bindings: Optional[Object] = None,
    ) -> None:
        ...

    @classmethod
    def from_trap_type(
        cls: Type[T],
        trap_type: int,
        enterprise: Optional[str] = None,
        agent_addr: Optional[str] = None,
        specific_code: int = 0,
        time_stamp: Optional[int] = None,
        variables: Optional[list[tuple[str, object]]] = None,
    ) -> T:
        """Create a Trap-PDU from a trap type constant."""
        ...

    def __repr__(self) -> str:
        ...