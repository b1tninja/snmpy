"""SNMP datagram encoding and decoding."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ber.enums import TagClassEnum, UniversalClassTags
from ber.object import Object, ObjectTag, OctetString, Integer, ObjectValue

if TYPE_CHECKING:
    from snmp.pdus import PDU
from snmp.enums import SNMPVersion


def _ensure_object(val: object) -> Object:
    """Ensure a value is a full Object (not just an ObjectValue/bytes).

    ObjectValue instances (Integer, OctetString, etc.) are bytes subclasses
    without the proper Object tag. When passed directly to SNMPDatagram, they
    end up encoded as raw bytes (tag 04 = OCTET STRING) instead of their
    proper ASN.1 type. This wrapper converts them to full Object instances.

    Args:
        val: Value to convert — already an Object, an ObjectValue (bytes), or None.

    Returns:
        A full Object instance with proper tag and value.
    """
    if val is None:
        return None  # type: ignore[return-value]
    # Already a full Object — return as-is
    if isinstance(val, Object) and not isinstance(val, ObjectValue):
        return val
    # ObjectValue (Integer, OctetString, etc.) is a bytes subclass — wrap it
    if isinstance(val, ObjectValue):
        tag = type(val).get_object_tag()
        return Object(tag, val)
    # Fallback for raw bytes
    if isinstance(val, bytes):
        tag = ObjectTag(TagClassEnum.universal, False, UniversalClassTags.octet_string)
        return Object(tag, val)
    return val  # type: ignore[return-value]


class SNMPDatagram(Object):
    """SNMP protocol datagram.

    Wraps an SNMP message as a BER SEQUENCE containing:
    - version (INTEGER)
    - community (OCTET STRING)
    - pdu (context-specific tagged PDU)
    """

    snmp_version = SNMPVersion.v1
    pdus: dict[int, type[PDU]] = {}  # populated at runtime

    def __init__(
        self,
        version: Optional[Object] = None,
        community: Optional[Object] = None,
        pdu: Optional[PDU] = None,
    ) -> None:
        # _ensure_object handles both ObjectValue (raw bytes) and full Object instances.
        # Integer/OctetString are bytes subclasses (ObjectValue) without tags — they
        # must be wrapped in a full Object so __bytes__() emits the proper ASN.1 tag.
        version = _ensure_object(version or Integer.from_int(self.snmp_version))
        community = _ensure_object(community or OctetString(b"public"))

        # Store the processed values (already full Objects) into self.value list
        Object.__init__(
            self,
            ObjectTag(TagClassEnum.universal, True, UniversalClassTags.sequence_of),
            [version, community, pdu],
        )

        self.version = version  # type: ignore[assignment]
        self.community = community  # type: ignore[assignment]
        self.pdu = pdu
        # Store references back into value list so bytes() encoding works correctly
        self._version_obj = version
        self._community_obj = community
        self._pdu_obj = pdu

    @classmethod
    def decode(cls, buffer: bytes, offset: int = 0) -> SNMPDatagram:
        """Decode an SNMP datagram from raw bytes.

        Args:
            buffer: Raw bytes to decode.
            offset: Byte offset to start decoding at.

        Returns:
            Decoded SNMPDatagram instance.
        """
        obj, _offset = Object.decode(buffer, offset)
        assert len(buffer) == _offset
        version, community, pdu = obj.value  # type: ignore[misc]

        assert pdu.tag.tag_class == TagClassEnum.context_specific, (
            f"pdu.tag.tag_class={pdu.tag.tag_class} != {TagClassEnum.context_specific}"
        )  # type: ignore[union-attr]
        assert isinstance(community.value, (OctetString, bytes)), (
            f"community.value={community.value} type={type(community.value)}"
        )
        if hasattr(pdu, "tag") and hasattr(pdu.tag, "tag_id"):
            if pdu.tag.tag_id in cls.pdus:  # type: ignore[union-attr]
                pdu = cls.pdus[pdu.tag.tag_id].from_object(pdu)  # type: ignore[union-attr]
        return cls(version, community, pdu)  # type: ignore[arg-type]

    def encode(self) -> bytes:
        """Encode this datagram to BER bytes."""
        from ber.object import ObjectLength
        from snmp.pdus import PDU

        # Each element in self.value is already an Object with proper tag/bytes representation
        parts: list[bytes] = []
        for val in self.value:
            # If it's already an Object, use its bytes() representation
            if isinstance(val, Object):
                parts.append(bytes(val))
            elif isinstance(val, bytes):
                # Raw bytes need to be wrapped as OCTET STRING
                from ber.object import OctetString
                parts.append(bytes(OctetString(val).get_object()))
            elif val is not None:
                parts.append(bytes(val))

        encoded = b"".join(parts)
        outer_tag = self.tag
        return bytes(outer_tag) + ObjectLength.encode(len(encoded)) + encoded

    def __bytes__(self) -> bytes:
        return self.encode()

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(version={self.version}, "
            f"community={self.community}, pdu={self.pdu})"
        )


# Register PDU types by tag_id to enable proper type dispatch in decode().
# Import at bottom of module to avoid circular imports.
from snmp.pdus import (  # noqa: E402
    GetRequest,
    GetNextRequest,
    GetResponse,
    SetRequest,
    GetBulkRequest,
    InformRequest,
    SNMPv2Trap,
    Report,
    Trap,
)

# SNMPv1 PDU registration (RFC 1157)
SNMPDatagram.pdus[GetRequest.tag_id] = GetRequest            # type: ignore[arg-type]
SNMPDatagram.pdus[GetNextRequest.tag_id] = GetNextRequest    # type: ignore[arg-type]
SNMPDatagram.pdus[GetResponse.tag_id] = GetResponse          # type: ignore[arg-type]
SNMPDatagram.pdus[SetRequest.tag_id] = SetRequest            # type: ignore[arg-type]
SNMPDatagram.pdus[Trap.tag_id] = Trap                        # type: ignore[arg-type]

# SNMPv2 PDU registration (RFC 1905)
SNMPDatagram.pdus[GetBulkRequest.tag_id] = GetBulkRequest    # type: ignore[arg-type]
SNMPDatagram.pdus[InformRequest.tag_id] = InformRequest      # type: ignore[arg-type]
SNMPDatagram.pdus[SNMPv2Trap.tag_id] = SNMPv2Trap            # type: ignore[arg-type]
SNMPDatagram.pdus[Report.tag_id] = Report                    # type: ignore[arg-type]