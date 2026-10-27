"""Scoped PDU — RFC 3411 §3.3.4, RFC 3412 §5.1.

Provides:
- ScopedPDU: Inner PDU with contextEngineID + contextName (RFC 3411 §3.3.4)
- ScopedPDU encoding/decoding for unencrypted and encrypted forms
- Integration with USM for message wrapping

RFC 3411 §3.3.4 (ScopedPDU):
    The ScopedPDU is the inner PDU of the SNMPv3 message.
    It contains:
    - contextEngineID: The engine ID of the context
    - contextName: The context name
    - data: The actual PDU data (GetRequest, GetResponse, etc.)

    For encrypted messages, the contextEngineID + contextName + data
    are encrypted as a unit.

RFC 3412 §5.1 (ScopedPDU structure):
    ScopedPDU ::= SEQUENCE {
        contextEngineID OCTET STRING,
        contextName   OCTET STRING,
        data          SNMPData
    }
"""

from __future__ import annotations

from typing import Optional

from ber.enums import TagClassEnum
from ber.object import (
    Object,
    ObjectIdentifier,
    OctetString,
    Integer,
    Sequence,
    Null,
)
from snmp.pdus import (
    GetBulkRequest,
    GetNextRequest,
    GetRequest,
    GetResponse,
    InformRequest,
    PDU,
    Report,
    SetRequest,
    SNMPv2Trap,
)
from snmp.enums import ErrorStatus


# PDU classes keyed by context-specific tag_id (RFC 1905 §2), mirroring the
# dispatch table SNMPDatagram maintains for v1/v2c messages.
_PDU_BY_TAG: dict[int, type[PDU]] = {
    pdu.tag_id: pdu
    for pdu in (
        GetRequest,
        GetNextRequest,
        GetResponse,
        SetRequest,
        GetBulkRequest,
        InformRequest,
        SNMPv2Trap,
        Report,
    )
}


def promote_pdu(data: Object) -> Object:
    """Return the ScopedPDU ``data`` field as a typed PDU where possible.

    ``SNMPDatagram.decode`` promotes its PDU to a :class:`~snmp.pdus.PDU`
    subclass, which iterates as ``(oid, value)`` variable bindings.  ScopedPDU
    decoding used to leave the raw BER ``Object`` here instead, so identical
    varbind code worked over v2c and silently misbehaved over v3 — a raw PDU
    object iterates its four BER fields, not its bindings.

    Anything unrecognised (a non-context tag, an unknown PDU, an empty
    varBindList) is returned unchanged rather than guessed at.
    """
    tag = getattr(data, "tag", None)
    if tag is None or isinstance(data, PDU):
        return data
    # A universal INTEGER and a context-specific getResponse share tag_id 2.
    if tag.tag_class != TagClassEnum.context_specific or tag.tag_id not in _PDU_BY_TAG:
        return data
    try:
        return _PDU_BY_TAG[tag.tag_id].from_object(data)
    except (AssertionError, IndexError, TypeError, ValueError):
        return data


# =============================================================================
# ScopedPDU
# =============================================================================

class ScopedPDU:
    """SNMPv3 Scoped PDU per RFC 3411 §3.3.4.

    The ScopedPDU contains:
    - contextEngineID: Identifies the SNMP engine owning the context
    - contextName: The name of the context (e.g., empty string for default)
    - data: The actual PDU data (GetRequest, GetResponse, etc.)

    For encrypted messages, the entire ScopedPDU is encrypted.
    For unencrypted messages, only the data portion is encrypted.

    RFC 3411 §3.3.4 (ScopedPDU):
        The ScopedPDU structure is used for SNMPv3 message processing.

    Usage:
        >>> from snmp.scoped_pdu import ScopedPDU
        >>> scoped = ScopedPDU(
        ...     context_engine_id=b"\\x01\\x00\\x00\\x01\\x01",
        ...     context_name="default",
        ...     pdu=GetRequest.from_oid("1.3.6.1.2.1.1.1.0"),
        ... )
        >>> encoded = scoped.encode()
        >>> decoded = ScopedPDU.decode(encoded)
    """

    def __init__(
        self,
        context_engine_id: bytes = b"",
        context_name: str = "",
        pdu: Optional[Object] = None,
        error_status: ErrorStatus = ErrorStatus.no_error,
        error_index: int = 0,
        variable_bindings: Optional[Object] = None,
    ) -> None:
        """Initialize a Scoped PDU.

        Args:
            context_engine_id: The engine ID of the context owner.
            context_name: The context name (e.g., empty string for default).
            pdu: The PDU data (GetRequest, GetResponse, etc.).
            error_status: Error status code (for Response, Report).
            error_index: Error index (for Response, Report).
            variable_bindings: Variable bindings (for Response, Report).
        """
        self.context_engine_id = context_engine_id
        self.context_name = context_name
        self.pdu = pdu
        self.error_status = error_status
        self.error_index = error_index
        self.variable_bindings = variable_bindings

    def encode(self) -> bytes:
        """Encode the ScopedPDU to BER bytes.

        Returns:
            BER-encoded bytes of the ScopedPDU.
        """
        # contextEngineID is an OCTET STRING
        if self.context_engine_id:
            ctx_id = OctetString(self.context_engine_id).get_object()
        else:
            ctx_id = OctetString(b"").get_object()

        # contextName is an OCTET STRING
        ctx_name = OctetString(
            self.context_name.encode() if self.context_name else b""
        ).get_object()

        # data is the PDU
        data = self.pdu if self.pdu else Null().get_object()

        # Encode as SEQUENCE using bytes() conversion
        return bytes(Sequence.from_list([ctx_id, ctx_name, data]))

    def decode(self, data: bytes) -> ScopedPDU:
        """Decode BER bytes into a ScopedPDU.

        Args:
            data: BER-encoded ScopedPDU bytes.

        Returns:
            Self.
        """
        # Use Object.decode for proper BER parsing
        obj, _ = Object.decode(data, 0)
        seq = obj

        if seq.value and len(seq.value) >= 3:
            ctx_id_obj = seq.value[0]
            ctx_name_obj = seq.value[1]
            data_obj = seq.value[2]

            if isinstance(ctx_id_obj, OctetString):
                self.context_engine_id = (
                    bytes(ctx_id_obj.value) if hasattr(ctx_id_obj, "value") else data
                )
            if isinstance(ctx_name_obj, OctetString):
                self.context_name = (
                    ctx_name_obj.value.decode() if hasattr(ctx_name_obj, "value") else ""
                )
            self.pdu = promote_pdu(data_obj)

        return self

    @classmethod
    def from_pdu(
        cls,
        pdu: Object,
        context_engine_id: bytes = b"",
        context_name: str = "",
    ) -> ScopedPDU:
        """Create a ScopedPDU from a PDU.

        Args:
            pdu: The PDU data (GetRequest, GetResponse, etc.).
            context_engine_id: The context engine ID.
            context_name: The context name.

        Returns:
            A new ScopedPDU instance.
        """
        return cls(
            context_engine_id=context_engine_id,
            context_name=context_name,
            pdu=pdu,
        )

    @classmethod
    def decode_response(
        cls,
        data: bytes,
    ) -> ScopedPDU:
        """Decode a response ScopedPDU.

        Args:
            data: BER-encoded response bytes.

        Returns:
            A new ScopedPDU instance.
        """
        seq = Sequence()
        seq.decode(data)

        if seq.value and len(seq.value) >= 3:
            ctx_id = seq.value[0]
            ctx_name = seq.value[1]
            data_obj = seq.value[2]

            context_engine_id = (
                bytes(ctx_id.value) if hasattr(ctx_id, "value") else b""
            )
            context_name = (
                ctx_name.value.decode() if hasattr(ctx_name, "value") else ""
            )

            return cls(
                context_engine_id=context_engine_id,
                context_name=context_name,
                pdu=promote_pdu(data_obj),
            )

        return cls()

    def __repr__(self) -> str:
        ctx_id = (
            self.context_engine_id.hex()[:16] + "..."
            if self.context_engine_id
            else "none"
        )
        return (
            f"ScopedPDU(context_engine_id={ctx_id}, "
            f"context_name={self.context_name!r}, "
            f"pdu={self.pdu})"
        )


# =============================================================================
# ScopedPDUBuilder — Builder pattern for constructing ScopedPDU
# =============================================================================

class ScopedPDUBuilder:
    """Build ScopedPDU for SNMPv3 messages per RFC 3412 §5.1.

    Usage:
        >>> builder = ScopedPDUBuilder()
        >>> builder.set_context_engine_id(b"\\x01\\x00\\x00\\x01\\x01")
        >>> builder.set_context_name("default")
        >>> builder.set_pdu(GetRequest.from_oid("1.3.6.1.2.1.1.1.0"))
        >>> scoped_pdu = builder.build()
        >>> encoded = scoped_pdu.encode()
    """

    def __init__(self) -> None:
        self._context_engine_id: bytes = b""
        self._context_name: str = ""
        self._pdu: Optional[Object] = None
        self._error_status: ErrorStatus = ErrorStatus.no_error
        self._error_index: int = 0
        self._variable_bindings: Optional[Object] = None

    def set_context_engine_id(self, engine_id: bytes) -> ScopedPDUBuilder:
        """Set the context engine ID.

        Args:
            engine_id: The context engine ID bytes.

        Returns:
            Self for method chaining.
        """
        self._context_engine_id = engine_id
        return self

    def set_context_name(self, name: str) -> ScopedPDUBuilder:
        """Set the context name.

        Args:
            name: The context name string.

        Returns:
            Self for method chaining.
        """
        self._context_name = name
        return self

    def set_pdu(self, pdu: Object) -> ScopedPDUBuilder:
        """Set the PDU data.

        Args:
            pdu: The PDU data (GetRequest, GetResponse, etc.).

        Returns:
            Self for method chaining.
        """
        self._pdu = pdu
        return self

    def build(self) -> ScopedPDU:
        """Build the ScopedPDU.

        Returns:
            A new ScopedPDU instance.
        """
        return ScopedPDU(
            context_engine_id=self._context_engine_id,
            context_name=self._context_name,
            pdu=self._pdu,
        )


# =============================================================================
# Exported Names
# =============================================================================

__all__ = [
    "ScopedPDU",
    "ScopedPDUBuilder",
]