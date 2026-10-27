"""Unwrap BER response values into plain Python types.

The counterpart of :mod:`snmp.factories` (which builds Python -> BER);
these helpers go BER -> Python for values found in GET / GETNEXT /
GETBULK / SET responses.

Response values are BER ``Object`` instances (:mod:`ber.object`):
``Object.tag`` carries the ASN.1 tag and ``Object.value`` the decoded
content.  For SNMP that content is an ``ObjectValue`` bytes-subclass
(``Integer``, ``OctetString``, ``ObjectIdentifier``, ``Null``) or plain
``bytes`` (Counter32 / Gauge32 / TimeTicks etc. decode to raw content
octets because this codec has no dedicated class for them).

v2c exception values (RFC 3416 §4.1.6) — ``noSuchObject`` (context 0),
``noSuchInstance`` (context 1) and ``endOfMibView`` (context 2) — are
empty context-specific primitives.  The ``as_*`` helpers raise
``LookupError`` naming the exception instead of masquerading it as empty
data.  (When responding to SNMPv1 clients these map to ``noSuchName``
per RFC 3584 §4.2.2.2; see :class:`snmp.enums.SNMPException`.)
"""

from __future__ import annotations

from ber.enums import TagClassEnum
from ber.object import Integer, ObjectIdentifier
from snmp.oid import OidLike, resolve_oid

__all__ = ["as_bytes", "as_int", "as_str", "exception_name", "oid_string"]

# RFC 3416 §4.1.6 context-specific exception values.
_EXCEPTION_NAMES = {
    0: "noSuchObject",
    1: "noSuchInstance",
    2: "endOfMibView",
}


def exception_name(value: object) -> str | None:
    """Return the v2c exception name if *value* is an exception value.

    Detects context-specific primitive tags 0 / 1 / 2 (``noSuchObject``,
    ``noSuchInstance``, ``endOfMibView``) per RFC 3416 §4.1.6.  Returns
    ``None`` for ordinary values.
    """
    tag = getattr(value, "tag", None)
    if tag is None:
        return None
    if tag.tag_class == TagClassEnum.context_specific and tag.tag_id in _EXCEPTION_NAMES:
        return _EXCEPTION_NAMES[tag.tag_id]  # type: ignore[union-attr]
    return None


def _reject_exception(value: object) -> None:
    name = exception_name(value)
    if name is not None:
        raise LookupError(f"{name} (RFC 3416 §4.1.6 exception value)")


def _content(value: object) -> object:
    """Return the decoded content of an ``Object`` (or *value* itself)."""
    return getattr(value, "value", value)


def as_bytes(value: object) -> bytes:
    """Unwrap to ``bytes`` — the raw content octets of the value.

    OctetString / Counter / Gauge / TimeTicks content comes back as its
    octets; ``Null`` / empty content yields ``b""``.

    Raises:
        LookupError: on a v2c exception value (RFC 3416 §4.1.6).
        TypeError: for constructed (sequence) content.
    """
    _reject_exception(value)
    content = _content(value)
    if content is None:
        return b""
    if isinstance(content, bytes):  # includes all ObjectValue subclasses
        return bytes(content)
    if isinstance(content, str):
        return content.encode()
    raise TypeError(
        f"as_bytes: cannot unwrap {type(content).__name__} content "
        f"from {type(value).__name__}"
    )


def as_int(value: object) -> int:
    """Unwrap to ``int``.

    INTEGER / Counter32 / Counter64 / Gauge32 / TimeTicks / Unsigned32
    content is read as an unsigned big-endian integer (matching
    ``ber.object.Integer.from_int``/``__int__`` which encode unsigned).

    Raises:
        LookupError: on a v2c exception value (RFC 3416 §4.1.6).
        ValueError: on empty content.
        TypeError: on content that cannot be interpreted as an integer.
    """
    _reject_exception(value)
    content = _content(value)
    if isinstance(content, bool):
        return int(content)
    if isinstance(content, int):
        return content
    if isinstance(content, (bytes, bytearray, memoryview)):
        data = bytes(content)
        if not data:
            raise ValueError(f"as_int: empty content in {type(value).__name__}")
        return int.from_bytes(data, "big", signed=False)
    if isinstance(content, str):
        return int(content)
    raise TypeError(
        f"as_int: cannot unwrap {type(content).__name__} content "
        f"from {type(value).__name__}"
    )


def as_str(value: object) -> str:
    """Unwrap to ``str``.

    OctetString content decodes as UTF-8, falling back to latin-1 (which
    never fails and is byte-preserving).  ``Integer``-like content
    renders as its decimal value; ``ObjectIdentifier`` renders dotted.
    """
    _reject_exception(value)
    content = _content(value)
    if isinstance(content, ObjectIdentifier):
        return str(content)
    if isinstance(content, Integer):
        return str(int(content))
    if isinstance(content, (bytes, bytearray, memoryview)):
        data = bytes(content)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1")
    if isinstance(content, str):
        return content
    if isinstance(content, int):
        return str(content)
    raise TypeError(
        f"as_str: cannot unwrap {type(content).__name__} content "
        f"from {type(value).__name__}"
    )


def oid_string(oid: OidLike) -> str:
    """Normalize a var-bind OID to a dotted-decimal string.

    Accepts dotted ``str``, a BER ``ObjectIdentifier`` (as yielded when
    iterating :class:`snmp.pdus.PDU` var-binds) or a named
    :class:`snmp.oid.Oid` — thin wrapper over
    :func:`snmp.oid.resolve_oid` for the response side.
    """
    return resolve_oid(oid)


