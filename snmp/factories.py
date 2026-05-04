"""Factory functions for SNMP object construction.

Provides helpers to reduce boilerplate when creating BER Objects and
variable bindings for SNMP requests/responses.

Usage:
    >>> from snmp.factories import make_var_bind, make_sequence_of_objects
    >>> var_bind = make_var_bind("1.3.6.1.2.1.1.1.0", "Linux device")
    >>> seq = make_sequence_of_objects([oid, value])
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Sequence, Union

from ber.object import Object, ObjectIdentifier, ObjectValue, Integer, Null, OctetString, Sequence as BERSequence

if TYPE_CHECKING:
    from snmp.types import SNMPValue

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

ObjectInput = Union[str, Object]
"""Accepted input types for Object construction (string OID or BER Object)."""

ValueInput = Union["SNMPValue", Object]
"""Accepted input types for value construction (Python value or BER Object)."""


# =========================================================================
# Value conversion helpers
# =========================================================================

def _to_snmp_value(value: ValueInput) -> Object:
    """Convert a Python value or BER Object to a BER Object.

    Type mapping (per RFC 1902 SMIV2):
      - int → Integer Object (Counter32, Gauge32, TimeTicks, Unsigned32)
      - bool → Integer Object (0/1)
      - str/bytes → OctetString Object
      - Object → returned as-is

    Args:
        value: Python value or BER Object to convert.

    Returns:
        BER Object with appropriate tag.
    """
    # Already a full Object — return as-is
    if isinstance(value, Object):
        return value

    # bytes → OctetString
    if isinstance(value, bytes):
        return OctetString(value).get_object()

    # int (but not bool) → Integer
    if isinstance(value, int) and not isinstance(value, bool):
        try:
            return Integer.from_int(value).get_object()
        except (OverflowError, ValueError):
            # Large integers — fall back to OctetString
            return OctetString(str(value).encode()).get_object()

    # bool → Integer(0/1)
    if isinstance(value, bool):
        return Integer.from_int(1 if value else 0).get_object()

    # str → OctetString
    if isinstance(value, str):
        return OctetString(value.encode()).get_object()

    # Fallback → Null
    return Null().get_object()


# =========================================================================
# Variable binding factory
# =========================================================================

def make_var_bind(oid: ObjectInput, value: ValueInput) -> Object:
    """Create a BER variable binding (varBind) from an OID and value.

    A variable binding is a SEQUENCE containing two elements:
    1. An ObjectIdentifier (the OID)
    2. A value (any BER-compatible type)

    Usage:
        >>> # From string OID and Python value
        >>> vb = make_var_bind("1.3.6.1.2.1.1.1.0", "My device")
        >>> # From existing Objects
        >>> vb = make_var_bind(existing_oid, existing_value)

    Args:
        oid: Object Identifier string (e.g., "1.3.6.1.2.1.1.1.0")
            or an existing BER Object/ObjectIdentifier.
        value: SNMP value (int, str, bytes, BER Object, etc.).

    Returns:
        A BER Sequence object representing the variable binding.
    """
    # Convert OID input to Object
    if isinstance(oid, str):
        oid_obj: Object = ObjectIdentifier.from_string(oid).get_object()
    elif isinstance(oid, ObjectIdentifier):
        oid_obj = oid.get_object()
    elif isinstance(oid, Object):
        oid_obj = oid
    else:
        oid_obj = ObjectIdentifier.from_string(str(oid)).get_object()

    # Convert value to Object
    value_obj = _to_snmp_value(value)

    return BERSequence.from_list([oid_obj, value_obj])


def make_var_binds(pairs: Sequence[tuple[ObjectInput, ValueInput]]) -> Object:
    """Create a BER variable-bindings SEQUENCE from a list of (oid, value) pairs.

    Usage:
        >>> pairs = [
        ...     ("1.3.6.1.2.1.1.1.0", "My device"),
        ...     ("1.3.6.1.2.1.1.5.0", "MyRouter"),
        ... ]
        >>> seq = make_var_binds(pairs)

    Args:
        pairs: Iterable of (oid, value) tuples.

    Returns:
        A BER Sequence of Sequences (variable-bindings list).
    """
    return BERSequence.from_list([make_var_bind(oid, val) for oid, val in pairs])


# =========================================================================
# Common PDU helper
# =========================================================================

def make_get_request(oid: str) -> Object:
    """Create a GetRequest variable binding (OID with Null value).

    Used for GetRequest and GetNextRequest operations.

    Args:
        oid: Object Identifier string.

    Returns:
        A BER Sequence representing the variable binding with a Null value.
    """
    return BERSequence.from_list([
        ObjectIdentifier.from_string(oid).get_object(),
        Null().get_object(),
    ])


def make_set_value(value: ValueInput) -> Object:
    """Create a value object for SetRequest operations.

    Wraps the value in a BER Object suitable for inclusion in a SetRequest.

    Args:
        value: The value to set (int, str, bytes, BER Object, etc.).

    Returns:
        A BER Object with appropriate tag for the value.

    Example:
        >>> set_obj = make_set_value(42)         # Integer
        >>> set_obj = make_set_value("public")   # OctetString
        >>> set_obj = make_set_value(b"\\x01\\x02")  # OctetString
    """
    return _to_snmp_value(value)


def make_empty_var_binds() -> Object:
    """Create an empty variable-bindings SEQUENCE.

    Used when a request has no variable bindings.

    Returns:
        An empty BER Sequence.
    """
    return BERSequence.from_list([])