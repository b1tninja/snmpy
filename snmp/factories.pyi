"""Type stub for snmp.factories module."""

from __future__ import annotations

from typing import TYPE_CHECKING, Sequence

from ber.object import Object

if TYPE_CHECKING:
    from snmp.types import SNMPValue

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

ObjectInput: object
"""Accepted input types for Object construction (string OID or BER Object)."""

ValueInput: object
"""Accepted input types for value construction (Python value or BER Object)."""


# =========================================================================
# Value conversion
# =========================================================================

def _to_snmp_value(value: ValueInput) -> Object:
    """Convert a Python value or BER Object to a BER Object."""
    ...


# =========================================================================
# Variable binding factory
# =========================================================================

def make_var_bind(oid: ObjectInput, value: ValueInput) -> Object:
    """Create a BER variable binding (varBind) from an OID and value."""
    ...

def make_var_binds(pairs: Sequence[tuple[ObjectInput, ValueInput]]) -> Object:
    """Create a BER variable-bindings SEQUENCE from a list of (oid, value) pairs."""
    ...


# =========================================================================
# Common PDU helpers
# =========================================================================

def make_get_request(oid: str) -> Object:
    """Create a GetRequest variable binding (OID with Null value)."""
    ...

def make_set_value(value: ValueInput) -> Object:
    """Create a value object for SetRequest operations."""
    ...

def make_empty_var_binds() -> Object:
    """Create an empty variable-bindings SEQUENCE."""
    ...