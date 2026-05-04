"""Shared type aliases for SNMP module.

Defines common type aliases used across the SNMP library to ensure consistency
and avoid duplication.

Usage:
    >>> from snmp.types import VarBind, WalkResult, SNMPValue
    >>> result: WalkResult = [("1.3.6.1.2.1.1.1.0", b"Linux device")]
"""

from __future__ import annotations

from typing import Any

from ber.object import Object

# ---------------------------------------------------------------------------
# Variable binding types
# ---------------------------------------------------------------------------

VarBind = tuple[str, object]
"""A single variable binding: (OID string, value)."""

VarBinds = list[VarBind]
"""List of variable bindings."""

WalkResult = list[tuple[str, Object]]
"""Result of a walk operation: list of (OID string, BER Object)."""

# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------

SNMPValue = Any
"""Any value acceptable as an SNMP value (BER Object, int, str, bytes, etc.)."""

PDUResult = Object | list[tuple[str, Object]] | None
"""Possible return types from PDU operations."""

# ---------------------------------------------------------------------------
# Network / socket types
# ---------------------------------------------------------------------------

SocketAddress = tuple[str, int]
"""A network socket address: (host, port)."""

# ---------------------------------------------------------------------------
# Error status types
# ---------------------------------------------------------------------------

ErrorStatusInt = int
"""Integer representation of an SNMP error status (0-5 for standard codes)."""