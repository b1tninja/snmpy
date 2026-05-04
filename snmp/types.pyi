"""Type stub for snmp.types module."""

from __future__ import annotations

from typing import Any

from ber.object import Object


# ---------------------------------------------------------------------------
# Variable binding types
# ---------------------------------------------------------------------------

VarBind: tuple[str, object]
"""A single variable binding: (OID string, value)."""

VarBinds: list[tuple[str, object]]
"""List of variable bindings."""

WalkResult: list[tuple[str, Object]]
"""Result of a walk operation: list of (OID string, BER Object)."""


# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------

SNMPValue: Any
"""Any value acceptable as an SNMP value (BER Object, int, str, bytes, etc.)."""

PDUResult: object
"""Possible return types from PDU operations."""


# ---------------------------------------------------------------------------
# Network / socket types
# ---------------------------------------------------------------------------

SocketAddress: tuple[str, int]
"""A network socket address: (host, port)."""


# ---------------------------------------------------------------------------
# Error status types
# ---------------------------------------------------------------------------

ErrorStatusInt: int
"""Integer representation of an SNMP error status (0-5 for standard codes)."""