"""SNMP protocol package: BER datagrams, PDUs, clients and servers.

Protocol baselines: RFC 1157 (v1), RFC 3416 (v2c protocol operations),
RFC 3417 (UDP transport mapping).  Keep the public surface small and
explicit — import submodules directly for everything else (e.g.
``from snmp.client import SNMPClientImpl``).
"""

from __future__ import annotations

# UDP port assignments (RFC 3417 §3.1): agents 161, SNMP middlemen/trap
# receiver 162.  Defined before submodule imports so partially
# initialized state never breaks ``from snmp import DEFAULT_PORT``.
DEFAULT_PORT = 161
TRAP_PORT = 162

from snmp.enums import ErrorStatus, SNMPVersion  # noqa: E402
from snmp.session import Session  # noqa: E402

__all__ = [
    "DEFAULT_PORT",
    "TRAP_PORT",
    "ErrorStatus",
    "SNMPVersion",
    "Session",
]

