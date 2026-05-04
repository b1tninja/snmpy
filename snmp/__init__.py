"""SNMP module for SNMP protocol operations.

Implements RFC 1157: A Simple Network Management Protocol (SNMP).

Exports PDU types:
    - GetRequest: Retrieve managed object value (§4.1.2)
    - GetNextRequest: Retrieve next managed object value (§4.1.3)
    - GetResponse: Response to GetRequest/GetNextRequest (§4.1.4)
    - SetRequest: Set managed object value (§4.1.5)
    - Trap: Asynchronous trap message (§4.1.6)

Exports server/client ABCs:
    - SNMPServer: Abstract base class for SNMP servers
    - SNMPClient: Abstract base class for SNMP clients
"""

from __future__ import annotations

from snmp.datagram import SNMPDatagram
from snmp.pdus import GetRequest, GetNextRequest, GetResponse, SetRequest, Trap
from snmp.enums import ErrorStatus, SNMPVersion
from snmp.security import (
    AuthenticationError,
    CommunityDatabase,
    CommunityPolicy,
    CommunityProfile,
    MIBViewFilter,
    MIBViewTree,
    MessageSizeLimit,
    ProfileDatabase,
    ProxyAgent,
    ProxyAgentRegistry,
    AuthenticationService,
    get_authentication_service,
    generate_authentication_failure_trap,
)
from snmp.mib_view import (
    MIBView,
    UCDView,
    IFTableView,
    HostResourcesView,
    InterfaceInfo,
    SystemMetrics,
    BatteryInfo,
)
from snmp.server import SNMPServer
from snmp.client import SNMPClient
from snmp.types import VarBind, VarBinds, WalkResult, SNMPValue, SocketAddress, ErrorStatusInt
from snmp.factories import (
    make_var_bind,
    make_var_binds,
    make_get_request,
    make_set_value,
    make_empty_var_binds,
    _to_snmp_value,
)

DEFAULT_PORT = 161

__all__ = [
    # Constants
    "DEFAULT_PORT",
    # Datagram
    "SNMPDatagram",
    # PDU Types
    "GetRequest",
    "GetNextRequest",
    "GetResponse",
    "SetRequest",
    "Trap",
    # Enums
    "ErrorStatus",
    "SNMPVersion",
    # Security (RFC 1157 §8)
    "AuthenticationError",
    "CommunityDatabase",
    "CommunityPolicy",
    "CommunityProfile",
    "MIBViewFilter",
    "MIBViewTree",
    "ProfileDatabase",
    "ProxyAgent",
    "ProxyAgentRegistry",
    "AuthenticationService",
    "MessageSizeLimit",
    "get_authentication_service",
    "generate_authentication_failure_trap",
    # Server/Client ABCs
    "SNMPServer",
    "SNMPClient",
    # MIB View ABC & Implementations
    "MIBView",
    "UCDView",
    "IFTableView",
    "HostResourcesView",
    "InterfaceInfo",
    "SystemMetrics",
    "BatteryInfo",
    # Type aliases (snmp.types)
    "VarBind",
    "VarBinds",
    "WalkResult",
    "SNMPValue",
    "SocketAddress",
    "ErrorStatusInt",
    # Factory functions (snmp.factories)
    "make_var_bind",
    "make_var_binds",
    "make_get_request",
    "make_set_value",
    "make_empty_var_binds",
    "_to_snmp_value",
]
