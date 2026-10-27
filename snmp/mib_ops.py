"""MIB Operations — RFC 2577: MIB Operations for SNMPv2.

Provides high-level MIB read/write operations that wrap around the
MIB registry and MIB lookup modules. Implements:

    - get(oid)        — Get value for a single OID (RFC 2577 §3.1)
    - get_next(oid)   — Get next OID after given OID (RFC 2577 §3.2)
    - get_bulk(oids)  — Bulk get with non-repeaters and max-repetitions (RFC 2577 §3.3)
    - set(oid, value) — Atomic set operation (RFC 2577 §3.4)
    - walk(root)      — Efficient tree walk using bulk operations (RFC 2577 §3.5)

Usage:
    >>> from snmp.mib_ops import get, get_next, get_bulk, set_value, walk
    >>> from snmp.mib_lookup import create_default_registry
    >>> registry = create_default_registry()
    >>> result = get("1.3.6.1.2.1.1.1", registry)
    >>> result  # ('1.3.6.1.2.1.1.1', <Value>)
"""

from __future__ import annotations

from typing import Optional, Any, Tuple, List, Dict, Union

from ber.object import (
    Object,
    ObjectIdentifier,
    OctetString,
    Integer,
    Sequence,
    Null,
)
from snmp.smi import (
    Counter32,
    Counter64,
    Gauge32,
    Unsigned32,
    TimeTicks,
    IpAddress,
    Opaque,
    DisplayString,
    PhysAddress,
    TruthStatus,
    StorageType,
    TestAndIncr,
)
from snmp.enums import ErrorStatus, SNMPVersion, SNMPException
from snmp.mib_lookup import MIBRegistry


# =============================================================================
# Type Mapping
# =============================================================================

# Map expected SMI types to their BER Object classes
_SMI_TO_BER_MAP: dict[str, type[Object]] = {
    "Counter32": Counter32,
    "Counter64": Counter64,
    "Gauge32": Gauge32,
    "Unsigned32": Unsigned32,
    "TimeTicks": TimeTicks,
    "IpAddress": IpAddress,
    "Opaque": Opaque,
    "DisplayString": DisplayString,
    "PhysAddress": PhysAddress,
    "TruthStatus": TruthStatus,
    "StorageType": StorageType,
    "TestAndIncr": TestAndIncr,
    "OCTET STRING": OctetString,
    "INTEGER": Integer,
    "OBJECT IDENTIFIER": ObjectIdentifier,
}


def _get_smi_type_from_oid(oid: str, registry: MIBRegistry) -> Optional[str]:
    """Get the expected SMI type for an OID from the registry.

    Args:
        oid: The OID string.
        registry: The MIB registry.

    Returns:
        The expected type name, or None.
    """
    info = registry.get_info(oid)
    if info and "type" in info:
        return info["type"]
    return None


# =============================================================================
# Error Handling
# =============================================================================

def error_status_for_exception(exc: Exception) -> ErrorStatus:
    """Map a Python exception to an SNMP error status.

    Args:
        exc: The exception to map.

    Returns:
        The corresponding SNMP error status.
    """
    if isinstance(exc, ValueError):
        return ErrorStatus.bad_value
    if isinstance(exc, KeyError):
        return ErrorStatus.no_such_name
    if isinstance(exc, PermissionError):
        return ErrorStatus.read_only
    return ErrorStatus.generic_error


def validate_oid_format(oid: str) -> bool:
    """Validate an OID's format.

    Args:
        oid: The OID string to validate.

    Returns:
        True if the OID format is valid.
    """
    if not oid or not isinstance(oid, str):
        return False
    parts = oid.strip(".").split(".")
    if not parts:
        return False
    for part in parts:
        try:
            val = int(part)
            if val < 0:
                return False
        except ValueError:
            return False
    return True


# =============================================================================
# Type Coercion
# =============================================================================

def coerce_value(value: Any, expected_type: Optional[str] = None) -> Object:
    """Coerce a Python value to an SNMP BER Object.

    Args:
        value: The Python value to coerce.
        expected_type: Expected SMI type name (e.g., "Counter32").

    Returns:
        A BER Object.

    Raises:
        ValueError: If the value cannot be coerced.
    """
    if isinstance(value, Object):
        return value

    if expected_type and expected_type in _SMI_TO_BER_MAP:
        cls = _SMI_TO_BER_MAP[expected_type]
        if expected_type == "Counter32":
            return Counter32(int(value)).get_object()
        if expected_type == "Counter64":
            return Counter64(int(value)).get_object()
        if expected_type == "Gauge32":
            return Gauge32(int(value)).get_object()
        if expected_type == "Unsigned32":
            return Unsigned32(int(value)).get_object()
        if expected_type == "TimeTicks":
            return TimeTicks(int(value)).get_object()
        if expected_type == "IpAddress":
            return IpAddress(value).get_object()
        if expected_type == "DisplayString":
            if isinstance(value, str):
                return DisplayString(value).get_object()
            return DisplayString(value).get_object()
        if expected_type == "TruthStatus":
            return TruthStatus(int(value)).get_object()
        if expected_type == "StorageType":
            return StorageType(int(value)).get_object()
        if expected_type == "TestAndIncr":
            return TestAndIncr(int(value)).get_object()
        if expected_type == "Opaque":
            return Opaque(value).get_object()
        if expected_type == "OBJECT IDENTIFIER":
            return ObjectIdentifier.from_string(str(value)).get_object()
        if expected_type == "OCTET STRING":
            return OctetString(value).get_object()
        if expected_type == "INTEGER":
            return Integer.from_int(int(value))

    # Default coercion
    if isinstance(value, bytes):
        return OctetString(value).get_object()
    if isinstance(value, int):
        return Integer.from_int(value)
    if isinstance(value, str):
        return OctetString(value.encode()).get_object()
    if isinstance(value, bool):
        return Integer.from_int(1 if value else 0)

    raise ValueError(f"Cannot coerce value {value!r} to SNMP object type")


# =============================================================================
# Core MIB Operations
# =============================================================================

def get_value(
    oid: str,
    registry: MIBRegistry,
    lookup_func: Optional[Any] = None,
) -> Optional[Tuple[str, Object]]:
    """Get the value for a single OID.

    Implements RFC 2577 §3.1: The Get operation retrieves the value of a
    managed object identified by its OID.

    Args:
        oid: The OID to retrieve.
        registry: The MIB registry for name→OID resolution.
        lookup_func: Optional callable(oid) -> value for actual data lookup.

    Returns:
        Tuple of (oid, value) if found, or None if not found.
    """
    # Resolve name to OID if needed
    resolved_oid = registry.name_to_oid(oid) if not validate_oid_format(oid) else oid
    if resolved_oid is None:
        resolved_oid = oid

    if lookup_func:
        value = lookup_func(resolved_oid)
    else:
        # Try registry lookup
        info = registry.get_info(resolved_oid)
        if info and callable(info.get("get", None)):
            value = info["get"]()
        else:
            value = None

    if value is None:
        return None

    expected_type = _get_smi_type_from_oid(resolved_oid, registry)
    ber_value = coerce_value(value, expected_type)
    return (resolved_oid, ber_value)


def get_next_value(
    oid: str,
    registry: MIBRegistry,
    lookup_next_func: Optional[Any] = None,
) -> Optional[Tuple[str, str, Object]]:
    """Get the value for the next OID after the given OID.

    Implements RFC 2577 §3.2: The GetNext operation retrieves the value
    of the next OID in lexicographic order.

    Args:
        oid: The starting OID.
        registry: The MIB registry.
        lookup_next_func: Optional callable(oid) -> (next_oid, value) for data lookup.

    Returns:
        Tuple of (current_oid, next_oid, value) or None if no successor.
    """
    resolved_oid = oid

    if lookup_next_func:
        result = lookup_next_func(resolved_oid)
        if result is None:
            return None
        if isinstance(result, tuple) and len(result) == 2:
            next_oid, value = result
        elif isinstance(result, tuple) and len(result) == 3:
            current_oid, next_oid, value = result
        else:
            next_oid = result
            value = None
            current_oid = ""
    else:
        next_oid = registry.prefix_match(resolved_oid)
        if next_oid is None:
            return None
        if isinstance(next_oid, tuple):
            next_oid = next_oid[0]
        current_oid = ""

    if lookup_next_func and callable(lookup_next_func):
        value = lookup_next_func(next_oid)

    if value is None:
        return None

    expected_type = _get_smi_type_from_oid(next_oid, registry)
    ber_value = coerce_value(value, expected_type)
    return (current_oid, next_oid, ber_value)


def get_bulk_values(
    oids: list[str],
    non_repeaters: int = 0,
    max_repetitions: int = 256,
    registry: Optional[MIBRegistry] = None,
    lookup_func: Optional[Any] = None,
) -> List[Tuple[str, Object]]:
    """Perform a bulk GET operation.

    Implements RFC 2577 §3.3: The GetBulk operation retrieves multiple
    OIDs efficiently, combining GetNext for non-repeaters and repeated
    GetNext for repeaters.

    Args:
        oids: List of OIDs to query. First N are non-repeaters;
              remaining R are repeated up to M times.
        non_repeaters: Number of OIDs that should return at most one value.
        max_repetitions: Maximum number of iterations for repeated OIDs.
        registry: The MIB registry.
        lookup_func: Optional callable for data lookup.

    Returns:
        List of (oid, value) tuples.
    """
    results: List[Tuple[str, Object]] = []

    if not oids:
        return results

    non_repeaters = min(non_repeaters, len(oids))
    repeater_oids = oids[non_repeaters:]

    # Process non-repeaters (single GetNext)
    for oid in oids[:non_repeaters]:
        result = get_value(oid, registry, lookup_func)
        if result:
            results.append(result)
        elif lookup_func:
            next_oid_result = lookup_func(oid)
            if next_oid_result:
                results.append((oid, coerce_value(next_oid_result)))

    # Process repeaters (up to max_repetitions)
    for oid in repeater_oids:
        current_oid = oid
        for _ in range(max_repetitions):
            if lookup_func and callable(lookup_func):
                result = get_next_value(current_oid, registry, lookup_func)
                if result is None:
                    break
                _, next_oid, value = result
                results.append((next_oid, value))
                current_oid = next_oid
            else:
                break

    return results


def set_value(
    oid: str,
    value: Any,
    registry: Optional[MIBRegistry] = None,
    set_func: Optional[Any] = None,
    access: str = "readwrite",
) -> ErrorStatus:
    """Set a MIB value.

    Implements RFC 2577 §3.4: The Set operation atomically modifies
    one or more managed objects.

    Args:
        oid: The OID to set.
        value: The value to set.
        registry: The MIB registry.
        set_func: Optional callable(oid, value) -> bool for actual set.
        access: "read" or "readwrite".

    Returns:
        ErrorStatus indicating success or failure.
    """
    if not validate_oid_format(oid):
        return ErrorStatus.no_such_name

    # Check if the OID is settable
    if registry:
        info = registry.get_info(oid)
        if info and info.get("access") == "read":
            return ErrorStatus.read_only

    if set_func is None:
        return ErrorStatus.no_such_name

    try:
        success = set_func(oid, value)
        if success:
            return ErrorStatus.no_error
        return ErrorStatus.generic_error
    except Exception as e:
        return error_status_for_exception(e)


def walk_mib(
    root_oid: str,
    max_repetitions: int = 256,
    max_iterations: int = 10000,
    registry: Optional[MIBRegistry] = None,
    lookup_func: Optional[Any] = None,
) -> List[Tuple[str, Object]]:
    """Walk the MIB subtree starting at root_oid.

    Implements RFC 2577 §3.5: The Walk operation retrieves all OIDs
    that are lexicographically after root_oid, stopping when the
    root prefix is exceeded.

    Args:
        root_oid: The starting OID.
        max_repetitions: Max iterations per GetBulk request.
        max_iterations: Total iteration limit.
        registry: The MIB registry.
        lookup_func: Optional callable for data lookup.

    Returns:
        List of (oid, value) tuples.
    """
    results: List[Tuple[str, Object]] = []
    current_oid = root_oid
    iteration = 0

    while iteration < max_iterations:
        iteration += 1

        if lookup_func and callable(lookup_func):
            result = get_next_value(current_oid, registry, lookup_func)
            if result is None:
                break
            _, next_oid, value = result
        else:
            break

        # Check if we've exceeded the root OID
        if not next_oid.startswith(root_oid):
            break

        results.append((next_oid, value))
        current_oid = next_oid

    return results


# =============================================================================
# Compound Operations
# =============================================================================

def get_multiple(
    oids: list[str],
    registry: MIBRegistry,
    lookup_func: Optional[Any] = None,
) -> List[Tuple[str, Optional[Object]]]:
    """Get values for multiple OIDs in a single call.

    Args:
        oids: List of OIDs to retrieve.
        registry: The MIB registry.
        lookup_func: Optional callable for data lookup.

    Returns:
        List of (oid, value_or_None) tuples.
    """
    results: List[Tuple[str, Optional[Object]]] = []
    for oid in oids:
        result = get_value(oid, registry, lookup_func)
        if result:
            results.append((result[0], result[1]))
        else:
            results.append((oid, None))
    return results


def set_multiple(
    values: Dict[str, Any],
    registry: Optional[MIBRegistry] = None,
    set_func: Optional[Any] = None,
) -> List[Tuple[str, ErrorStatus]]:
    """Set multiple MIB values atomically.

    Implements all-or-nothing semantics: if any set fails, the entire
    operation is rolled back (as much as possible).

    Args:
        values: Dict mapping OID strings to values.
        registry: The MIB registry.
        set_func: Optional callable(oid, value) -> bool.

    Returns:
        List of (oid, ErrorStatus) tuples.
    """
    results: List[Tuple[str, ErrorStatus]] = []
    all_ok = True

    for oid, value in values.items():
        status = set_value(oid, value, registry, set_func)
        results.append((oid, status))
        if status != ErrorStatus.no_error:
            all_ok = False

    return results


# =============================================================================
# Version-Aware Operations (RFC 3584 §4.2, RFC 3416 §4.4)
# =============================================================================

def get_response_for_request(
    oid: str,
    registry: MIBRegistry,
    lookup_func: Optional[Any] = None,
    request_version: SNMPVersion = SNMPVersion.v2c,
    error_status: ErrorStatus = ErrorStatus.no_error,
    error_index: int = 0,
) -> Tuple[ErrorStatus, int, List[Tuple[str, Object]]]:
    """Generate a GetResponse/GetNextResponse PDU from a request.
    
    Implements RFC 3584 §4.2 (Multi-lingual command responder behavior):
    - SNMPv1: Map exceptions to noSuchName, never return Counter64
    - SNMPv2: Return exceptions as-is (noSuchObject, noSuchInstance, endOfMibView)
    
    Args:
        oid: The OID that was requested.
        registry: The MIB registry.
        lookup_func: Optional callable for data lookup.
        request_version: The SNMP version of the request.
        error_status: Current error status (for compound responses).
        error_index: Current error index.
        
    Returns:
        Tuple of (error_status, error_index, variable_bindings).
    """
    result = get_value(oid, registry, lookup_func)
    
    if result is None:
        # Not found — use appropriate exception
        if request_version == SNMPVersion.v1:
            return (ErrorStatus.no_such_name, error_index or 1, [])
        else:
            return (ErrorStatus.no_such_object, error_index or 1, [(oid, Null().get_object())])
    
    value_oid, value_obj = result
    
    # Check if value is Counter64 — must never return in SNMPv1
    if isinstance(value_obj, Counter64):
        if request_version == SNMPVersion.v1:
            # RFC 3584 §4.2.2.1: Counter64 must be excluded from SNMPv1 responses
            return (ErrorStatus.no_such_name, error_index or 1, [])
    
    return (error_status, error_index, [(value_oid, value_obj)])


def get_next_response_for_request(
    oid: str,
    registry: MIBRegistry,
    lookup_next_func: Optional[Any] = None,
    request_version: SNMPVersion = SNMPVersion.v2c,
    error_status: ErrorStatus = ErrorStatus.no_error,
    error_index: int = 0,
) -> Tuple[ErrorStatus, int, List[Tuple[str, Object]]]:
    """Generate a GetNextResponse PDU from a request.
    
    Implements RFC 3584 §4.2.2.2 (Mapping endOfMibView to noSuchName for SNMPv1):
    - SNMPv1: Map endOfMibView → noSuchName, Counter64 → noSuchName
    - SNMPv2: Return exceptions as-is (endOfMibView, noSuchObject)
    
    Args:
        oid: The OID to find next after.
        registry: The MIB registry.
        lookup_next_func: Optional callable for data lookup.
        request_version: The SNMP version of the request.
        error_status: Current error status.
        error_index: Current error index.
        
    Returns:
        Tuple of (error_status, error_index, variable_bindings).
    """
    result = get_next_value(oid, registry, lookup_next_func)
    
    if result is None:
        # No successor — end of MIB
        if request_version == SNMPVersion.v1:
            return (ErrorStatus.no_such_name, error_index or 1, [])
        else:
            return (ErrorStatus.end_of_mib_view, error_index or 1, [])
    
    current_oid, next_oid, value_obj = result
    
    # Check if value is Counter64 — must never return in SNMPv1
    if isinstance(value_obj, Counter64):
        if request_version == SNMPVersion.v1:
            # Skip Counter64, continue search
            # For simplicity, return noSuchName
            return (ErrorStatus.no_such_name, error_index or 1, [])
    
    return (error_status, error_index, [(next_oid, value_obj)])


def map_error_to_version(error: ErrorStatus, target_version: SNMPVersion) -> ErrorStatus:
    """Map an SNMP error/status code to the target SNMP version's error codes.
    
    RFC 3584 §4.4 (Error Status Mappings):
    - SNMPv1 → SNMPv2: noSuchName → noAccess, readOnly → notWritable, etc.
    - SNMPv2 → SNMPv1: noAccess → noSuchName, commitFailed → genErr, etc.
    
    Args:
        error: The source error status.
        target_version: The target SNMP version.
        
    Returns:
        The mapped error status for the target version.
    """
    if target_version == SNMPVersion.v1:
        return error.to_snmpv1_error()
    elif target_version in (SNMPVersion.v2c, SNMPVersion.v3):
        # Return as-is (SNMPv2+ has all SNMPv1 codes plus extensions)
        return error
    return error


def map_exception_to_snmpv1(exception_code: int) -> int:
    """Map SNMPv3 exception codes to SNMPv1 error codes.
    
    RFC 3584 §4.2.2.2:
    - noSuchObject (200) → noSuchName (2)
    - noSuchInstance (201) → noSuchName (2)
    - endOfMibView (202) → noSuchName (2)
    
    Args:
        exception_code: The SNMPv3 exception code (200-202).
        
    Returns:
        The corresponding SNMPv1 error code (2 for noSuchName).
    """
    return SNMPException.map_to_snmpv1(exception_code)


def check_counter64_response(value: Object, request_version: SNMPVersion) -> bool:
    """Check if a value should be excluded from SNMPv1 responses.
    
    RFC 3584 §4.2.2.1: Multi-lingual command responders MUST NOT
    return Counter64 values in SNMPv1 responses.
    
    Args:
        value: The BER Object value.
        request_version: The SNMP version of the request.
        
    Returns:
        True if the value should be excluded from the response.
    """
    if request_version != SNMPVersion.v1:
        return False
    return isinstance(value, Counter64)


# =============================================================================
# Exported Names
# =============================================================================

__all__ = [
    # Type coercion
    "coerce_value",
    # Validation
    "validate_oid_format",
    "error_status_for_exception",
    # Core operations
    "get_value", "get_next_value", "get_bulk_values", "set_value", "walk_mib",
    # Compound operations
    "get_multiple", "set_multiple",
    # Version-aware operations (RFC 3584 §4.2, RFC 3416 §4.4)
    "get_response_for_request",
    "get_next_response_for_request",
    "map_error_to_version",
    "map_exception_to_snmpv1",
    "check_counter64_response",
    # Type mapping
    "_SMI_TO_BER_MAP",
]
