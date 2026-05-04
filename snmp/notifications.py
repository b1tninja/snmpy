"""Trap and Notification data contracts.

Provides structured dataclasses that separate semantic SNMP notification data
from BER encoding. These data contracts are consumed by the application layer
while PDU classes handle BER serialization.

Encoding/Decoding Flow:
    Raw bytes (BER) -> SNMPDatagram.decode() -> PDU Object
    PDU Object -> Notification.from_pdu() -> Notification data contract
    Notification -> application processing

Usage:
    >>> from snmp.notifications import TrapNotification, SNMPv2Notification
    >>> notification = TrapNotification.from_pdu(trap_pdu)
    >>> print(f"Trap: {notification.trap_type} from {notification.source}")
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from snmp.enums import SNMPVersion

if TYPE_CHECKING:
    from ber.object import Object as BerObject


class TrapType(Enum):
    """SNMPv1 standard trap types.

    Per RFC 1157 Section 4.1.6.
    """
    COLD_START = 0
    WARM_START = 1
    LINK_DOWN = 2
    LINK_UP = 3
    AUTHENTICATION_FAILURE = 4
    EGP_NEIGHBOR_LOSS = 5
    ENTERPRISE_SPECIFIC = 6


class VariableValue:
    """Union type for SNMP variable binding values.

    Represents the different BER value types that can appear in variable bindings.
    Stores Python-native values, not raw BER bytes.
    """

    __slots__ = ('value', 'value_type')

    def __init__(self, value, value_type: str = "raw") -> None:
        """Initialize the variable value.

        Args:
            value: The Python-native value (int, str, bytes, None, etc.).
            value_type: Type hint for the value category.
        """
        self.value = value
        self.value_type = value_type

    @classmethod
    def from_int(cls, val: int) -> 'VariableValue':
        """Create from an integer value."""
        return cls(val, "integer")

    @classmethod
    def from_str(cls, val: str) -> 'VariableValue':
        """Create from a string value."""
        return cls(val, "string")

    @classmethod
    def from_bytes(cls, val: bytes) -> 'VariableValue':
        """Create from bytes."""
        return cls(val, "bytes")

    @classmethod
    def from_oid(cls, val: str) -> 'VariableValue':
        """Create from an OID string."""
        return cls(val, "oid")

    @classmethod
    def from_null(cls) -> 'VariableValue':
        """Create from a NULL value."""
        return cls(None, "null")

    @classmethod
    def from_object(cls, val_obj: "BerObject") -> 'VariableValue':
        """Create from a BER Object using type coercion.

        Uses the BER Object's own type coercion methods (__int__, __str__)
        to extract native Python values, avoiding raw .value access.

        Args:
            val_obj: A BER Object instance.

        Returns:
            VariableValue with a Python-native value extracted via
            int(), str(), or bytes() coercion.
        """
        # None check
        if val_obj is None:
            return cls.from_null()

        # Check if the BER Object itself supports __int__ (Integer, etc.)
        # This catches Integer before the bytes path since Integer extends bytes
        try:
            # Only use __int__ if it produces a meaningful result (not the bytes length)
            int_val = int(val_obj)
            if isinstance(int_val, int) and not isinstance(int_val, bool):
                return cls.from_int(int_val)
        except (TypeError, ValueError):
            pass

        # Check the underlying value type for dispatch
        raw = val_obj.value

        # Empty bytes → treat as zero
        if isinstance(raw, bytes) and len(raw) == 0:
            return cls.from_int(0)

        # Bytes (OctetString): decode as string or raw bytes
        if isinstance(raw, bytes) and len(raw) > 0:
            try:
                decoded = raw.decode("utf-8")
                # If all chars are printable, return as string
                if all(c.isprintable() for c in decoded):
                    return cls.from_str(decoded)
            except (UnicodeDecodeError, AttributeError):
                pass
            return cls.from_bytes(raw)

        # Try str() coercion (handles ObjectIdentifier, etc.)
        try:
            return cls.from_str(str(raw))
        except Exception:
            pass

        # Fallback: store as raw
        return cls(value=raw, value_type="raw")

    def __str__(self) -> str:
        if self.value is None:
            return "None"
        return str(self.value)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.value!r}, {self.value_type!r})"


@dataclass(frozen=True)
class VariableBinding:
    """A single variable binding (VarBind) from an SNMP message.

    Attributes:
        oid: Object Identifier string (e.g., "1.3.6.1.2.1.1.3").
        value: Decoded value (Python-native).
    """
    oid: str
    value: VariableValue

    @classmethod
    def from_dict(cls, oid: str, value) -> 'VariableBinding':
        """Create a VariableBinding from a value or VariableBinding.

        Args:
            oid: Object Identifier string.
            value: Can be a VariableBinding (passthrough), dict with oid/value,
                  or raw value.

        Returns:
            VariableBinding instance.
        """
        if isinstance(value, VariableBinding):
            return value
        return VariableBinding(oid=oid, value=value)


@dataclass(frozen=True)
class TrapNotification:
    """Structured SNMPv1 Trap-PDU notification.

    This is the data contract for SNMPv1 trap notifications. It separates
    the semantic data from the BER encoding layer.

    Attributes:
        trap_type: The trap type name (e.g., "coldStart", "linkDown").
        source: Source IP address of the trap sender.
        version: SNMP version.
        community: Community name.
        enterprise: Enterprise OID string.
        agent_addr: Agent IP address.
        generic_trap: Generic trap type integer (0-6).
        specific_code: Specific trap code integer.
        time_stamp: TimeTicks value (hundredths of seconds since boot).
        variables: Tuple of variable bindings.
    """
    trap_type: str
    source: str
    version: SNMPVersion
    community: str
    enterprise: str
    agent_addr: str
    generic_trap: int
    specific_code: int
    time_stamp: int
    variables: tuple[VariableBinding, ...]

    @property
    def trap_type_enum(self) -> TrapType:
        """Get the trap type as an enum."""
        try:
            return TrapType(self.generic_trap)
        except (ValueError, KeyError):
            return TrapType.ENTERPRISE_SPECIFIC

    @classmethod
    def from_pdu(cls, pdu) -> 'TrapNotification':
        """Create a TrapNotification from a Trap PDU object.

        Args:
            pdu: A Trap PDU object (snmp.pdus.Trap).

        Returns:
            TrapNotification instance.
        """
        from snmp.pdus import Trap

        assert isinstance(pdu, Trap), f"Expected Trap PDU, got {type(pdu).__name__}"

        # Extract variable bindings
        vars_list: list[VariableBinding] = []
        if pdu.variable_bindings and len(pdu.variable_bindings.value):
            for var_obj in pdu.variable_bindings.value:
                if var_obj is not None and var_obj.value is not None and len(var_obj.value) >= 2:
                    oid_obj = var_obj.value[0]
                    val_obj = var_obj.value[1]
                    oid_str = str(oid_obj) if oid_obj is not None else "unknown"

                    # Use VariableValue.from_object for type-safe value extraction
                    value = VariableValue.from_object(val_obj)

                    vars_list.append(VariableBinding(oid=oid_str, value=value))

        # Map generic_trap to name — use int() which delegates to __int__()
        trap_names = {
            0: "coldStart",
            1: "warmStart",
            2: "linkDown",
            3: "linkUp",
            4: "authenticationFailure",
            5: "egpNeighborLoss",
            6: "enterpriseSpecific",
        }

        return cls(
            trap_type=trap_names.get(int(pdu.generic_trap) if hasattr(pdu.generic_trap, '__int__') else pdu.generic_trap, "unknown"),
            source="",  # Source is set by TrapReceptor
            version=SNMPVersion.v1,
            community="",  # Set by receptor
            enterprise=str(pdu.enterprise) if pdu.enterprise else "",
            agent_addr=str(pdu.agent_addr) if pdu.agent_addr else "",
            generic_trap=int(pdu.generic_trap) if hasattr(pdu.generic_trap, '__int__') else 0,
            specific_code=int(pdu.specific_code) if hasattr(pdu.specific_code, '__int__') else 0,
            time_stamp=int(pdu.time_stamp) if hasattr(pdu.time_stamp, '__int__') else 0,
            variables=tuple(vars_list),
        )

    def __repr__(self) -> str:
        return (
            f"TrapNotification(trap_type={self.trap_type!r}, "
            f"generic_trap={self.generic_trap}, "
            f"time_stamp={self.time_stamp})"
        )


@dataclass(frozen=True)
class SNMPv2Notification:
    """Structured SNMPv2-Trap-PDU notification.

    This is the data contract for SNMPv2c trap notifications. Unlike SNMPv1,
    SNMPv2-Trap-PDU uses variable bindings directly instead of separate
    enterprise/agentAddr/genericTrap/specificCode/timeStamp fields.

    Attributes:
        request_id: Request identifier from the PDU.
        error_status: Error status integer.
        error_index: Error index integer.
        trap_oid: The trap OID (snmpTrapOID.0 variable binding).
        source: Source IP address.
        version: SNMP version.
        community: Community name.
        variables: Tuple of variable bindings.
    """
    request_id: int
    error_status: int
    error_index: int
    trap_oid: str
    source: str
    version: SNMPVersion
    community: str
    variables: tuple[VariableBinding, ...]

    @classmethod
    def from_pdu(cls, pdu) -> 'SNMPv2Notification':
        """Create an SNMPv2Notification from an SNMPv2Trap PDU.

        Args:
            pdu: An SNMPv2Trap PDU object.

        Returns:
            SNMPv2Notification instance.
        """
        from snmp.pdus import SNMPv2Trap

        assert isinstance(pdu, SNMPv2Trap), f"Expected SNMPv2Trap PDU, got {type(pdu).__name__}"

        # Extract variable bindings and find trap OID
        vars_list: list[VariableBinding] = []
        trap_oid = ""

        if pdu.variable_bindings and len(pdu.variable_bindings.value):
            for var_obj in pdu.variable_bindings.value:
                if var_obj is not None and var_obj.value is not None and len(var_obj.value) >= 2:
                    oid_obj = var_obj.value[0]
                    val_obj = var_obj.value[1]
                    oid_str = str(oid_obj) if oid_obj is not None else "unknown"

                    # Check if this is the snmpTrapOID.0 binding
                    if oid_str == "1.3.6.1.6.3.1.1.4.1.0":
                        trap_oid = str(val_obj) if val_obj is not None else ""

                    # Use VariableValue.from_object for type-safe value extraction
                    value = VariableValue.from_object(val_obj)

                    vars_list.append(VariableBinding(oid=oid_str, value=value))

        return cls(
            request_id=int(pdu.request_id) if hasattr(pdu.request_id, '__int__') else 0,
            error_status=int(pdu.error_status) if hasattr(pdu.error_status, '__int__') else 0,
            error_index=int(pdu.error_index) if hasattr(pdu.error_index, '__int__') else 0,
            trap_oid=trap_oid,
            source="",  # Set by TrapReceptor
            version=SNMPVersion.v2c,
            community="",  # Set by receptor
            variables=tuple(vars_list),
        )

    def __repr__(self) -> str:
        return (
            f"SNMPv2Notification(trap_oid={self.trap_oid!r}, "
            f"request_id={self.request_id})"
        )


@dataclass(frozen=True)
class InformNotification:
    """Structured SNMP InformRequest notification.

    Attributes:
        request_id: Request identifier.
        error_status: Error status.
        error_index: Error index.
        source: Source IP address.
        version: SNMP version.
        community: Community name.
        variables: Variable bindings.
    """
    request_id: int
    error_status: int
    error_index: int
    source: str
    version: SNMPVersion
    community: str
    variables: tuple[VariableBinding, ...]

    @classmethod
    def from_pdu(cls, pdu) -> 'InformNotification':
        """Create InformNotification from an InformRequest PDU."""
        from snmp.pdus import InformRequest

        assert isinstance(pdu, InformRequest), f"Expected InformRequest PDU, got {type(pdu).__name__}"

        vars_list: list[VariableBinding] = []
        if pdu.variable_bindings and len(pdu.variable_bindings.value):
            for var_obj in pdu.variable_bindings.value:
                if var_obj is not None and var_obj.value is not None and len(var_obj.value) >= 2:
                    oid_obj = var_obj.value[0]
                    val_obj = var_obj.value[1]
                    oid_str = str(oid_obj) if oid_obj is not None else "unknown"

                    # Use VariableValue.from_object for type-safe value extraction
                    value = VariableValue.from_object(val_obj)
                    vars_list.append(VariableBinding(oid=oid_str, value=value))

        return cls(
            request_id=int(pdu.request_id) if hasattr(pdu.request_id, '__int__') else 0,
            error_status=int(pdu.error_status) if hasattr(pdu.error_status, '__int__') else 0,
            error_index=int(pdu.error_index) if hasattr(pdu.error_index, '__int__') else 0,
            source="",
            version=SNMPVersion.v2c,
            community="",
            variables=tuple(vars_list),
        )

    def __repr__(self) -> str:
        return (
            f"InformNotification(request_id={self.request_id}, "
            f"error_status={self.error_status})"
        )


@dataclass(frozen=True)
class ReportNotification:
    """Structured Report PDU notification.

    Attributes:
        request_id: Request identifier.
        error_status: Error status.
        error_index: Error index.
        source: Source IP address.
        version: SNMP version.
        community: Community name.
        variables: Variable bindings (typically contains report parameters).
    """
    request_id: int
    error_status: int
    error_index: int
    source: str
    version: SNMPVersion
    community: str
    variables: tuple[VariableBinding, ...]

    @classmethod
    def from_pdu(cls, pdu) -> 'ReportNotification':
        """Create ReportNotification from a Report PDU."""
        from snmp.pdus import Report

        assert isinstance(pdu, Report), f"Expected Report PDU, got {type(pdu).__name__}"

        vars_list: list[VariableBinding] = []
        if pdu.variable_bindings and len(pdu.variable_bindings.value):
            for var_obj in pdu.variable_bindings.value:
                if var_obj is not None and var_obj.value is not None and len(var_obj.value) >= 2:
                    oid_obj = var_obj.value[0]
                    val_obj = var_obj.value[1]
                    oid_str = str(oid_obj) if oid_obj is not None else "unknown"

                    # Use VariableValue.from_object for type-safe value extraction
                    value = VariableValue.from_object(val_obj)
                    vars_list.append(VariableBinding(oid=oid_str, value=value))

        return cls(
            request_id=int(pdu.request_id) if hasattr(pdu.request_id, '__int__') else 0,
            error_status=int(pdu.error_status) if hasattr(pdu.error_status, '__int__') else 0,
            error_index=int(pdu.error_index) if hasattr(pdu.error_index, '__int__') else 0,
            source="",
            version=SNMPVersion.v2c,
            community="",
            variables=tuple(vars_list),
        )

    def __repr__(self) -> str:
        return (
            f"ReportNotification(request_id={self.request_id}, "
            f"error_status={self.error_status})"
        )


# =============================================================================
# Union Type for All Notification Types
# =============================================================================

TrapNotificationType = TrapNotification | SNMPv2Notification | InformNotification | ReportNotification


def decode_notification(pdu, source: str = "", community: str = "public") -> TrapNotificationType:
    """Decode a PDU into the appropriate notification type.

    This is the central dispatch function that converts raw PDU objects into
    typed notification data contracts.

    Args:
        pdu: A PDU object (Trap, SNMPv2Trap, InformRequest, Report).
        source: Source IP address.
        community: Community name.

    Returns:
        Typed notification dataclass instance.
    """
    from snmp.pdus import Trap, SNMPv2Trap, InformRequest, Report

    if isinstance(pdu, Trap):
        notification = TrapNotification.from_pdu(pdu)
    elif isinstance(pdu, SNMPv2Trap):
        notification = SNMPv2Notification.from_pdu(pdu)
    elif isinstance(pdu, InformRequest):
        notification = InformNotification.from_pdu(pdu)
    elif isinstance(pdu, Report):
        notification = ReportNotification.from_pdu(pdu)
    else:
        raise ValueError(f"Unknown PDU type: {type(pdu).__name__}")

    # Set source and community on the notification
    # Note: dataclasses are frozen, so we need to create new instances
    notification = notification.__class__(
        **{**notification.__dict__, 'source': source, 'community': community}
    )

    return notification