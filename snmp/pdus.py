"""SNMP Protocol Data Units (PDUs).

Implements RFC 1157 §4.1 (SNMPv1) and RFC 1905 §2 (SNMPv2c):
- GetRequest, GetNextRequest, GetResponse, SetRequest, Trap (SNMPv1)
- GetBulkRequest, Report, InformRequest, SNMPv2-Trap (SNMPv2)
"""

from __future__ import annotations

from random import randint
from typing import TYPE_CHECKING, Iterator, Optional, Type, TypeVar

import snmp.mib
from ber.enums import TagClassEnum
from ber.object import (
    Object,
    ObjectTag,
    Null,
    ObjectValue,
    ObjectIdentifier,
    Integer,
    Sequence,
)
from snmp.enums import ErrorStatus

if TYPE_CHECKING:
    from snmp.datagram import SNMPDatagram


T = TypeVar("T", bound="PDU")


# ---------------------------------------------------------------------------
# Type alias for MIB value results returned from handlers / MIB lookups
# ---------------------------------------------------------------------------

MibValue = object  # Any BER Object, or None


# =========================================================================
# PDU — dict[ObjectIdentifier, Object] + Object for BER encoding
# =========================================================================

class PDU(Object, dict):
    """Base SNMP PDU class.

    PDU inherits from both Object (for BER encoding) and dict (for
    variable bindings). This gives us:
    - BER encoding via Object.__bytes__(), Object.__init__(), etc.
    - All Python dict methods: items(), keys(), values(), get(), __getitem__(),
      __setitem__(), __delitem__(), __iter__, __len__, in, etc.

    Variable bindings are stored as a native dict mapping ObjectIdentifier
    bytes to BER Object values.

    Usage:
        # Iterate over (oid, value) pairs directly on PDU
        for oid, value in pdu:
            print(f"{oid} = {value}")

        # OID lookup
        value = pdu.get(ObjectIdentifier(b"..."))

        # Membership test
        if "1.3.6.1.2.1.1.1.0" in pdu:
            ...
    """

    _ber_obj: Object  # Internal BER object — BER objects are immutable

    tag_class = TagClassEnum.context_specific
    is_constructed = True
    tag_id: Optional[int] = None
    field_names: tuple[str, ...] = (
        "request_id",
        "error_status",
        "error_index",
        "variable_bindings",
    )

    @property
    def tag(self) -> ObjectTag:
        """Return the ASN.1 tag."""
        return self._ber_obj.tag

    @property
    def value(self):
        """Return the BER value."""
        return self._ber_obj.value

    @classmethod
    def get_object_tag(cls) -> ObjectTag:
        """Get the ObjectTag for this PDU type."""
        assert cls.tag_id is not None
        return ObjectTag(cls.tag_class, cls.is_constructed, cls.tag_id)

    @classmethod
    def from_object(cls: Type[T], obj: Object) -> T:
        """Create a PDU instance from a raw BER Object.

        Unpacks *obj.value* according to ``cls.field_names`` and assigns
        each element to the corresponding attribute. Also populates the
        dict interface via ``_populate_from_varbinds()``.

        Args:
            obj: Object containing PDU data.

        Returns:
            PDU instance.
        """
        assert isinstance(obj, Object)
        values = obj.value
        expected = len(cls.field_names)
        assert len(values) == expected, (
            f"{cls.__name__} PDU expects {expected} field(s) ({', '.join(cls.field_names)}), "
            f"got {len(values)}"
        )
        pdu = cls.__new__(cls)
        # BER objects are immutable — store reference directly
        object.__setattr__(pdu, '_ber_obj', obj)
        for name, val in zip(cls.field_names, values):
            setattr(pdu, name, val)
        # Populate dict interface (mimics __init__ behavior)
        dict.__init__(pdu)
        pdu._populate_from_varbinds()
        return pdu

    def __init__(
        self,
        tag: Optional[ObjectTag] = None,
        request_id: Optional[Object] = None,
        error_status: Optional[Object] = None,
        error_index: Optional[Object] = None,
        variable_bindings: Optional[Object] = None,
    ) -> None:
        if request_id is None:
            request_id = Integer.from_int(randint(1 << 24, 1 << 31)).get_object()
        assert isinstance(request_id.value, Integer)
        self.request_id = request_id

        if error_status is None:
            error_status = Integer.from_int(ErrorStatus.no_error).get_object()
        assert isinstance(error_status.value, Integer)
        self.error_status = error_status

        if error_index is None:
            error_index = Integer.from_int(0).get_object()
        assert isinstance(error_index.value, Integer)
        self.error_index = error_index

        assert variable_bindings is not None
        self.variable_bindings = variable_bindings

        # Create a fresh BER Object — not monkey-patching existing attrs
        ber_obj = Object.__new__(Object)
        ber_obj.tag = self.get_object_tag() if tag is None else tag
        ber_obj.value = [self.request_id, self.error_status, self.error_index, self.variable_bindings]
        object.__setattr__(self, '_ber_obj', ber_obj)

        # Populate dict with variable bindings
        self._populate_from_varbinds()

    def _populate_from_varbinds(self) -> None:
        """Populate dict from variable_bindings Sequence."""
        if isinstance(self.variable_bindings, Object) and isinstance(self.variable_bindings.value, list):
            for var_obj in self.variable_bindings.value:
                if isinstance(var_obj, Object) and isinstance(var_obj.value, list) and len(var_obj.value) >= 2:
                    oid = var_obj.value[0].value
                    val = var_obj.value[1]
                    dict.__setitem__(self, oid, val)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"request_id={self.request_id}, "
            f"error_status={self.error_status}, "
            f"error_index={self.error_index}, "
            f"variable_bindings={self.variable_bindings})"
        )

    def __len__(self) -> int:
        """Return number of variable bindings — like dict.__len__()."""
        return dict.__len__(self)

    def __iter__(self) -> Iterator[tuple[ObjectIdentifier, Object]]:
        """Iterate over (oid, value) pairs — like dict.items()."""
        return iter(dict.items(self))

    def __getitem__(self, key: object) -> Object:
        """Access variable binding by OID — like dict.__getitem__()."""
        return dict.__getitem__(self, key)  # type: ignore[arg-type]

    def __contains__(self, key: object) -> bool:
        """Check if OID is present — like dict.__contains__()."""
        return dict.__contains__(self, key)  # type: ignore[arg-type]

    def get(self, key: object, default: Optional[Object] = None) -> Optional[Object]:
        """Get a value by OID — like dict.get()."""
        return dict.get(self, key, default)  # type: ignore[arg-type]

    def __eq__(self, other: object) -> bool:
        """Compare PDU instances — like dict.__eq__()."""
        if not isinstance(other, PDU):
            return NotImplemented
        return (dict(self) == dict(other) and
                self.request_id == other.request_id and
                self.error_status == other.error_status and
                self.error_index == other.error_index)


class BulkPDU(PDU):
    """Base SNMP Bulk PDU class (SNMPv2).

    BulkPDU shares the same structure as PDU but with different fields:
    - request-id
    - non-repeaters
    - max-repetitions
    - variable-bindings

    RFC 1905 §2.7, §4.1
    """

    field_names = (
        "request_id",
        "non_repeaters",
        "max_repetitions",
        "variable_bindings",
    )

    def __init__(
        self,
        tag: Optional[ObjectTag] = None,
        request_id: Optional[Object] = None,
        non_repeaters: Optional[Object] = None,
        max_repetitions: Optional[Object] = None,
        variable_bindings: Optional[Object] = None,
    ) -> None:
        if request_id is None:
            request_id = Integer.from_int(randint(1 << 24, 1 << 31)).get_object()
        assert isinstance(request_id.value, Integer)
        self.request_id = request_id

        if non_repeaters is None:
            non_repeaters = Integer.from_int(0).get_object()
        assert isinstance(non_repeaters.value, Integer)
        self.non_repeaters = non_repeaters

        if max_repetitions is None:
            max_repetitions = Integer.from_int(250).get_object()
        assert isinstance(max_repetitions.value, Integer)
        self.max_repetitions = max_repetitions

        assert variable_bindings is not None
        self.variable_bindings = variable_bindings

        # BulkPDU has 4 fields: request-id, non-repeaters, max-repetitions, variable-bindings
        ber_obj = Object.__new__(Object)
        ber_obj.tag = self.get_object_tag() if tag is None else tag
        ber_obj.value = [
            self.request_id,
            self.non_repeaters,
            self.max_repetitions,
            self.variable_bindings,
        ]
        object.__setattr__(self, '_ber_obj', ber_obj)

        # Populate dict with variable bindings
        self._populate_from_varbinds()

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"request_id={self.request_id}, "
            f"non_repeaters={self.non_repeaters}, "
            f"max_repetitions={self.max_repetitions}, "
            f"variable_bindings={self.variable_bindings})"
        )


# =========================================================================
# Request base class (SNMPv1 GET / GETNEXT)
# =========================================================================

class Request(PDU):
    """Base SNMP Request PDU."""

    @classmethod
    def from_oid(cls: Type[T], oid: Optional[object] = None) -> T:
        """Create a Request PDU from an OID string, ``ObjectIdentifier``, or ``Oid``.

        Args:
            oid: Object Identifier. Defaults to snmp.mib.system.

        Returns:
            Request instance.
        """
        from snmp.oid import Oid, resolve_oid

        if oid is None:
            oid = snmp.mib.system
        if isinstance(oid, Oid) or (
            isinstance(oid, str) and (":" in oid and not oid[0].isdigit())
        ):
            oid = ObjectIdentifier.from_string(resolve_oid(oid))  # type: ignore[arg-type]
        elif isinstance(oid, str):
            oid = ObjectIdentifier.from_string(oid)
        if isinstance(oid, ObjectIdentifier):
            oid = oid.get_object()
        else:
            assert isinstance(oid, Object)
            assert isinstance(oid.value, ObjectIdentifier)

        variable_bindings = Sequence.from_list(
            [Sequence.from_list([oid, Null().get_object()])]
        )
        return cls(variable_bindings=variable_bindings)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(request_id={self.request_id})"


class GetRequest(Request):
    """SNMP GetRequest PDU (tag_id=0)."""

    tag_id = 0


class GetNextRequest(Request):
    """SNMP GetNextRequest PDU (tag_id=1)."""

    tag_id = 1


# =========================================================================
# Response PDU
# =========================================================================

class GetResponse(PDU):
    """SNMP GetResponse PDU (tag_id=2)."""

    tag_id = 2

    @classmethod
    def from_object(cls: Type[T], obj: Object) -> T:
        """Create GetResponse from BER Object, computing oid and response."""
        result = super().from_object(obj)
        first_var = result.variable_bindings.value[0]  # type: ignore[index, union-attr]
        result.oid = first_var.value[0]  # type: ignore[assignment]
        result.response = first_var.value[1]  # type: ignore[assignment]
        return result

    def __init__(
        self,
        tag: Optional[ObjectTag] = None,
        request_id: Optional[Object] = None,
        error_status: Optional[Object] = None,
        error_index: Optional[Object] = None,
        variable_bindings: Optional[Object] = None,
    ) -> None:
        super().__init__(tag, request_id, error_status, error_index, variable_bindings)
        # variable_bindings is a Sequence of Sequence of [Object, Object]
        # Each inner element is an Object wrapping the actual value
        first_var = self.variable_bindings.value[0]  # type: ignore[index, union-attr]
        oid_obj = first_var.value[0]  # type: ignore[index]
        assert isinstance(oid_obj, Object)
        self.oid = oid_obj  # Store the Object, not the raw bytes

        resp_obj = first_var.value[1]  # type: ignore[index]
        self.response = resp_obj  # Store the Object

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"request_id={self.request_id}, "
            f"oid={self.oid}, "
            f"response={self.response})"
        )


class SetRequest(Request):
    """SNMP SetRequest PDU (tag_id=3).

    Allows the management station to alter the value of a managed variable.
    Implements all-or-nothing semantics: either all variables are set, or none.

    RFC 1157 §4.1.5
    """

    tag_id = 3


class GetBulkRequest(BulkPDU):
    """SNMP GetBulkRequest-PDU (tag_id=5).

    Requests transfer of potentially large amounts of data,
    including efficient and rapid retrieval of large tables.

    RFC 1905 §2.7, §4.2.3
    """

    tag_id = 5


class InformRequest(PDU):
    """SNMP InformRequest-PDU (tag_id=6).

    Manager-to-manager confirmed notification. Like a trap but with
    request/response semantics — the receiver must send back a Response-PDU.

    RFC 1905 §2.9
    """

    tag_id = 6


class SNMPv2Trap(PDU):
    """SNMPv2-Trap-PDU (tag_id=7).

    Different from RFC 1157 Trap-PDU — uses variable-bindings directly
    instead of enterprise/agentAddr/genericTrap/specificCode/timeStamp fields.

    RFC 1905 §2.10
    """

    tag_id = 7


class Report(PDU):
    """Report-PDU (tag_id=8).

    Used for reporting exceptional conditions and protocol-level errors.
    The precise semantics are defined by the administrative framework in use.

    RFC 1905 §2.8
    """

    tag_id = 8


# =========================================================================
# SNMPv1 Trap-PDU (RFC 1157)
# =========================================================================

class Trap(PDU):
    """SNMP Trap-PDU (tag_id=4).

    An asynchronously generated message, usually indicating some exceptional condition.
    Sent from agent to management station (not a response to any request).

    RFC 1157 §4.1.6
    """

    tag_id = 4

    field_names = (
        "enterprise",
        "agent_addr",
        "generic_trap",
        "specific_code",
        "time_stamp",
        "variable_bindings",
    )

    # Trap type constants per RFC 1157 §4.1.6
    COLD_START = 0
    WARM_START = 1
    LINK_DOWN = 2
    LINK_UP = 3
    AUTHENTICATION_FAILURE = 4
    EGP_NEIGHBOR_LOSS = 5
    ENTERPRISE_SPECIFIC = 6

    def __init__(
        self,
        tag: Optional[ObjectTag] = None,
        enterprise: Optional[Object] = None,
        agent_addr: Optional[Object] = None,
        generic_trap: Optional[Object] = None,
        specific_code: Optional[Object] = None,
        time_stamp: Optional[Object] = None,
        variable_bindings: Optional[Object] = None,
    ) -> None:
        """Initialize Trap-PDU.

        Args:
            tag: The ObjectTag for this PDU.
            enterprise: Object Identifier identifying the enterprise.
            agent_addr: IpAddress of the agent (interface that detected the trap).
            generic_trap: INTEGER trap type (0-6).
            specific_code: INTEGER specific trap code (for enterpriseSpecific traps).
            time_stamp: TimeTicks value (sysUpTime).
            variable_bindings: VarBindList containing trap information.
        """
        if enterprise is None:
            enterprise = ObjectIdentifier.from_string("0").get_object()
        assert isinstance(enterprise.value, ObjectIdentifier)
        self.enterprise = enterprise

        if agent_addr is None:
            agent_addr = ObjectIdentifier.from_string("0.0.0.0").get_object()
        assert isinstance(agent_addr.value, ObjectIdentifier)
        self.agent_addr = agent_addr

        if generic_trap is None:
            generic_trap = Integer.from_int(Trap.COLD_START).get_object()
        assert isinstance(generic_trap.value, Integer)
        self.generic_trap = generic_trap

        if specific_code is None:
            specific_code = Integer.from_int(0).get_object()
        assert isinstance(specific_code.value, Integer)
        self.specific_code = specific_code

        if time_stamp is None:
            time_stamp = Integer.from_int(0).get_object()
        assert isinstance(time_stamp.value, Integer)
        self.time_stamp = time_stamp

        assert variable_bindings is not None
        self.variable_bindings = variable_bindings

        # Trap-PDU has 6 fields (different from standard PDU's 4)
        ber_obj = Object.__new__(Object)
        ber_obj.tag = self.get_object_tag() if tag is None else tag
        ber_obj.value = [
            self.enterprise,
            self.agent_addr,
            self.generic_trap,
            self.specific_code,
            self.time_stamp,
            self.variable_bindings,
        ]
        object.__setattr__(self, '_ber_obj', ber_obj)

        # Populate dict with variable bindings
        self._populate_from_varbinds()

    @classmethod
    def from_trap_type(
        cls: Type[T],
        trap_type: int,
        enterprise: Optional[str] = None,
        agent_addr: Optional[str] = None,
        specific_code: int = 0,
        time_stamp: Optional[int] = None,
        variables: Optional[list[tuple[str, object]]] = None,
    ) -> T:
        """Create a Trap-PDU from a trap type constant.

        Args:
            trap_type: One of Trap.COLD_START, Trap.WARM_START, Trap.LINK_DOWN,
                       Trap.LINK_UP, Trap.AUTHENTICATION_FAILURE,
                       Trap.EGP_NEIGHBOR_LOSS, or Trap.ENTERPRISE_SPECIFIC.
            enterprise: Object Identifier identifying the enterprise.
            agent_addr: IpAddress of the agent.
            specific_code: Specific trap code for enterpriseSpecific traps.
            time_stamp: TimeTicks value (sysUpTime). If None, uses 0.
            variables: List of (oid_string, value) tuples for variable bindings.

        Returns:
            Trap instance.
        """
        if enterprise is None:
            enterprise = ObjectIdentifier.from_string("0")
        if isinstance(enterprise, str):
            enterprise = ObjectIdentifier.from_string(enterprise)
        if isinstance(enterprise, ObjectIdentifier):
            enterprise = enterprise.get_object()
        else:
            assert isinstance(enterprise, Object)
            assert isinstance(enterprise.value, ObjectIdentifier)

        if agent_addr is None:
            agent_addr = ObjectIdentifier.from_string("0.0.0.0")
        if isinstance(agent_addr, str):
            agent_addr = ObjectIdentifier.from_string(agent_addr)
        if isinstance(agent_addr, ObjectIdentifier):
            agent_addr = agent_addr.get_object()
        else:
            assert isinstance(agent_addr, Object)
            assert isinstance(agent_addr.value, ObjectIdentifier)

        if time_stamp is None:
            time_stamp = Integer.from_int(0).get_object()
        assert isinstance(time_stamp.value, Integer)

        generic_trap = Integer.from_int(trap_type).get_object()
        assert isinstance(generic_trap.value, Integer)

        specific_code_obj = Integer.from_int(specific_code).get_object()
        assert isinstance(specific_code_obj.value, Integer)

        if variables:
            # Use factory helper for variable binding construction
            from snmp.factories import make_var_binds
            var_bind_list = make_var_binds(variables)
        else:
            from snmp.factories import make_empty_var_binds
            var_bind_list = make_empty_var_binds()

        return cls(
            enterprise=enterprise,
            agent_addr=agent_addr,
            generic_trap=generic_trap,
            specific_code=specific_code_obj,
            time_stamp=time_stamp,
            variable_bindings=var_bind_list,
        )

    def __repr__(self) -> str:
        trap_names = {
            0: "coldStart",
            1: "warmStart",
            2: "linkDown",
            3: "linkUp",
            4: "authenticationFailure",
            5: "egpNeighborLoss",
            6: "enterpriseSpecific",
        }
        trap_name = trap_names.get(self.generic_trap.value.val, f"unknown({self.generic_trap.value.val})")  # type: ignore[union-attr]
        return (
            f"{self.__class__.__name__}("
            f"enterprise={self.enterprise}, "
            f"agent_addr={self.agent_addr}, "
            f"trap={trap_name}, "
            f"specific_code={self.specific_code}, "
            f"time_stamp={self.time_stamp}, "
            f"variables={self.variable_bindings})"
        )


# PDU registration is handled in snmp/datagram.py to avoid circular imports.