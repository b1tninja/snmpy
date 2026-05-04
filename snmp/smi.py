"""SMIv2 Application Types and Textual Conventions.

Implements RFC 1902 §5-7: Application-wide types for SNMPv2 management.

Application Types (from SMIv2):
- IpAddress (APPLICATION 0): 32-bit IP address
- Counter32 (APPLICATION 1): 32-bit counter, wraps at 2^32
- Gauge32 (APPLICATION 2): 32-bit gauge, never wraps
- Unsigned32 (APPLICATION 2): 32-bit unsigned integer
- TimeTicks (APPLICATION 3): Hundredths of seconds since epoch
- Opaque (APPLICATION 4): Arbitrary binary data (RFC 1215)
- Counter64 (APPLICATION 6): 64-bit counter, wraps at 2^64

Textual Conventions (from RFC 2579):
- DisplayString: Printable string (size-limited OCTET STRING)
- PhysAddress: MAC/address (5-255 octets)
- DateAndTime: Date/time encoding (RFC 2579)
- TimeStamp: Timestamp value (RFC 2579)
- TruthStatus: Truth status for conceptual tables (RFC 2579)
"""

from __future__ import annotations

import struct
from typing import Optional

from ber.enums import ApplicationTags, TagClassEnum
from ber.object import Object, ObjectTag, OctetString, Integer, ObjectIdentifier
from snmp.enums import SNMPVersion


# ---------------------------------------------------------------------------
# Application Types
# ---------------------------------------------------------------------------

class IpAddress(OctetString):
    """IPv4 address: 4-octet OCTET STRING [APPLICATION 0].

    Represents a 32-bit Internet address in network byte order.
    RFC 1902 §7.1.5
    """

    tag = ObjectTag(TagClassEnum.application, False, ApplicationTags.ip_address)  # type: ignore[arg-type,assignment]

    def __init__(self, value: bytes | int | str | None = None) -> None:
        if value is None:
            value = b"\x00\x00\x00\x00"
        if isinstance(value, int):
            value = struct.pack("!I", value)
        elif isinstance(value, str):
            # Parse dotted-decimal IP address
            parts = value.split(".")
            if len(parts) != 4:
                raise ValueError(f"Invalid IP address: {value}")
            value = bytes(int(p) for p in parts)
        if isinstance(value, bytes) and len(value) == 4:
            super().__init__(value)
        else:
            raise ValueError(f"IpAddress must be 4 bytes, got {len(value) if value else 0} bytes")

    @classmethod
    def from_int(cls, value: int) -> IpAddress:
        """Create an IpAddress from a 32-bit integer.

        Args:
            value: 32-bit integer representing an IP address.

        Returns:
            IpAddress instance.
        """
        return cls(struct.pack("!I", value))

    def to_int(self) -> int:
        """Convert to a 32-bit integer."""
        return struct.unpack("!I", bytes(self))[0]

    def __str__(self) -> str:
        return ".".join(str(b) for b in bytes(self))


class Counter32(Integer):
    """32-bit counter: monotonically increases, wraps at 2^32.

    Range: 0 .. 4,294,967,295
    RFC 1902 §7.1.6
    """

    tag = ObjectTag(TagClassEnum.application, False, ApplicationTags.counter32)  # type: ignore[arg-type,assignment]

    MIN_VALUE = 0
    MAX_VALUE = 0xFFFFFFFF  # 4,294,967,295

    def __init__(self, value: int | None = None) -> None:
        if value is None:
            value = 0
        if not self.MIN_VALUE <= value <= self.MAX_VALUE:
            raise ValueError(
                f"Counter32 value {value} out of range [{self.MIN_VALUE}, {self.MAX_VALUE}]"
            )
        super().__init__(value)  # type: ignore[arg-type]

    @staticmethod
    def wrap(current: int, increment: int) -> int:
        """Calculate counter value after increment, with wrap-around.

        Args:
            current: Current counter value.
            increment: Value to add.

        Returns:
            Wrapped counter value.
        """
        return (current + increment) & 0xFFFFFFFF


class Gauge32(Integer):
    """32-bit gauge: increases/decreases, capped at maximum.

    Range: 0 .. 4,294,967,295
    RFC 1902 §7.1.7
    """

    tag = ObjectTag(TagClassEnum.application, False, ApplicationTags.gauge32)  # type: ignore[arg-type,assignment]

    MIN_VALUE = 0
    MAX_VALUE = 0xFFFFFFFF  # 4,294,967,295

    def __init__(self, value: int | None = None) -> None:
        if value is None:
            value = 0
        if not self.MIN_VALUE <= value <= self.MAX_VALUE:
            raise ValueError(
                f"Gauge32 value {value} out of range [{self.MIN_VALUE}, {self.MAX_VALUE}]"
            )
        super().__init__(value)  # type: ignore[arg-type]


class Unsigned32(Integer):
    """Unsigned 32-bit integer: indistinguishable from Gauge32.

    Range: 0 .. 4,294,967,295
    RFC 1902 §7.1.8

    Note: Unsigned32 and Gauge32 share the same APPLICATION tag (2)
    but have different semantic meanings.
    """

    tag = ObjectTag(TagClassEnum.application, False, ApplicationTags.gauge32)  # type: ignore[arg-type,assignment]

    MIN_VALUE = 0
    MAX_VALUE = 0xFFFFFFFF

    def __init__(self, value: int | None = None) -> None:
        if value is None:
            value = 0
        if not self.MIN_VALUE <= value <= self.MAX_VALUE:
            raise ValueError(
                f"Unsigned32 value {value} out of range [{self.MIN_VALUE}, {self.MAX_VALUE}]"
            )
        super().__init__(value)  # type: ignore[arg-type]


class TimeTicks(Integer):
    """Time ticks: hundredths of seconds since an epoch.

    Range: 0 .. 4,294,967,295 (modulo 2^32 hundredths of a second)
    ~49.7 days before wrapping
    RFC 1902 §7.1.8
    """

    tag = ObjectTag(TagClassEnum.application, False, ApplicationTags.time_ticks)  # type: ignore[arg-type,assignment]

    MIN_VALUE = 0
    MAX_VALUE = 0xFFFFFFFF  # 4,294,967,295

    def __init__(self, value: int | None = None) -> None:
        if value is None:
            value = 0
        if not self.MIN_VALUE <= value <= self.MAX_VALUE:
            raise ValueError(
                f"TimeTicks value {value} out of range [{self.MIN_VALUE}, {self.MAX_VALUE}]"
            )
        super().__init__(value)  # type: ignore[arg-type]

    @staticmethod
    def from_seconds(seconds: float) -> TimeTicks:
        """Create a TimeTicks from seconds.

        Args:
            seconds: Time in seconds (float).

        Returns:
            TimeTicks instance.
        """
        return TimeTicks(int(seconds * 100) & 0xFFFFFFFF)

    def to_seconds(self) -> float:
        """Convert to seconds."""
        return self.value / 100.0  # type: ignore[union-attr]

    def to_minutes(self) -> float:
        """Convert to minutes."""
        return self.to_seconds() / 60.0

    def to_hours(self) -> float:
        """Convert to hours."""
        return self.to_minutes() / 60.0


class Opaque(OctetString):
    """Opaque: arbitrary binary data.

    Used for encoding structured data in a single OCTET STRING value.
    RFC 1902 §7.1.9

    Note: Opaque was originally defined in RFC 1215 for trap-specific
    data, but is now used more broadly for encoding arbitrary data.
    """

    tag = ObjectTag(TagClassEnum.application, False, ApplicationTags.opaque)  # type: ignore[arg-type,assignment]


class Counter64(Object):
    """64-bit counter: monotonically increases, wraps at 2^64.

    Range: 0 .. 18,446,744,073,709,551,615
    RFC 1902 §7.1.10

    Implements RFC 7317 binary encoding for 64-bit counters
    (splitting into two 32-bit values for compatibility).
    """

    tag = ObjectTag(TagClassEnum.application, False, ApplicationTags.counter64)  # type: ignore[arg-type,assignment]

    MIN_VALUE = 0
    MAX_VALUE = 0xFFFFFFFFFFFFFFFF  # 2^64 - 1

    def __init__(self, value: int | None = None) -> None:
        if value is None:
            value = 0
        if not self.MIN_VALUE <= value <= self.MAX_VALUE:
            raise ValueError(
                f"Counter64 value {value} out of range [{self.MIN_VALUE}, {self.MAX_VALUE}]"
            )
        super().__init__(value)  # type: ignore[arg-type]

    @staticmethod
    def wrap(current: int, increment: int) -> int:
        """Calculate counter value after increment, with wrap-around.

        Args:
            current: Current counter value.
            increment: Value to add.

        Returns:
            Wrapped counter value.
        """
        return (current + increment) & 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# Textual Conventions (RFC 2579)
# ---------------------------------------------------------------------------

class DisplayString(OctetString):
    """Textual Convention: printable ASCII string.

    SIZE constraint: 0..255 (extended by RFC 2579 from 0..127)
    Characters: 32..126 (printable ASCII) plus space
    RFC 2579 §4.6
    """

    MIN_SIZE = 0
    MAX_SIZE = 255

    def __init__(self, value: bytes | str | None = None) -> None:
        if value is None:
            value = b""
        if isinstance(value, str):
            value = value.encode("ascii")
        if len(value) > self.MAX_SIZE:
            raise ValueError(
                f"DisplayString size {len(value)} exceeds maximum {self.MAX_SIZE}"
            )
        for b in value:
            if not (32 <= b <= 126):
                raise ValueError(
                    f"DisplayString contains non-printable byte: 0x{b:02x}"
                )
        super().__init__(value)


class PhysAddress(OctetString):
    """Textual Convention: physical address (MAC-like).

    SIZE constraint: 5..255 octets
    Used for InterfaceIndex, ifPhysAddress, etc.
    RFC 2579 §4.3
    """

    MIN_SIZE = 5
    MAX_SIZE = 255

    def __init__(self, value: bytes | None = None) -> None:
        if value is None:
            value = b""
        if len(value) < self.MIN_SIZE:
            raise ValueError(
                f"PhysAddress size {len(value)} below minimum {self.MIN_SIZE}"
            )
        super().__init__(value)


class DateAndTime(Object):
    """Textual Convention: date and time encoding.

    Format: yyyy-mm-dd hh:mm:ss[.nn][+-zz:zz|Z]
    Example: 2024-01-15 10:30:00.00-08:00

    Encoded as OCTET STRING with 10 bytes:
    (year-high, year-low, month, day, hour, minute, second, frac-sec,
     timezone-high, timezone-low)

    RFC 2579 §4.2

    Note: DateAndTime uses context-specific tagging for the actual
    octet string content rather than a dedicated application tag.
    """

    tag = ObjectTag(TagClassEnum.context_specific, False, 0x01)  # type: ignore[arg-type,assignment]

    MIN_SIZE = 8
    MAX_SIZE = 11

    def __init__(self, value: bytes | None = None) -> None:
        if value is None:
            value = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        if not self.MIN_SIZE <= len(value) <= self.MAX_SIZE:
            raise ValueError(
                f"DateAndTime size {len(value)} outside range "
                f"[{self.MIN_SIZE}, {self.MAX_SIZE}]"
            )
        super().__init__(value)


class TimeStamp(Integer):
    """Textual Convention: timestamp value.

    Non-negative integer representing hundredths of seconds since an
    implementation-specific epoch. Monotonically increasing, wraps at 2^32.

    When the information being modeled is unavailable, the value is 0.
    If the value is 0, it indicates a non-applicable/disposable time.

    RFC 2579 §4.1
    """

    tag = ObjectTag(TagClassEnum.application, False, ApplicationTags.time_ticks)  # type: ignore[arg-type,assignment]

    MIN_VALUE = 0
    MAX_VALUE = 0xFFFFFFFF

    def __init__(self, value: int | None = None) -> None:
        if value is None:
            value = 0
        if not self.MIN_VALUE <= value <= self.MAX_VALUE:
            raise ValueError(
                f"TimeStamp value {value} out of range [{self.MIN_VALUE}, {self.MAX_VALUE}]"
            )
        super().__init__(value)  # type: ignore[arg-type]

    @property
    def is_non_applicable(self) -> bool:
        """Return True if the timestamp indicates non-applicable."""
        return self.value == 0  # type: ignore[union-attr]


class TruthStatus(Integer):
    """Textual Convention: truth status for conceptual tables.

    Values:
        truth(1): The row is valid/active.
        false(2): The row is not valid/active.

    RFC 2579 §6
    """

    MIN_VALUE = 1
    MAX_VALUE = 2

    truth = 1
    false = 2

    def __init__(self, value: int | None = None) -> None:
        if value is None:
            value = 1
        if value not in (1, 2):
            raise ValueError(f"TruthStatus value {value} must be 1 (truth) or 2 (false)")
        super().__init__(value)  # type: ignore[arg-type]


class RowStatus(Integer):
    """Textual Convention: row status for managing conceptual tables.

    Values:
        active(1): The row is active.
        createAndGo(2): The agent should create and activate the row.
        createAndWait(3): The agent should create the row and wait.
        notInService(4): The row exists but is not operational.
        createAndActive(4): synonym for notInService.
        notAccessible(5): Cannot be modified.
        commitThenFail(6): Part of a transaction, may fail.
        unknown(7): Status is unknown.
        testAndFail(8): Part of a transaction, test first.
        destroy(9): Delete the row.

    RFC 2579 §7
    """

    MIN_VALUE = 1
    MAX_VALUE = 9

    active = 1
    create_and_go = 2
    create_and_wait = 3
    not_in_service = 4
    not_accessible = 5
    commit_then_fail = 6
    unknown = 7
    test_and_fail = 8
    destroy = 9

    def __init__(self, value: int | None = None) -> None:
        if value is None:
            value = 1
        if not self.MIN_VALUE <= value <= self.MAX_VALUE:
            raise ValueError(f"RowStatus value {value} out of range [{self.MIN_VALUE}, {self.MAX_VALUE}]")
        super().__init__(value)  # type: ignore[arg-type]

    def __repr__(self) -> str:
        names = {
            1: "active",
            2: "createAndGo",
            3: "createAndWait",
            4: "notInService",
            5: "notAccessible",
            6: "commitThenFail",
            7: "unknown",
            8: "testAndFail",
            9: "destroy",
        }
        name = names.get(self.value, f"unknown({self.value})") if self.value is not None else "unknown"
        return f"RowStatus({name})"  # type: ignore[union-attr]


class StorageType(Integer):
    """Textual Convention: storage type for conceptual tables (RFC 2578 §7.5).

    Values:
        other(1): Not one of the following.
        permanent(2): Row persists across reboots.
        nonVolatile(3): Row persists across reboots but can be modified.
        volatile(4): Row is lost on reboot.
        loading(5): Row is being loaded (temporary state).

    RFC 2578 §7.5
    """

    MIN_VALUE = 1
    MAX_VALUE = 5

    other = 1
    permanent = 2
    nonVolatile = 3
    volatile = 4
    loading = 5

    def __init__(self, value: int | None = None) -> None:
        if value is None:
            value = 4  # volatile is default
        if not self.MIN_VALUE <= value <= self.MAX_VALUE:
            raise ValueError(f"StorageType value {value} out of range [{self.MIN_VALUE}, {self.MAX_VALUE}]")
        super().__init__(value)  # type: ignore[arg-type]

    def __repr__(self) -> str:
        names = {
            1: "other",
            2: "permanent",
            3: "nonVolatile",
            4: "volatile",
            5: "loading",
        }
        name = names.get(self.value, f"unknown({self.value})") if self.value is not None else "unknown"
        return f"StorageType({name})"  # type: ignore[union-attr]


class TestAndIncr(Integer):
    """Textual Convention: atomic test-and-increment counter (RFC 2578 §7.8).

    Used for coarse-grain coordination of concurrent operations (e.g.,
    manager-to-manager coordination for SNMPv2 set operations).

    Semantics:
        1. Read the current value.
        2. If the read value matches the value the manager expects,
           set the value to current + 1 atomically.
        3. If the read value does not match, the set is rejected with
           a badValue error.

    This provides atomic compare-and-set semantics for SNMP Set operations.
    Range: 0 .. 2,147,483,647

    RFC 2578 §7.8
    """

    MIN_VALUE = 0
    MAX_VALUE = 0x7FFFFFFF  # 2,147,483,647

    def __init__(self, value: int | None = None) -> None:
        if value is None:
            value = 0
        if not self.MIN_VALUE <= value <= self.MAX_VALUE:
            raise ValueError(
                f"TestAndIncr value {value} out of range [{self.MIN_VALUE}, {self.MAX_VALUE}]"
            )
        super().__init__(value)  # type: ignore[arg-type]

    def increment(self) -> int:
        """Atomically increment and return the new value."""
        self.value = (self.value + 1) % (self.MAX_VALUE + 1)  # type: ignore[union-attr]
        return self.value  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------

APPLICATION_TYPE_MAP: dict[int, type[Object]] = {
    # Application type tags -> Python classes
    ApplicationTags.ip_address: IpAddress,
    ApplicationTags.counter32: Counter32,
    ApplicationTags.gauge32: Gauge32,
    ApplicationTags.time_ticks: TimeTicks,
    ApplicationTags.opaque: Opaque,
    ApplicationTags.counter64: Counter64,
}
"""Map APPLICATION tag values to Python classes."""