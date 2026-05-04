"""BER (Basic Encoding Rules) ASN.1 encoding/decoding."""

from __future__ import annotations

import logging
from binascii import b2a_hex
from math import ceil, log2
from string import printable
from typing import Optional, Sequence, Type, TypeVar, Union

from ber.enums import TagClassEnum, UniversalClassTags

logger = logging.getLogger(__name__)

T = TypeVar("T", bound="Object")


class ObjectTag:
    """ASN.1 BER tag."""

    def __init__(
        self,
        tag_class: int | TagClassEnum,
        is_constructed: bool,
        tag_id: int | UniversalClassTags,
    ) -> None:
        if isinstance(tag_class, int):
            self.tag_class = TagClassEnum(tag_class)
        else:
            assert isinstance(tag_class, TagClassEnum)
            self.tag_class = tag_class

        assert isinstance(is_constructed, bool)
        self.is_constructed = is_constructed

        if tag_class == TagClassEnum.universal and isinstance(tag_id, int):
            try:
                self.tag_id = UniversalClassTags(tag_id)
            except ValueError:
                self.tag_id = tag_id
        else:
            self.tag_id = tag_id

    def __bytes__(self) -> bytes:
        buffer = bytearray()
        buffer.append(
            self.tag_class << 6
            | (0b00100000 if self.is_constructed else 0)
            | min(0b00011111, self.tag_id)  # type: ignore[arg-type]
        )
        if self.tag_id >= 0b00011111:  # type: ignore[operator]
            n = self.tag_id
            buffer.append(n & 0b01111111)
            while n >= 0b10000000:
                n >>= 7
                buffer.insert(1, 0b10000000 | n & 0b011111111)
        return bytes(buffer)

    def __repr__(self) -> str:
        tag_name: str = (
            self.tag_id.name  # type: ignore[union-attr]
            if isinstance(self.tag_id, UniversalClassTags)
            else str(self.tag_id)
        )
        return (
            f"({self.tag_class.name}, "
            f"{'constructed' if self.is_constructed else 'primitive'}, "
            f"{tag_name})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ObjectTag):
            return NotImplemented
        return (
            self.tag_class == other.tag_class
            and self.is_constructed == other.is_constructed
            and self.tag_id == other.tag_id
        )

    def __hash__(self) -> int:
        return hash((self.tag_class, self.is_constructed, self.tag_id))

    @classmethod
    def decode(cls, buffer: bytes, offset: int = 0) -> tuple[ObjectTag, int]:
        """Decode a tag from bytes.

        Args:
            buffer: Raw bytes.
            offset: Byte offset to start decoding at.

        Returns:
            Tuple of (ObjectTag, new offset).
        """
        tag_class = TagClassEnum(buffer[offset] >> 6)
        is_constructed = bool(buffer[offset] & 0b00100000)
        tag_id = buffer[offset] & 0b00011111
        if tag_id == 0b00011111:
            tag_id = 0
            while buffer[offset] & 0b10000000:
                tag_id |= buffer[offset] & 0b01111111
                tag_id <<= 7
                offset += 1
            else:
                tag_id |= buffer[offset]
        offset += 1
        return cls(tag_class, is_constructed, tag_id), offset


# ---------------------------------------------------------------------------
# BER value type aliases
# ---------------------------------------------------------------------------

BERPrimitive = Union[bytes, int, str, bool, None]
"""Simple BER value primitives."""


class ObjectValue(bytes):
    """Base class for ASN.1 BER value types."""

    tag_id: Optional[int] = None

    def get_object(self) -> Object:
        """Get this value as an Object."""
        return Object(self.get_object_tag(), self)

    @classmethod
    def get_object_tag(cls) -> ObjectTag:
        """Get the ObjectTag for this value type."""
        assert cls.tag_id is not None
        return ObjectTag(TagClassEnum.universal, False, cls.tag_id)


OptionalInt = Optional[int]


class ObjectLength:
    """BER length encoding/decoding."""

    @staticmethod
    def encode(length: int) -> bytes:
        """Encode a length value in BER format.

        Args:
            length: The length to encode.

        Returns:
            BER-encoded bytes.
        """
        assert not (length >> 128)
        if length < 0b10000000:
            return bytes([length])
        else:
            octets = ceil(log2(length) / 8)
            return bytes([0b10000000 | octets]) + length.to_bytes(
                octets, byteorder="big"
            )

    @staticmethod
    def decode(buffer: bytes, offset: int = 0) -> tuple[int, int]:
        """Decode a BER length from bytes.

        Args:
            buffer: Raw bytes.
            offset: Byte offset to start decoding at.

        Returns:
            Tuple of (length, new offset).
        """
        if buffer[offset] == 0b10000000:
            try:
                offset += 1
                octet_length = buffer.index(b"\0" * 2, offset) - offset
            except ValueError:
                raise ValueError(
                    "Malformed packet: Indefinite form has no end-of-content terminator."
                )
        elif buffer[offset] < 0b10000000:
            octet_length = buffer[offset]
            offset += 1
        else:
            length_octets = buffer[offset] & 0b01111111
            offset += 1
            octet_length = int.from_bytes(
                buffer[offset : offset + length_octets], "big"
            )
            offset += length_octets
        return octet_length, offset


class Null(ObjectValue):
    """ASN.1 Null type."""

    tag_id = 5


class ObjectIdentifier(ObjectValue):
    """ASN.1 ObjectIdentifier type — a tuple of integers with dot-separated representation.

    At its core, an ObjectIdentifier is a tuple of non-negative integers.
    The dotted-decimal notation (e.g., "1.3.6.1.2.1.1.1") is just a
    convenient string representation of the underlying tuple (1, 3, 6, 1, 2, 1, 1, 1).

    Supports tuple-like operations for convenient composition:
        - Concatenation: (1,2) + (3,4) → (1,2,3,4)
        - Indexing: (1,2,3)[0] → 1
        - Slicing: (1,2,3)[0:2] → (1,2)
        - Iteration: for x in (1,2,3): print(x)
        - Membership: 2 in (1,2,3)
        - Repetition: (1,2) * 3 → (1,2,1,2,1,2)

    Example:
        >>> from snmp.mib import sysDescr
        >>> sysDescr + (1, 0)
        ObjectIdentifier('1.3.6.1.2.1.1.1.0')
        >>> sysDescr[:4]
        ObjectIdentifier('1.3.6.1')
        >>> len(sysDescr)
        8
        >>> sysDescr[0]
        1
    """

    tag_id = 6

    def __eq__(self, other: object) -> bool:
        """Compare ObjectIdentifier for equality.

        Supports comparison with:
        - Another ObjectIdentifier (bytes comparison)
        - A tuple of integers: (1, 3, 6, 1, 2, 1, 1, 1)
        - A dotted string: "1.3.6.1.2.1.1.1"
        """
        if isinstance(other, ObjectIdentifier):
            return bytes(self) == bytes(other)
        elif isinstance(other, tuple) and all(isinstance(x, int) for x in other):
            return self._as_tuple() == other
        elif isinstance(other, str):
            return str(self) == other
        return False

    def __hash__(self) -> int:
        """Hash the integer tuple representation.

        Enables: hash(sysDescr) == hash((1, 3, 6, 1, 2, 1, 1, 1))
        """
        return hash(self._as_tuple())

    def _as_tuple(self) -> tuple[int, ...]:
        """Convert OID bytes to integer tuple.

        Example: ObjectIdentifier("1.3.6.1.2.1.1.1") → (1, 3, 6, 1, 2, 1, 1, 1)

        NOTE: Uses bytes.__len__() to avoid recursion with __len__().
        """
        byte_len = bytes.__len__(self)
        x = min(2, bytes.__getitem__(self, 0) // 40)
        y = bytes.__getitem__(self, 0) - x * 40
        oid: list[int] = [x, y]
        i = 0
        for n in range(1, byte_len):
            i |= bytes.__getitem__(self, n) & 0b01111111
            if bytes.__getitem__(self, n) & 0b10000000:
                i <<= 7
            else:
                oid.append(i)
                i = 0
        return tuple(oid)

    # =====================================================================
    # Tuple-like operators
    # =====================================================================

    def __add__(self, other: object) -> ObjectIdentifier:
        """Concatenate OID tuples: (1,2) + (3,) → (1,2,3)

        Args:
            other: Another ObjectIdentifier or tuple of ints.

        Returns:
            New ObjectIdentifier with combined OID components.
        """
        if isinstance(other, ObjectIdentifier):
            other_tuple = other._as_tuple()
        elif isinstance(other, tuple) and all(isinstance(x, int) for x in other):
            other_tuple = other
        else:
            return NotImplemented  # type: ignore[return-value]
        full = self._as_tuple() + other_tuple
        return ObjectIdentifier.from_string(".".join(str(x) for x in full))

    def __radd__(self, other: object) -> ObjectIdentifier:
        """Concatenate from the right: (3,) + (1,2) → (3,1,2)

        Args:
            other: Tuple of ints to prepend.

        Returns:
            New ObjectIdentifier with combined OID components.
        """
        if isinstance(other, tuple) and all(isinstance(x, int) for x in other):
            full = other + self._as_tuple()
            return ObjectIdentifier.from_string(".".join(str(x) for x in full))
        return NotImplemented  # type: ignore[return-value]

    def __mul__(self, other: object) -> ObjectIdentifier:
        """Repeat OID tuple: (1,2) * 3 → (1,2,1,2,1,2)

        Args:
            other: Integer multiplier.

        Returns:
            New ObjectIdentifier with repeated OID components.
        """
        if isinstance(other, int) and other >= 0:
            full = self._as_tuple() * other
            return ObjectIdentifier.from_string(".".join(str(x) for x in full))
        return NotImplemented  # type: ignore[return-value]

    def __rmul__(self, other: object) -> ObjectIdentifier:
        """Repeat OID tuple from the right: 3 * (1,2) → (1,2,1,2,1,2)"""
        return self.__mul__(other)

    def __getitem__(self, index: object) -> object:
        """Index into or slice OID components.

        Examples:
            >>> sysDescr[0]  # → 1
            >>> sysDescr[0:4]  # → ObjectIdentifier('1.3.6.1')
        """
        if isinstance(index, slice):
            # Return slice as new ObjectIdentifier
            start, stop, step = index.indices(len(self._as_tuple()))
            sliced = self._as_tuple()[start:stop:step]
            return ObjectIdentifier.from_string(".".join(str(x) for x in sliced))
        if isinstance(index, int):
            # Single index — return integer
            return self._as_tuple()[index]
        return NotImplemented  # type: ignore[return-value]

    def __len__(self) -> int:
        """Get number of OID components.

        Example:
            >>> len(sysDescr)
            8
        """
        return len(self._as_tuple()) if self._as_tuple() else bytes.__len__(self)

    def __iter__(self):
        """Iterate over OID components.

        Example:
            >>> for x in sysDescr:
            ...     print(x)
            1
            3
            6
            ...
        """
        return iter(self._as_tuple())

    def __contains__(self, item: object) -> bool:
        """Check if OID contains a component.

        Example:
            >>> 2 in sysDescr
            False
            >>> 1 in sysDescr
            True
        """
        if isinstance(item, int):
            return item in self._as_tuple()
        return False

    def __reversed__(self) -> object:
        """Reverse OID components.

        Example:
            >>> reversed(sysDescr)  # → (1, 1, 1, 2, 1, 6, 3, 1)
        """
        return reversed(self._as_tuple())

    def __str__(self) -> str:
        """Convert OID to dotted-decimal string representation.

        Example:
            >>> str(sysDescr)
            '1.3.6.1.2.1.1.1'

        NOTE: Uses bytes.__len__() to avoid recursion with __len__().
        """
        byte_len = bytes.__len__(self)
        x = min(2, bytes.__getitem__(self, 0) // 40)
        y = bytes.__getitem__(self, 0) - x * 40
        oid = [x, y]
        i = 0
        for n in range(1, byte_len):
            i |= bytes.__getitem__(self, n) & 0b01111111
            if bytes.__getitem__(self, n) & 0b10000000:
                i <<= 7
            else:
                oid.append(i)
                i = 0
        return ".".join(str(v) for v in oid)

    @classmethod
    def from_string(cls, oid: str) -> ObjectIdentifier:
        """Create an ObjectIdentifier from a dotted-decimal string.

        Args:
            oid: Dotted-decimal OID string (e.g., '1.3.6.1.2.1.1').

        Returns:
            ObjectIdentifier instance.
        """
        ids = list(map(int, oid.split(".")))
        assert 0 <= ids[0] <= 2
        if ids[0] < 2:
            assert ids[1] < 40
        else:
            assert ids[1] < 256 - 80
        buffer = bytearray([ids[0] * 40 + ids[1]])
        for n in range(2, len(ids)):
            i = ids[n]
            sub_buffer = bytearray([i & 0b01111111])
            while i >= 0b10000000:
                i >>= 7
                sub_buffer.insert(0, 0b10000000 | i & 0xFF)
            buffer.extend(sub_buffer)
        return cls(bytes(buffer))


class OctetString(ObjectValue):
    """ASN.1 OctetString type."""

    is_constructed = False
    tag_id = 4

    def __str__(self) -> str:
        try:
            decoded = self.decode("ascii")
            if all(c in printable for c in decoded):
                return decoded
        except (UnicodeDecodeError, ValueError):
            pass
        return b2a_hex(self).decode("ascii")

    @classmethod
    def encode(cls, value: str) -> OctetString:
        """Encode a string as OctetString.

        Args:
            value: ASCII string to encode.

        Returns:
            OctetString instance.
        """
        assert isinstance(value, str)
        return cls(value.encode("ascii"))


class Integer(ObjectValue):
    """ASN.1 Integer type."""

    tag_id = 2

    def __int__(self) -> int:
        return int.from_bytes(self, byteorder="big")

    def __str__(self) -> str:
        return f"%d" % int(self)

    @classmethod
    def from_int(cls, value: int) -> Integer:
        """Create an Integer from a Python int.

        Args:
            value: Integer value (must be >= 0).

        Returns:
            Integer instance.
        """
        assert isinstance(value, int)
        assert value >= 0
        # Ensure at least 1 byte for the length calculation
        num_bytes = max(1, (value.bit_length() + 7) // 8) if value > 0 else 1
        return cls(
            value.to_bytes(num_bytes, byteorder="big", signed=False)
        )


class Object:
    """Base ASN.1 BER Object.

    Wraps a BER-encoded value with its ASN.1 tag for encoding/decoding.
    Provides Python magic methods that forward to the underlying value,
    making Object instances work naturally with Python built-ins:
        - int(obj) → int(obj.value) if value supports __int__
        - str(obj) → str(obj.value)
        - float(obj) → float(obj.value)
        - bool(obj) → bool(obj.value)

    BER encoding still works via self.tag and self.value.
    """

    universal_tags: dict[int, type[ObjectValue]] = {
        tag.tag_id: tag for tag in ObjectValue.__subclasses__()
    }

    def __init__(self, tag: ObjectTag, value: BERPrimitive | list[Object]) -> None:
        assert isinstance(tag, ObjectTag)
        self.tag = tag
        self.value = value

    def __int__(self) -> int:
        """Convert to int. Forwards to int(self.value) if supported."""
        if hasattr(self.value, "__int__"):
            return int(self.value)
        return int(self.value)

    def __str__(self) -> str:
        """Convert to string. Forwards to str(self.value)."""
        return str(self.value)

    def __float__(self) -> float:
        """Convert to float. Forwards to float(self.value) if supported."""
        if hasattr(self.value, "__float__"):
            return float(self.value)
        return float(self.value)

    def __bool__(self) -> bool:
        """Convert to bool. Forwards to bool(self.value)."""
        return bool(self.value)

    def __len__(self) -> int:
        """Return length of value. Forwards to len(self.value)."""
        try:
            return len(self.value)
        except TypeError:
            return 0

    def __getitem__(self, key: object) -> object:
        """Index into or slice the value. Forwards to self.value[key]."""
        if isinstance(key, slice):
            return self.value[key]  # type: ignore[index]
        return self.value[key]  # type: ignore[index]

    def __iter__(self):
        """Iterate over the value."""
        return iter(self.value)  # type: ignore[return-value]

    def __bytes__(self) -> bytes:
        if isinstance(self.value, list):
            encoded_value = b"".join(bytes(v) for v in self.value)  # type: ignore[misc]
        else:
            encoded_value = bytes(self.value)
        return bytes(self.tag) + ObjectLength.encode(len(encoded_value)) + encoded_value

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.tag}: {self.value})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Object):
            return NotImplemented
        return self.tag == other.tag and self.value == other.value

    @classmethod
    def decode(cls, buffer: bytes, offset: int = 0) -> tuple[Object, int]:
        """Decode an Object from bytes.

        Args:
            buffer: Raw bytes.
            offset: Byte offset to start decoding at.

        Returns:
            Tuple of (Object, new offset).
        """
        tag, offset = ObjectTag.decode(buffer, offset)
        octet_length, offset = ObjectLength.decode(buffer, offset)
        stop_octet = offset + octet_length

        if tag.is_constructed:
            value: list[Object] = []
            while offset < stop_octet:
                sub_object, offset = cls.decode(buffer, offset)
                value.append(sub_object)
        else:
            value = buffer[offset:stop_octet]

        if tag.tag_class == TagClassEnum.universal:
            if tag.tag_id in cls.universal_tags:
                value = cls.universal_tags[tag.tag_id](value)  # type: ignore[assignment]

        return cls(tag, value), stop_octet


class Sequence(Object):
    """ASN.1 Sequence type."""

    tag_id = 16
    is_constructed = True

    @classmethod
    def from_list(cls, value: Sequence[Object]) -> Sequence:
        """Create a Sequence from a list.

        Args:
            value: List of Object instances.

        Returns:
            Sequence instance.
        """
        return cls(
            ObjectTag(
                TagClassEnum.universal,
                True,
                UniversalClassTags.sequence_of,
            ),
            value,
        )