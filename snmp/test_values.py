"""Unit tests for snmp.values BER-unwrapping helpers."""

from __future__ import annotations

import unittest

from ber.enums import TagClassEnum
from ber.object import (
    Integer,
    Null,
    Object,
    ObjectIdentifier,
    ObjectTag,
    OctetString,
)
from snmp.oid import Oid
from snmp.values import as_bytes, as_int, as_str, exception_name, oid_string


def _exc(tag_id: int) -> Object:
    """v2c exception value (RFC 3416 §4.1.6): context tag, empty content."""
    return Object(ObjectTag(TagClassEnum.context_specific, False, tag_id), b"")


class TestAsBytes(unittest.TestCase):
    def test_octet_string(self) -> None:
        obj = OctetString(b"payload\x00\x01").get_object()
        self.assertEqual(as_bytes(obj), b"payload\x00\x01")

    def test_integer_content(self) -> None:
        obj = Integer.from_int(258).get_object()
        self.assertEqual(as_bytes(obj), b"\x01\x02")

    def test_null_is_empty(self) -> None:
        self.assertEqual(as_bytes(Null().get_object()), b"")

    def test_raw_passthrough(self) -> None:
        self.assertEqual(as_bytes(b"hi"), b"hi")
        self.assertEqual(as_bytes("hi"), b"hi")

    def test_constructed_raises(self) -> None:
        seq = Object(ObjectTag(TagClassEnum.universal, True, 16),
                     [OctetString(b"x").get_object()])
        with self.assertRaises(TypeError):
            as_bytes(seq)


class TestAsInt(unittest.TestCase):
    def test_integer(self) -> None:
        self.assertEqual(as_int(Integer.from_int(78).get_object()), 78)

    def test_unsigned_big_endian(self) -> None:
        # Counter32/Gauge32-style raw content (no dedicated class).
        obj = Object(
            ObjectTag(TagClassEnum.universal, False, 65), b"\x01\x00"
        )
        self.assertEqual(as_int(obj), 256)

    def test_python_passthrough(self) -> None:
        self.assertEqual(as_int(5), 5)
        self.assertEqual(as_int(True), 1)
        self.assertEqual(as_int("42"), 42)

    def test_empty_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            as_int(Null().get_object())

    def test_constructed_raises_type_error(self) -> None:
        seq = Object(ObjectTag(TagClassEnum.universal, True, 16), [])
        with self.assertRaises(TypeError):
            as_int(seq)


class TestAsStr(unittest.TestCase):
    def test_utf8(self) -> None:
        obj = OctetString("café".encode()).get_object()
        self.assertEqual(as_str(obj), "café")

    def test_latin1_fallback(self) -> None:
        obj = OctetString(b"caf\xe9").get_object()
        self.assertEqual(as_str(obj), "café")

    def test_integer_renders_decimal(self) -> None:
        self.assertEqual(as_str(Integer.from_int(78).get_object()), "78")

    def test_object_identifier(self) -> None:
        obj = ObjectIdentifier.from_string("1.3.6.1.2.1.1.0").get_object()
        self.assertEqual(as_str(obj), "1.3.6.1.2.1.1.0")

    def test_str_passthrough(self) -> None:
        self.assertEqual(as_str("plain"), "plain")

    def test_constructed_raises(self) -> None:
        seq = Object(ObjectTag(TagClassEnum.universal, True, 16), [])
        with self.assertRaises(TypeError):
            as_str(seq)


class TestExceptionValues(unittest.TestCase):
    def test_names(self) -> None:
        self.assertEqual(exception_name(_exc(0)), "noSuchObject")
        self.assertEqual(exception_name(_exc(1)), "noSuchInstance")
        self.assertEqual(exception_name(_exc(2)), "endOfMibView")

    def test_normal_values_are_not_exceptions(self) -> None:
        self.assertIsNone(exception_name(OctetString(b"x").get_object()))
        self.assertIsNone(exception_name(b"raw"))
        self.assertIsNone(exception_name(5))

    def test_as_helpers_raise_lookup_error(self) -> None:
        for helper in (as_bytes, as_int, as_str):
            with self.subTest(helper=helper.__name__):
                with self.assertRaises(LookupError) as ctx:
                    helper(_exc(1))
                self.assertIn("noSuchInstance", str(ctx.exception))


class TestOidString(unittest.TestCase):
    def test_str(self) -> None:
        self.assertEqual(oid_string("1.3.6.1.2.1.1.1.0"), "1.3.6.1.2.1.1.1.0")

    def test_object_identifier(self) -> None:
        oid = ObjectIdentifier.from_string("1.3.6.1.2.1.1.1.0")
        self.assertEqual(oid_string(oid), "1.3.6.1.2.1.1.1.0")

    def test_named_oid(self) -> None:
        self.assertEqual(oid_string(Oid("n", "1.2.3.0")), "1.2.3.0")


if __name__ == "__main__":
    unittest.main()


