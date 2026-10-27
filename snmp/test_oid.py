"""Unit tests for snmp.oid Oid / OidPack / resolve_oid."""

from __future__ import annotations

import unittest

from ber.object import ObjectIdentifier

from snmp.oid import (
    Oid,
    OidPack,
    PACKS,
    get_pack,
    register_pack,
    resolve_oid,
    resolve_symbolic,
)
from snmp.pdus import GetRequest
import snmp.mib_printer  # noqa: F401 — register RFC packs
import snmp.mib_system  # noqa: F401


class TestOid(unittest.TestCase):
    def test_str_and_object_identifier(self) -> None:
        leaf = Oid("sysName", "1.3.6.1.2.1.1.5.0", scalar=True)
        self.assertEqual(str(leaf), "1.3.6.1.2.1.1.5.0")
        self.assertEqual(str(leaf.as_object_identifier()), "1.3.6.1.2.1.1.5.0")

    def test_instance(self) -> None:
        col = Oid("level", "1.3.6.1.2.1.43.11.1.1.9", scalar=False)
        inst = col.instance(1, 2)
        self.assertEqual(inst.oid, "1.3.6.1.2.1.43.11.1.1.9.1.2")
        self.assertTrue(inst.scalar)
        self.assertEqual(inst.name, "level.1.2")


class TestOidPack(unittest.TestCase):
    def test_lookup_and_filters(self) -> None:
        pack = OidPack(
            name="_test_pack_unique",
            oids=[
                Oid("a", "1.2.3.0", scalar=True, access="ro"),
                Oid("b", "1.2.4", scalar=False),
            ],
        )
        self.assertEqual(pack["a"].oid, "1.2.3.0")
        self.assertIn("a", pack)
        self.assertEqual(len(pack.scalars()), 1)
        self.assertEqual(len(pack.trees()), 1)
        self.assertEqual(pack.by_oid("1.2.3.0"), pack["a"])
        register_pack(pack)
        self.assertIs(get_pack("_test_pack_unique"), pack)
        del PACKS["_test_pack_unique"]

    def test_duplicate_name_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OidPack(
                name="dup",
                oids=[
                    Oid("x", "1.0"),
                    Oid("x", "1.1"),
                ],
            )


class TestResolve(unittest.TestCase):
    def test_resolve_str_oid_object(self) -> None:
        self.assertEqual(resolve_oid("1.2.3"), "1.2.3")
        self.assertEqual(
            resolve_oid(ObjectIdentifier.from_string("1.2.3.4")),
            "1.2.3.4",
        )
        leaf = Oid("n", "9.9.9.0")
        self.assertEqual(resolve_oid(leaf), "9.9.9.0")

    def test_resolve_pack_shorthand(self) -> None:
        self.assertEqual(
            resolve_oid("mib2-system:sysName"),
            "1.3.6.1.2.1.1.5.0",
        )
        self.assertEqual(
            resolve_symbolic("printer-mib", "prtMarkerLifeCount").oid,
            "1.3.6.1.2.1.43.10.2.1.4.1.1",
        )

    def test_get_request_accepts_oid(self) -> None:
        from snmp.mib_system import sysDescr

        pdu = GetRequest.from_oid(sysDescr)
        self.assertIsNotNone(pdu)


class TestBuiltinPacks(unittest.TestCase):
    def test_registered_rfc_only(self) -> None:
        self.assertIn("mib2-system", PACKS)
        self.assertIn("printer-mib", PACKS)
        self.assertNotIn("brother", PACKS)


if __name__ == "__main__":
    unittest.main()
