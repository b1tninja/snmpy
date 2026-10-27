"""RFC 3805 conformance tests for the Printer-MIB pack (snmp.mib_printer).

Every leaf is checked against the ``::= { <Entry> n }`` assignment in the RFC
3805 SMI module, because a wrong column number is invisible in code review yet
silently returns another object's value (or nothing) on a live agent.  Two
columns used to be wrong here: ``prtMarkerSuppliesLevel`` pointed at entry 7
(``prtMarkerSuppliesSupplyUnit``) and ``prtMarkerSuppliesDescription`` pointed
at a nonexistent entry 11 — the supplies table stops at 9.
"""

from __future__ import annotations

import unittest

import snmp.mib_printer as mib

_43 = "1.3.6.1.2.1.43"

# name -> expected dotted OID, transcribed from RFC 3805 §6.
RFC_3805 = {
    "printmib": _43,
    "prtGeneralTable": f"{_43}.5.1",
    "prtGeneralPrinterName": f"{_43}.5.1.1.16.1",
    "prtGeneralSerialNumber": f"{_43}.5.1.1.17.1",
    "prtCoverTable": f"{_43}.6.1.1",
    "prtInputTable": f"{_43}.8.2.1",
    "prtInputDesc": f"{_43}.8.2.1.3",
    "prtInputCurrentLevel": f"{_43}.8.2.1.9",
    "prtMarkerTable": f"{_43}.10.2.1",
    "prtMarkerMarkTech": f"{_43}.10.2.1.2",
    "prtMarkerCounterUnit": f"{_43}.10.2.1.3",
    "prtMarkerLifeCount": f"{_43}.10.2.1.4.1.1",
    "prtMarkerSuppliesTable": f"{_43}.11.1.1",
    "prtMarkerSuppliesType": f"{_43}.11.1.1.5",
    "prtMarkerSuppliesDescription": f"{_43}.11.1.1.6",
    "prtMarkerSuppliesMaxCapacity": f"{_43}.11.1.1.8",
    "prtMarkerSuppliesLevel": f"{_43}.11.1.1.9",
    "prtConsoleDisplayBufferText": f"{_43}.16.5.1.2",
}

# HOST-RESOURCES (RFC 2790) companions live in the same pack.
RFC_2790 = {
    "hrPrinterStatus": "1.3.6.1.2.1.25.3.5.1.1",
}


class TestPrinterMibRFC3805(unittest.TestCase):
    def test_every_rfc_leaf_matches_the_rfc(self) -> None:
        for name, expected in {**RFC_3805, **RFC_2790}.items():
            with self.subTest(name=name):
                self.assertEqual(mib.PRINTER[name].oid, expected)

    def test_module_level_aliases_are_the_pack_leaves(self) -> None:
        for name in mib.__all__:
            if name == "PRINTER":
                continue
            with self.subTest(name=name):
                self.assertIs(getattr(mib, name), mib.PRINTER[name])

    def test_supplies_columns_exist(self) -> None:
        """prtMarkerSuppliesEntry stops at 9 — no leaf may exceed it."""
        prefix = f"{_43}.11.1.1."
        for leaf in mib.PRINTER:
            if leaf.oid.startswith(prefix):
                column = int(leaf.oid[len(prefix) :])
                with self.subTest(column=column):
                    self.assertIn(column, {1, 2, 3, 4, 5, 6, 7, 8, 9})

    def test_level_is_not_supply_unit(self) -> None:
        """Regression: level was registered as entry 7 (= SupplyUnit)."""
        self.assertNotEqual(
            mib.prtMarkerSuppliesLevel.oid, f"{_43}.11.1.1.7"
        )
        self.assertEqual(mib.prtMarkerSuppliesLevel.oid, f"{_43}.11.1.1.9")

    def test_columns_expand_to_instances(self) -> None:
        """Table columns stay walk-roots so .instance(...) still works."""
        self.assertFalse(mib.prtMarkerSuppliesLevel.scalar)
        self.assertEqual(
            mib.prtMarkerSuppliesLevel.instance(1, 1).oid,
            f"{_43}.11.1.1.9.1.1",
        )
        self.assertTrue(mib.prtMarkerLifeCount.scalar)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
