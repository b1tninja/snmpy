"""Printer MIB v2 as an OidPack (RFC 3805 — obsoletes RFC 1759).

RFC-derived leaves only; no vendor subtrees belong in this pack.
Table columns are registered as walk-roots (``scalar=False``).  The
registered ``scalar=True`` leaves use the canonical single-device
indices (``hrDeviceIndex = 1``, ``prtMarkerIndex = 1``) for direct GET;
build other instances with ``Oid.instance(...)``.

OID arithmetic verified against the RFC 3805 SMI module (§6):

    printmib          ::= { mib-2 43 }      1.3.6.1.2.1.43
    prtGeneral        ::= { printmib 5 }    prtGeneralTable .43.5.1
      prtGeneralPrinterName ::= { prtGeneralEntry 16 }  (idx hrDeviceIndex)
      prtGeneralSerialNumber ::= { prtGeneralEntry 17 } (idx hrDeviceIndex)
    prtCover          ::= { printmib 6 }    prtCoverTable .43.6.1.1
    prtInput          ::= { printmib 8 }    prtInputTable .43.8.2.1
      prtInputDesc         ::= { prtInputEntry 3 }
      prtInputCurrentLevel ::= { prtInputEntry 9 }
    prtMarker         ::= { printmib 10 }   prtMarkerTable .43.10.2.1
      prtMarkerMarkTech    ::= { prtMarkerEntry 2 }
      prtMarkerCounterUnit ::= { prtMarkerEntry 3 }
      prtMarkerLifeCount   ::= { prtMarkerEntry 4 }  (idx hrDeviceIndex,
                                                      prtMarkerIndex)
    prtMarkerSupplies ::= { printmib 11 }   table .43.11.1.1
      type/desc/max/lvl    ::= { prtMarkerSuppliesEntry 5/6/8/9 }
      (entry 7 is prtMarkerSuppliesSupplyUnit, not a level)
    prtConsoleDisplayBuffer ::= { printmib 16 }   table .43.16.5.1
      prtConsoleDisplayBufferText ::= { prtConsoleDisplayBufferEntry 2 }

The two ``hr*`` leaves come from the HOST-RESOURCES MIB (RFC 2790);
Printer MIB tables are indexed by ``hrDeviceIndex``, so they are the
practical companions for device status / type lookups.  RFC 2790 has no
serial-number object (hrDeviceTable stops at hrDeviceErrors, entry 6), so
serials come from ``prtGeneralSerialNumber`` or an IEEE 1284.1 device ID.
"""

from __future__ import annotations

from snmp.oid import Oid, OidPack, register_pack

_43 = "1.3.6.1.2.1.43"

PRINTER = OidPack(
    name="printer-mib",
    pen=None,
    doc="Printer MIB v2 (RFC 3805) + RFC 2790 device-status companions",
    oids=[
        # -- Roots / tables (walk) ------------------------------------
        Oid("printmib", _43, doc="printmib root — full Printer MIB walk"),
        Oid("prtGeneralTable", f"{_43}.5.1", access="ro",
            doc="General printer group table"),
        Oid("prtCoverTable", f"{_43}.6.1.1", access="rw",
            doc="Cover / door status table"),
        Oid("prtInputTable", f"{_43}.8.2.1", access="ro",
            doc="Input (paper tray) table"),
        Oid("prtMarkerTable", f"{_43}.10.2.1", access="ro",
            doc="Marker (engine) table"),
        Oid("prtMarkerSuppliesTable", f"{_43}.11.1.1", access="ro",
            doc="Marker supplies (toner/ink) table"),
        # -- Scalars (direct GET, index 1 / 1.1) ----------------------
        Oid("prtGeneralPrinterName", f"{_43}.5.1.1.16.1",
            syntax="DisplayString", access="rw", scalar=True,
            doc="Printer name (prtGeneralPrinterName.1)"),
        Oid("prtGeneralSerialNumber", f"{_43}.5.1.1.17.1",
            syntax="OCTET STRING", access="ro", scalar=True,
            doc="Serial number (prtGeneralSerialNumber.1, RFC 3805 entry 17)"),
        Oid("prtMarkerLifeCount", f"{_43}.10.2.1.4.1.1",
            syntax="Counter32", access="ro", scalar=True,
            doc="Lifetime page count (marker 1 on device 1)"),
        Oid("prtConsoleDisplayBufferText", f"{_43}.16.5.1.2",
            syntax="DisplayString", access="ro",
            doc="Operator panel line (walk) — e.g. 'Sleep'"),
        # -- Table columns of interest (walk) --------------------------
        Oid("prtInputDesc", f"{_43}.8.2.1.3",
            syntax="DisplayString", access="rw",
            doc="Input tray description (walk)"),
        Oid("prtInputCurrentLevel", f"{_43}.8.2.1.9",
            syntax="Integer32", access="ro",
            doc="Current media level %, -3 = unknown (walk)"),
        Oid("prtMarkerMarkTech", f"{_43}.10.2.1.2",
            syntax="PrtMarkerMarkTechTC", access="ro",
            doc="Marking technology enumeration (walk)"),
        Oid("prtMarkerCounterUnit", f"{_43}.10.2.1.3",
            syntax="PrtMarkerCounterUnitTC", access="ro",
            doc="Unit of prtMarkerLifeCount (walk)"),
        Oid("prtMarkerSuppliesType", f"{_43}.11.1.1.5",
            syntax="PrtMarkerSuppliesTypeTC", access="ro",
            doc="Supply type, e.g. toner(4)/ink(11) (walk)"),
        Oid("prtMarkerSuppliesDescription", f"{_43}.11.1.1.6",
            syntax="DisplayString", access="rw",
            doc="Supply description, e.g. 'Black Toner Cartridge' (walk)"),
        Oid("prtMarkerSuppliesMaxCapacity", f"{_43}.11.1.1.8",
            syntax="Integer32", access="ro",
            doc="Full-supply capacity; -2 = unknown (walk)"),
        Oid("prtMarkerSuppliesLevel", f"{_43}.11.1.1.9",
            syntax="Integer32", access="ro",
            doc="Supply level, -2 = low / -3 = unknown (walk)"),
        # -- HOST-RESOURCES companions (RFC 2790) ----------------------
        Oid("hrPrinterStatus", "1.3.6.1.2.1.25.3.5.1.1",
            syntax="Integer", access="ro",
            doc="Device status: other(1) none(2) running(3) warmUp(4) "
                "dormant(5) interrupted(6) — RFC 2790"),
    ],
)
register_pack(PRINTER)

printmib = PRINTER["printmib"]
prtGeneralTable = PRINTER["prtGeneralTable"]
prtCoverTable = PRINTER["prtCoverTable"]
prtInputTable = PRINTER["prtInputTable"]
prtMarkerTable = PRINTER["prtMarkerTable"]
prtMarkerSuppliesTable = PRINTER["prtMarkerSuppliesTable"]
prtGeneralPrinterName = PRINTER["prtGeneralPrinterName"]
prtGeneralSerialNumber = PRINTER["prtGeneralSerialNumber"]
prtMarkerLifeCount = PRINTER["prtMarkerLifeCount"]
prtConsoleDisplayBufferText = PRINTER["prtConsoleDisplayBufferText"]
prtInputDesc = PRINTER["prtInputDesc"]
prtInputCurrentLevel = PRINTER["prtInputCurrentLevel"]
prtMarkerMarkTech = PRINTER["prtMarkerMarkTech"]
prtMarkerCounterUnit = PRINTER["prtMarkerCounterUnit"]
prtMarkerSuppliesType = PRINTER["prtMarkerSuppliesType"]
prtMarkerSuppliesDescription = PRINTER["prtMarkerSuppliesDescription"]
prtMarkerSuppliesMaxCapacity = PRINTER["prtMarkerSuppliesMaxCapacity"]
prtMarkerSuppliesLevel = PRINTER["prtMarkerSuppliesLevel"]
hrPrinterStatus = PRINTER["hrPrinterStatus"]

__all__ = [
    "PRINTER",
    "hrPrinterStatus",
    "printmib",
    "prtConsoleDisplayBufferText",
    "prtCoverTable",
    "prtGeneralPrinterName",
    "prtGeneralSerialNumber",
    "prtGeneralTable",
    "prtInputCurrentLevel",
    "prtInputDesc",
    "prtInputTable",
    "prtMarkerCounterUnit",
    "prtMarkerLifeCount",
    "prtMarkerMarkTech",
    "prtMarkerSuppliesDescription",
    "prtMarkerSuppliesLevel",
    "prtMarkerSuppliesMaxCapacity",
    "prtMarkerSuppliesTable",
    "prtMarkerSuppliesType",
    "prtMarkerTable",
]


