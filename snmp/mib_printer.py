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
      type/lvl/desc        ::= { prtMarkerSuppliesEntry 5/7/11 }

The two ``hr*`` leaves come from the HOST-RESOURCES MIB (RFC 2790);
Printer MIB tables are indexed by ``hrDeviceIndex``, so they are the
practical companion for device status / serial lookups.
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
        Oid("prtMarkerLifeCount", f"{_43}.10.2.1.4.1.1",
            syntax="Counter32", access="ro", scalar=True,
            doc="Lifetime page count (marker 1 on device 1)"),
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
        Oid("prtMarkerSuppliesLevel", f"{_43}.11.1.1.7",
            syntax="Integer32", access="ro",
            doc="Supply level, -2 = low / -3 = unknown (walk)"),
        Oid("prtMarkerSuppliesDescription", f"{_43}.11.1.1.11",
            syntax="DisplayString", access="rw",
            doc="Supply description, e.g. 'Black Toner Cartridge' (walk)"),
        # -- HOST-RESOURCES companions (RFC 2790) ----------------------
        Oid("hrPrinterStatus", "1.3.6.1.2.1.25.3.5.1.1",
            syntax="Integer", access="ro",
            doc="Device status: other(1) none(2) running(3) warmUp(4) "
                "dormant(5) interrupted(6) — RFC 2790"),
        Oid("hrDeviceSerialNumber", "1.3.6.1.2.1.25.3.5.1.18",
            syntax="OCTET STRING", access="ro",
            doc="Device serial number (RFC 2790 hrDeviceTable)"),
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
prtMarkerLifeCount = PRINTER["prtMarkerLifeCount"]
prtInputDesc = PRINTER["prtInputDesc"]
prtInputCurrentLevel = PRINTER["prtInputCurrentLevel"]
prtMarkerMarkTech = PRINTER["prtMarkerMarkTech"]
prtMarkerCounterUnit = PRINTER["prtMarkerCounterUnit"]
prtMarkerSuppliesType = PRINTER["prtMarkerSuppliesType"]
prtMarkerSuppliesLevel = PRINTER["prtMarkerSuppliesLevel"]
prtMarkerSuppliesDescription = PRINTER["prtMarkerSuppliesDescription"]
hrPrinterStatus = PRINTER["hrPrinterStatus"]
hrDeviceSerialNumber = PRINTER["hrDeviceSerialNumber"]

__all__ = [
    "PRINTER",
    "hrDeviceSerialNumber",
    "hrPrinterStatus",
    "printmib",
    "prtCoverTable",
    "prtGeneralPrinterName",
    "prtGeneralTable",
    "prtInputCurrentLevel",
    "prtInputDesc",
    "prtInputTable",
    "prtMarkerCounterUnit",
    "prtMarkerLifeCount",
    "prtMarkerMarkTech",
    "prtMarkerSuppliesDescription",
    "prtMarkerSuppliesLevel",
    "prtMarkerSuppliesTable",
    "prtMarkerSuppliesType",
    "prtMarkerTable",
]


