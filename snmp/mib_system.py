"""MIB-2 system group as an OidPack (RFC 1213 / RFC 1907).

Thin example of the pack foundation — does not replace ``snmp.mib`` constants.
Scalar leaves include the ``.0`` instance for direct GET.
"""

from __future__ import annotations

from snmp.oid import Oid, OidPack, register_pack

SYSTEM = OidPack(
    name="mib2-system",
    doc="MIB-2 system group (RFC 1213 §2 / RFC 1907) — GET-ready .0 scalars",
    oids=[
        Oid("system", "1.3.6.1.2.1.1", doc="system group root (walk)"),
        Oid(
            "sysDescr",
            "1.3.6.1.2.1.1.1.0",
            syntax="OCTET STRING",
            access="ro",
            scalar=True,
            doc="Textual description of the entity",
        ),
        Oid(
            "sysObjectID",
            "1.3.6.1.2.1.1.2.0",
            syntax="OBJECT IDENTIFIER",
            access="ro",
            scalar=True,
            doc="Vendor's authoritative identification",
        ),
        Oid(
            "sysUpTime",
            "1.3.6.1.2.1.1.3.0",
            syntax="TimeTicks",
            access="ro",
            scalar=True,
            doc="Time since last re-initialization",
        ),
        Oid(
            "sysContact",
            "1.3.6.1.2.1.1.4.0",
            syntax="OCTET STRING",
            access="rw",
            scalar=True,
            doc="Contact person for this managed node",
        ),
        Oid(
            "sysName",
            "1.3.6.1.2.1.1.5.0",
            syntax="OCTET STRING",
            access="rw",
            scalar=True,
            doc="Administratively assigned name",
        ),
        Oid(
            "sysLocation",
            "1.3.6.1.2.1.1.6.0",
            syntax="OCTET STRING",
            access="rw",
            scalar=True,
            doc="Physical location of this node",
        ),
        Oid(
            "sysServices",
            "1.3.6.1.2.1.1.7.0",
            syntax="Integer",
            access="ro",
            scalar=True,
            doc="Sum of layer values indicating services",
        ),
        Oid(
            "sysORLastChange",
            "1.3.6.1.2.1.1.8.0",
            syntax="TimeStamp",
            access="ro",
            scalar=True,
            doc="sysORTable last-change (SNMPv2)",
        ),
        Oid(
            "sysORTable",
            "1.3.6.1.2.1.1.9",
            access="ro",
            scalar=False,
            doc="sysORTable walk root",
        ),
    ],
)
register_pack(SYSTEM)

system = SYSTEM["system"]
sysDescr = SYSTEM["sysDescr"]
sysObjectID = SYSTEM["sysObjectID"]
sysUpTime = SYSTEM["sysUpTime"]
sysContact = SYSTEM["sysContact"]
sysName = SYSTEM["sysName"]
sysLocation = SYSTEM["sysLocation"]
sysServices = SYSTEM["sysServices"]
sysORLastChange = SYSTEM["sysORLastChange"]
sysORTable = SYSTEM["sysORTable"]

__all__ = [
    "SYSTEM",
    "system",
    "sysDescr",
    "sysObjectID",
    "sysUpTime",
    "sysContact",
    "sysName",
    "sysLocation",
    "sysServices",
    "sysORLastChange",
    "sysORTable",
]
