"""SNMP Framework MIB — SNMPv3 Management Information Base.

Implements RFC 3418 §6: MIB Definitions for the SNMP Management Framework.

This module defines:
    - snmpFrameworkMIB OID tree (1.3.6.1.6.3.10)
    - snmpEngineID — engine identification (RFC 3411 §3.1)
    - snmpEngineTable — engine discovery table
    - snmpEngineBoots — engine boot counter
    - snmpEngineTime — local time since last engineID change
    - snmpSecurityModel — security model OID
    - snmpSecurityModelName — security model display string

OID Hierarchy (RFC 3418):
    1.3.6.1.6.3.10  — snmpFrameworkMIB
    1.3.6.1.6.3.10.1 — snmpFrameworkMIBObjects
    1.3.6.1.6.3.10.1.1 — snmpEngineTable
    1.3.6.1.6.3.10.1.2 — snmpSecurityModels
    1.3.6.1.6.3.10.1.3 — snmpStatisticsObjects
    1.3.6.1.6.3.10.2   — snmpTraps
"""

from __future__ import annotations

from ber.object import ObjectIdentifier


# =============================================================================
# SNMP Framework MIB Root (RFC 3418)
# =============================================================================

snmpFrameworkMIB = ObjectIdentifier.from_string("1.3.6.1.6.3.10")  # snmpFrameworkMIB
snmpFrameworkMIBObjects = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1")  # snmpFrameworkMIBObjects

# =============================================================================
# snmpEngineTable (RFC 3418 §6.6.1)
# =============================================================================

# snmpEngineTable root
snmpEngineTable = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.1")       # snmpEngineTable
snmpEngineEntry = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.1.1")     # snmpEngineEntry

# Columnar objects in snmpEngineEntry
snmpEngineID = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.1.1.1")      # snmpEngineID.1 — OCTET STRING, read-only
snmpEngineTime = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.1.1.2")    # snmpEngineTime.2 — TimeTicks, read-only
snmpEngineBoots = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.1.1.3")   # snmpEngineBoots.3 — Counter32, read-only
snmpEngineTrustModel = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.1.1.4")  # snmpEngineTrustModel.4 — INTEGER, read-only

# =============================================================================
# snmpSecurityModels (RFC 3418 §6.6.2)
# =============================================================================

snmpSecurityModels = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.2")       # snmpSecurityModels
snmpSecurityModelsEntry = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.2.1")  # snmpSecurityModelsEntry

# Columnar objects in snmpSecurityModels
snmpSecurityModelID = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.2.1.1")  # snmpSecurityModelID.1 — INTEGER, read-only
snmpSecurityModelName = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.2.1.2")  # snmpSecurityModelName.2 — DisplayString, read-only

# Known security model OIDs (RFC 3411 §3.2)
USM_MODEL_ID = 3  # User-based Security Model (RFC 3414)
USM_MODEL_OID = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.2.1.1.3")  # usmModel

# =============================================================================
# snmpStatisticsObjects (RFC 3418 §6.6.3)
# =============================================================================

snmpStatisticsObjects = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.3")     # snmpStatisticsObjects

# snmpUnknownSecurityLevels — RFC 3414 §7
snmpUnknownSecurityLevels = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.3.1")  # snmpUnknownSecurityLevels.1

# snmpInvalidMsgs — RFC 3415 §8
snmpInvalidMsgs = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.3.2")  # snmpInvalidMsgs.2

# snmpSecFailedSnmpEntities — RFC 3416 §9
snmpSecFailedSnmpEntities = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.3.3")  # snmpSecFailedSnmpEntities.3

# =============================================================================
# snmpTraps (RFC 3418 §6.7)
# =============================================================================

snmpFrameworkTraps = ObjectIdentifier.from_string("1.3.6.1.6.3.10.2")          # snmpFrameworkTraps

# The only trap defined in RFC 3418 is snmpEngineStateChange
snmpEngineStateChange = ObjectIdentifier.from_string("1.3.6.1.6.3.10.2.1")  # snmpEngineStateChange.1

# =============================================================================
# SNMPv3 Security Model OIDs (RFC 3411 §3.2)
# =============================================================================

# Security model identifiers
SECURITY_MODEL_ID_V1 = 1   # SNMPv1
SECURITY_MODEL_ID_V2C = 2  # SNMPv2c
SECURITY_MODEL_ID_USM = 3  # User-based Security Model (SNMPv3)

# Security model OIDs for the SNMPv2-SecurityModel
snmpSecurityModelV1 = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.2.1.1.1")
snmpSecurityModelV2c = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.2.1.1.2")
snmpSecurityModelUSM = ObjectIdentifier.from_string("1.3.6.1.6.3.10.1.2.1.1.3")


# =============================================================================
# Engine ID Management
# =============================================================================

class SnmpEngineID:
    """SNMPv3 Engine Identifier (RFC 3411 §3.1).

    The snmpEngineID is a unique identifier for an SNMP engine. It is used
    in SNMPv3 message authentication and to uniquely identify the engine
    in the snmpEngineTable.

    Format (RFC 3411 §3.1):
        vendorId (variable) + assignedId (variable)
        └── enterpriseId (from IANA) ──┘

    The vendorId field contains:
        - 1 octet format (0x00) — deprecated
        - 2 octet format (0x01) — enterprise number encoded as in RFC 3412
        - 4 octet format (0x02) — private enterprise number
        - 5 octet format (0x03) — reverse IP address encoding

    RFC 3411 §3.1.1: "The length of the entire engineID MUST be between
    5 and 32 octets."

    Attributes:
        value: The raw bytes of the engine ID.
    """

    MIN_LENGTH = 5   # Minimum engine ID length (RFC 3411)
    MAX_LENGTH = 32  # Maximum engine ID length (RFC 3411)

    def __init__(self, value: bytes) -> None:
        """Initialize an SNMP engine ID.

        Args:
            value: Raw bytes for the engine ID.

        Raises:
            ValueError: If the engine ID is not between 5 and 32 octets.
        """
        if len(value) < self.MIN_LENGTH or len(value) > self.MAX_LENGTH:
            raise ValueError(
                f"snmpEngineID must be between {self.MIN_LENGTH} and {self.MAX_LENGTH} octets, "
                f"got {len(value)}"
            )
        self.value = value

    def __bytes__(self) -> bytes:
        return self.value

    def __str__(self) -> str:
        return " ".join(f"{b:02x}" for b in self.value)

    def __repr__(self) -> str:
        return f"SnmpEngineID({self})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SnmpEngineID):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)


# =============================================================================
# Engine ID Format Constants
# =============================================================================

# Format identifiers (RFC 3418 §6.6.1)
SNMP_ENGINE_ID_FORMAT_DEPRECATED = 0x00
SNMP_ENGINE_ID_FORMAT_ENTERPRISE = 0x01
SNMP_ENGINE_ID_FORMAT_PRIVATE = 0x02
SNMP_ENGINE_ID_FORMAT_REVERSE_DNS = 0x03


# =============================================================================
# Security Model Constants (RFC 3411 §3.2)
# =============================================================================

SNMP_SECURITY_MODEL_V1 = 1        # SNMPv1
SNMP_SECURITY_MODEL_V2C = 2      # SNMPv2c
SNMP_SECURITY_MODEL_USM = 3      # User-based Security Model (SNMPv3)
SNMP_SECURITY_MODEL_V3MIB = 4    # SNMPv3 MIB


# =============================================================================
# Exported Names
# =============================================================================

__all__ = [
    # MIB root
    "snmpFrameworkMIB", "snmpFrameworkMIBObjects",
    # Engine table
    "snmpEngineTable", "snmpEngineEntry",
    "snmpEngineID", "snmpEngineTime", "snmpEngineBoots", "snmpEngineTrustModel",
    # Security models
    "snmpSecurityModels", "snmpSecurityModelsEntry",
    "snmpSecurityModelID", "snmpSecurityModelName",
    "snmpSecurityModelV1", "snmpSecurityModelV2c", "snmpSecurityModelUSM",
    # Statistics
    "snmpStatisticsObjects",
    "snmpUnknownSecurityLevels", "snmpInvalidMsgs", "snmpSecFailedSnmpEntities",
    # Traps
    "snmpFrameworkTraps", "snmpEngineStateChange",
    # Engine ID management
    "SnmpEngineID",
    "SNMP_ENGINEID_MIN_LENGTH", "SNMP_ENGINEID_MAX_LENGTH",
    "SNMP_ENGINE_ID_FORMAT_DEPRECATED", "SNMP_ENGINE_ID_FORMAT_ENTERPRISE",
    "SNMP_ENGINE_ID_FORMAT_PRIVATE", "SNMP_ENGINE_ID_FORMAT_REVERSE_DNS",
    # Security model constants
    "SNMP_SECURITY_MODEL_V1", "SNMP_SECURITY_MODEL_V2C",
    "SNMP_SECURITY_MODEL_USM", "SNMP_SECURITY_MODEL_V3MIB",
]