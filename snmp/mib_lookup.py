"""MIB Registry and Lookup — OID name mapping for SNMP management.

Provides bidirectional OID-to-name and name-to-OID lookups for all known
MIB objects. Supports both dotted-decimal and dotted-string formats.

Usage:
    >>> registry = MIBRegistry()
    >>> registry.register("sysDescr", "1.3.6.1.2.1.1.1")
    >>> registry.oid_to_name("1.3.6.1.2.1.1.1")
    'sysDescr'
    >>> registry.name_to_oid("sysDescr")
    '1.3.6.1.2.1.1.1'
"""

from __future__ import annotations

from typing import Optional


class MIBRegistry:
    """Bidirectional MIB object registry.

    Maintains mappings between OID strings (dotted-decimal) and human-readable
    names. Supports both exact matches and prefix-based lookups for table rows.

    Attributes:
        _oid_to_name: Maps OID strings to name strings.
        _name_to_oid: Maps name strings to OID strings.
        _oid_to_info: Maps OID strings to optional metadata dicts.
    """

    def __init__(self) -> None:
        """Initialize an empty MIB registry."""
        self._oid_to_name: dict[str, str] = {}
        self._name_to_oid: dict[str, str] = {}
        self._oid_to_info: dict[str, dict] = {}

    def register(
        self,
        name: str,
        oid: str,
        info: Optional[dict] = None,
    ) -> None:
        """Register an OID name mapping.

        Args:
            name: Human-readable name (e.g., "sysDescr", "ifTable").
            oid: Dotted-decimal OID string (e.g., "1.3.6.1.2.1.1.1").
            info: Optional metadata dict (e.g., {"type": "counter", "access": "read-only"}).
        """
        oid = self._normalize_oid(oid)
        self._oid_to_name[oid] = name
        self._name_to_oid[name] = oid
        if info is not None:
            self._oid_to_info[oid] = info

    def unregister(self, name: str) -> bool:
        """Remove a registered OID by name.

        Args:
            name: The registered name to remove.

        Returns:
            True if the name was found and removed.
        """
        if name in self._name_to_oid:
            oid = self._name_to_oid.pop(name)
            self._oid_to_name.pop(oid, None)
            self._oid_to_info.pop(oid, None)
            return True
        return False

    def oid_to_name(self, oid: str) -> Optional[str]:
        """Convert a dotted-decimal OID to its registered name.

        Args:
            oid: Dotted-decimal OID string.

        Returns:
            The registered name, or None if not found.
        """
        return self._oid_to_name.get(self._normalize_oid(oid))

    def name_to_oid(self, name: str) -> Optional[str]:
        """Convert a registered name to its OID.

        Args:
            name: Human-readable OID name.

        Returns:
            Dotted-decimal OID string, or None if not found.
        """
        return self._name_to_oid.get(name)

    def get_info(self, oid: str) -> Optional[dict]:
        """Get metadata for an OID.

        Args:
            oid: Dotted-decimal OID string.

        Returns:
            Metadata dict, or None if not found.
        """
        return self._oid_to_info.get(self._normalize_oid(oid))

    def get_info_by_name(self, name: str) -> Optional[dict]:
        """Get metadata for a registered name.

        Args:
            name: Human-readable OID name.

        Returns:
            Metadata dict, or None if not found.
        """
        oid = self._name_to_oid.get(name)
        if oid is None:
            return None
        return self._oid_to_info.get(self._normalize_oid(oid))

    def has_oid(self, oid: str) -> bool:
        """Check if an OID is registered.

        Args:
            oid: Dotted-decimal OID string.

        Returns:
            True if registered.
        """
        return self._normalize_oid(oid) in self._oid_to_name

    def has_name(self, name: str) -> bool:
        """Check if a name is registered.

        Args:
            name: Human-readable name.

        Returns:
            True if registered.
        """
        return name in self._name_to_oid

    def get_all_oids(self) -> list[str]:
        """Return all registered OIDs.

        Returns:
            List of dotted-decimal OID strings.
        """
        return list(self._oid_to_name.keys())

    def get_all_names(self) -> list[str]:
        """Return all registered names.

        Returns:
            List of human-readable name strings.
        """
        return list(self._name_to_oid.keys())

    def get_count(self) -> int:
        """Return the number of registered entries.

        Returns:
            Count of registered OID-name pairs.
        """
        return len(self._oid_to_name)

    def prefix_match(self, oid: str) -> Optional[tuple[str, str]]:
        """Find the longest matching registered OID prefix for a given OID.

        Useful for finding the parent object when the exact OID is not registered
        (e.g., a table row OID matches its parent table entry).

        Args:
            oid: Dotted-decimal OID string.

        Returns:
            Tuple of (parent_oid, parent_name), or None if no match found.
        """
        parts = oid.rstrip(".").split(".")
        best_match: Optional[tuple[str, str]] = None
        best_depth = 0

        for registered_oid, name in self._oid_to_name.items():
            depth = self._common_depth(oid, registered_oid)
            if depth > 0 and depth > best_depth:
                best_match = (registered_oid, name)
                best_depth = depth

        if best_match is not None:
            return best_match
        return None

    def reload(self) -> None:
        """Clear all registered entries."""
        self._oid_to_name.clear()
        self._name_to_oid.clear()
        self._oid_to_info.clear()

    @staticmethod
    def _normalize_oid(oid: str) -> str:
        """Normalize an OID string for comparison.

        Strips leading/trailing whitespace and ensures no trailing dot.

        Args:
            oid: Raw OID string.

        Returns:
            Normalized OID string.
        """
        return oid.strip().rstrip(".")

    @staticmethod
    def _common_depth(oid_a: str, oid_b: str) -> int:
        """Count how many OID components two OIDs share in common.

        Args:
            oid_a: First OID string.
            oid_b: Second OID string.

        Returns:
            Number of common depth levels.
        """
        parts_a = oid_a.rstrip(".").split(".")
        parts_b = oid_b.rstrip(".").split(".")
        depth = 0
        for a, b in zip(parts_a, parts_b):
            if a == b:
                depth += 1
            else:
                break
        return depth


# =============================================================================
# Pre-built Registry with RFC 1907 / RFC 1156 OIDs
# =============================================================================

def create_default_registry() -> MIBRegistry:
    """Create and populate a MIBRegistry with standard MIB-2 OIDs.

    Returns:
        Pre-populated MIBRegistry instance.
    """
    reg = MIBRegistry()

    # System Group
    reg.register("sysDescr", "1.3.6.1.2.1.1.1", {"type": "OCTET STRING", "access": "read-only"})
    reg.register("sysObjectID", "1.3.6.1.2.1.1.2", {"type": "OBJECT IDENTIFIER", "access": "read-only"})
    reg.register("sysUpTime", "1.3.6.1.2.1.1.3", {"type": "TimeTicks", "access": "read-only"})
    reg.register("sysContact", "1.3.6.1.2.1.1.4", {"type": "OCTET STRING", "access": "read-write"})
    reg.register("sysName", "1.3.6.1.2.1.1.5", {"type": "OCTET STRING", "access": "read-write"})
    reg.register("sysLocation", "1.3.6.1.2.1.1.6", {"type": "OCTET STRING", "access": "read-write"})
    reg.register("sysServices", "1.3.6.1.2.1.1.7", {"type": "INTEGER", "access": "read-only"})
    reg.register("sysORLastChange", "1.3.6.1.2.1.1.8", {"type": "TimeStamp", "access": "read-only"})
    reg.register("sysORTable", "1.3.6.1.2.1.1.9", {"type": "SEQUENCE", "access": "read-only"})
    reg.register("sysORIndex", "1.3.6.1.2.1.1.9.1.1", {"type": "INTEGER", "access": "read-only"})
    reg.register("sysORID", "1.3.6.1.2.1.1.9.1.2", {"type": "OBJECT IDENTIFIER", "access": "read-only"})
    reg.register("sysORDescr", "1.3.6.1.2.1.1.9.1.3", {"type": "DisplayString", "access": "read-only"})
    reg.register("sysORUpTime", "1.3.6.1.2.1.1.9.1.4", {"type": "TimeTicks", "access": "read-only"})

    # SNMP Group
    reg.register("snmpInPkts", "1.3.6.1.2.1.11.1", {"type": "Counter32", "access": "read-only"})
    reg.register("snmpInBadVersions", "1.3.6.1.2.1.11.3", {"type": "Counter32", "access": "read-only"})
    reg.register("snmpInBadCommunityNames", "1.3.6.1.2.1.11.4", {"type": "Counter32", "access": "read-only"})
    reg.register("snmpInBadCommunityUses", "1.3.6.1.2.1.11.5", {"type": "Counter32", "access": "read-only"})
    reg.register("snmpInASNParseErrs", "1.3.6.1.2.1.11.6", {"type": "Counter32", "access": "read-only"})
    reg.register("snmpSetSerialNo", "1.3.6.1.2.1.11.100.1", {"type": "TestAndIncr", "access": "read-write"})

    # Trap/Notification OIDs
    reg.register("snmpTrapOID", "1.3.6.1.6.3.18.1", {"type": "OBJECT IDENTIFIER", "access": "accessible-for-notify"})
    reg.register("coldStart", "1.3.6.1.6.3.1.1.4.1.0.1", {"type": "NOTIFICATION-TYPE", "trap": True})
    reg.register("warmStart", "1.3.6.1.6.3.1.1.4.1.0.2", {"type": "NOTIFICATION-TYPE", "trap": True})
    reg.register("linkDown", "1.3.6.1.6.3.1.1.4.1.0.3", {"type": "NOTIFICATION-TYPE", "trap": True})
    reg.register("linkUp", "1.3.6.1.6.3.1.1.4.1.0.4", {"type": "NOTIFICATION-TYPE", "trap": True})
    reg.register("authenticationFailure", "1.3.6.1.6.3.1.1.4.1.0.5", {"type": "NOTIFICATION-TYPE", "trap": True})

    # SNMP Framework MIB (RFC 3418)
    reg.register("snmpEngineID", "1.3.6.1.6.3.10.1.1.1.1", {"type": "OCTET STRING", "access": "read-only"})
    reg.register("snmpEngineTime", "1.3.6.1.6.3.10.1.1.1.2", {"type": "TimeTicks", "access": "read-only"})
    reg.register("snmpEngineBoots", "1.3.6.1.6.3.10.1.1.1.3", {"type": "Counter32", "access": "read-only"})
    reg.register("snmpEngineStateChange", "1.3.6.1.6.3.10.2.1", {"type": "NOTIFICATION-TYPE", "trap": True})

    return reg