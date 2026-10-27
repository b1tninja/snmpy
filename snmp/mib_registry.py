"""MIB registry for OID routing and handler dispatch.

Provides:
- MIBEntry — Single registered OID handler with metadata
- MIBRegistry — OID routing/dispatch engine

The registry maintains a sorted list of MIB entries and provides:
- Exact lookups for GetRequest
- Lexicographic successor lookups for GetNextRequest
- Set handler resolution
- Access control per OID

RFC 1157 §4.1 (Protocol Operations), RFC 3416 §4.2 (PDU Operations)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from snmp.enums import ErrorStatus
from snmp.handlers import OIDHandler


@dataclass(frozen=True)
class MIBEntry:
    """Single registered OID handler with metadata."""
    oid: str              # Registered OID prefix (e.g., "1.3.6.1.2.1.1.1")
    handler: OIDHandler   # The handler instance
    access: str           # "read", "write", "readwrite"
    priority: int = 0     # Higher priority wins on conflict


class MIBRegistry:
    """OID routing and handler dispatch engine.
    
    Maintains a registry of OID handlers and provides lookup services
    for SNMP protocol operations (GetRequest, GetNextRequest, SetRequest).
    
    Usage:
        registry = MIBRegistry()
        registry.register("1.3.6.1.2.1.1.1", handler, access="read")
        value = registry.lookup("1.3.6.1.2.1.1.1.0")  # GetRequest
        next_oid = registry.lookup_next("1.3.6.1.2.1.1.1.0")  # GetNextRequest
    """

    def __init__(self) -> None:
        """Initialize the MIB registry."""
        self._entries: list[MIBEntry] = []

    # =========================================================================
    # Registration
    # =========================================================================

    def register(
        self,
        oid: str,
        handler: OIDHandler,
        access: str = "read",
        priority: int = 0,
    ) -> None:
        """Register a handler for an OID.
        
        Args:
            oid: The OID this handler is responsible for.
            handler: The OIDHandler instance.
            access: "read", "write", or "readwrite".
            priority: Higher priority wins on exact-match conflicts.
        """
        entry = MIBEntry(oid=oid, handler=handler, access=access, priority=priority)
        # Check for conflicts
        self._check_conflict(oid, priority)
        self._entries.append(entry)
        # Keep sorted by priority (descending)
        self._entries.sort(key=lambda e: e.priority, reverse=True)

    def unregister(self, oid: str) -> bool:
        """Remove a handler by OID.
        
        Args:
            oid: The OID to unregister.
            
        Returns:
            True if removed, False if not found.
        """
        for i, entry in enumerate(self._entries):
            if entry.oid == oid:
                self._entries.pop(i)
                return True
        return False

    # =========================================================================
    # Lookups
    # =========================================================================

    def lookup(self, oid: str) -> Optional[object]:
        """Find handler for exact OID (GetRequest).
        
        Searches for the most specific match — exact OID first, then
        prefix matches, then table cell matches.
        
        Args:
            oid: The full instance OID being requested.
            
        Returns:
            The value, or None if not found.
        """
        # 1. Exact match
        for entry in self._entries:
            if oid == entry.oid or oid.startswith(entry.oid + "."):
                value = entry.handler.get(oid)
                if value is not None:
                    return value
        
        # 2. Table cell match (e.g., 1.3.6.1.2.1.2.2.1.2.1 = ifDescr.1)
        for entry in self._entries:
            if entry.handler.is_leaf:
                continue
            value = entry.handler.get(oid)
            if value is not None:
                return value
        
        return None

    def lookup_next(self, oid: str) -> Optional[str]:
        """Find the lexicographic successor of an OID (GetNextRequest).
        
        Searches all registered handlers for their successors and returns
        the closest one that is greater than the requested OID.
        
        Args:
            oid: The OID to find successor for.
            
        Returns:
            The successor OID, or None.
        """
        candidates: list[str] = []
        
        for entry in self._entries:
            next_oid = entry.handler.get_next(oid)
            if next_oid is not None:
                candidates.append(next_oid)
        
        return min(candidates) if candidates else None

    def get_set_handler(
        self,
        oid: str,
        community: str = "",
    ) -> Optional[tuple[OIDHandler, ErrorStatus]]:
        """Get the set handler for an OID.
        
        Args:
            oid: The OID to set.
            community: Community name for access control.
            
        Returns:
            Tuple of (handler, error_status), or None if no handler.
        """
        for entry in self._entries:
            if oid == entry.oid or oid.startswith(entry.oid + "."):
                if entry.handler.is_writable(community, oid):
                    return (entry.handler, ErrorStatus.no_error)
                else:
                    return (entry.handler, ErrorStatus.read_only)
        return None

    def list_handlers(self) -> list[tuple[str, OIDHandler]]:
        """List all registered handlers.
        
        Returns:
            List of (oid, handler) tuples.
        """
        return [(entry.oid, entry.handler) for entry in self._entries]

    def list_oids(self) -> list[str]:
        """List all registered OIDs."""
        return [entry.oid for entry in self._entries]

    def count(self) -> int:
        """Number of registered handlers."""
        return len(self._entries)

    def clear(self) -> None:
        """Remove all handlers."""
        self._entries.clear()

    # =========================================================================
    # Internal
    # =========================================================================

    def _check_conflict(self, oid: str, priority: int) -> None:
        """Check for conflicting registrations."""
        for entry in self._entries:
            if entry.oid == oid and entry.priority == priority:
                raise ValueError(
                    f"OID '{oid}' already registered with priority {priority}"
                )

    def find_by_oid_prefix(self, prefix: str) -> list[MIBEntry]:
        """Find all entries whose OID starts with prefix.
        
        Args:
            prefix: OID prefix to search for.
            
        Returns:
            Matching MIBEntry instances.
        """
        return [
            entry for entry in self._entries
            if entry.oid.startswith(prefix) or prefix.startswith(entry.oid)
        ]

    def get_handler_for_access(
        self,
        oid: str,
        community: str,
        required_access: str,
    ) -> Optional[OIDHandler]:
        """Get handler that supports the required access level.
        
        Args:
            oid: The OID to check.
            community: Community name.
            required_access: "read" or "write".
            
        Returns:
            The handler, or None.
        """
        for entry in self._entries:
            if oid == entry.oid or (
                not entry.handler.is_leaf and
                (oid.startswith(entry.oid + ".") or entry.oid.startswith(oid + "."))
            ):
                if required_access == "read":
                    if entry.handler.is_readable(community, oid):
                        return entry.handler
                elif required_access == "write":
                    if entry.handler.is_writable(community, oid):
                        return entry.handler
        return None