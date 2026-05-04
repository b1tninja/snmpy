"""View-based Access Control Model (VACM) — RFC 3415.

Provides:
- AccessPolicy: VACM access policy configuration
- AccessEntry: View-based access control entry per group
- VACMView: OID subtree view (included/excluded)
- VACMAccessPolicy: Group-based access policy per security level
- VACMAccessControl: Full VACM access control database

RFC 3415 (View-based Access Control Model (VACM) for SNMPv3):
    Defines the access control model for SNMPv3 with:
    - Group mapping: Map security name + model to group
    - Access policy: Read/write/notify views per group + security level
    - View filtering: Include/exclude OID subtrees from views
    
    The VACM model defines three access levels:
    - noAuthNoPriv: No authentication or privacy required
    - authNoPriv: Authentication required, no privacy
    - authPriv: Authentication and privacy required
"""

from __future__ import annotations

from typing import Optional


# =============================================================================
# Access Policy
# =============================================================================

class AccessPolicy:
    """VACM access policy for a group at a specific security level.
    
    RFC 3415 §3.2 (AccessPolicy): The access policy defines which
    views (read, write, notify) are permitted for a group at a
    specific security level.
    
    Attributes:
        security_level: The security level (0=authNoPriv, 1=authPriv).
        read_view: OID subtrees allowed for GET/GET-NEXT operations.
        write_view: OID subtrees allowed for SET operations.
        notify_view: OID subtrees allowed for INFORM/TRAP operations.
    """
    
    def __init__(
        self,
        security_level: int = 0,
        read_view: Optional[VACMView] = None,
        write_view: Optional[VACMView] = None,
        notify_view: Optional[VACMView] = None,
    ) -> None:
        self.security_level = security_level
        self.read_view = read_view or VACMView()
        self.write_view = write_view or VACMView()
        self.notify_view = notify_view or VACMView()
    
    def check_read_access(self, oid: str) -> bool:
        """Check if a OID is allowed in the read view.
        
        Args:
            oid: The OID to check.
            
        Returns:
            True if the OID is in the read view.
        """
        return self.read_view.is_allowed(oid)
    
    def check_write_access(self, oid: str) -> bool:
        """Check if a OID is allowed in the write view.
        
        Args:
            oid: The OID to check.
            
        Returns:
            True if the OID is in the write view.
        """
        return self.write_view.is_allowed(oid)
    
    def check_notify_access(self, oid: str) -> bool:
        """Check if a OID is allowed in the notify view.
        
        Args:
            oid: The OID to check.
            
        Returns:
            True if the OID is in the notify view.
        """
        return self.notify_view.is_allowed(oid)


# =============================================================================
# VACM View
# =============================================================================

class VACMView:
    """VACM view — OID subtree include/exclude list.
    
    RFC 3415 §3.3 (VACMView): A view consists of a set of OID
    subtrees, each with an associated mask and status.
    
    - status=True means the subtree is included
    - status=False means the subtree is excluded
    - Masks allow partial matching of OID components
    
    Usage:
        >>> view = VACMView()
        >>> view.add_subtree("1.3.6.1.2.1.1")  # System group
        >>> view.add_subtree("1.3.6.1.2.1.2.2.1", included=True)  # ifTable
        >>> view.is_allowed("1.3.6.1.2.1.1.1")  # True
        >>> view.is_allowed("1.3.6.1.2.1.3.1")  # False (not in view)
    """
    
    def __init__(self) -> None:
        self._subtrees: list[tuple[str, bool]] = []  # (prefix, included)
    
    def add_subtree(self, prefix: str, included: bool = True) -> None:
        """Add an OID subtree to the view.
        
        Args:
            prefix: OID prefix (e.g., "1.3.6.1.2.1.1").
            included: True to include, False to exclude.
        """
        self._subtrees.append((prefix, included))
    
    def remove_subtree(self, prefix: str) -> bool:
        """Remove an OID subtree from the view.
        
        Args:
            prefix: The OID prefix to remove.
            
        Returns:
            True if the subtree was found and removed.
        """
        for i, (p, _) in enumerate(self._subtrees):
            if p == prefix:
                del self._subtrees[i]
                return True
        return False
    
    def is_allowed(self, oid: str) -> bool:
        """Check if an OID is allowed by this view.
        
        The view is evaluated in order: the last matching prefix
        determines the result.
        
        Args:
            oid: The OID to check.
            
        Returns:
            True if the OID is allowed by the view.
        """
        last_result = False
        for prefix, included in self._subtrees:
            if oid.startswith(prefix) or oid.startswith(prefix + "."):
                last_result = included
        return last_result
    
    def get_subtrees(self) -> list[tuple[str, bool]]:
        """Get all configured subtrees."""
        return list(self._subtrees)
    
    def clear(self) -> None:
        """Remove all subtrees from the view."""
        self._subtrees.clear()


# =============================================================================
# Access Entry
# =============================================================================

class AccessEntry:
    """VACM access entry — maps a group to an access policy.
    
    RFC 3415 §3.1 (AccessEntry): An access entry maps a group
    name, security model, and security level to an access policy.
    
    Attributes:
        group_name: The SNMPv3 group name.
        security_model: The security model ID (USM=3, SNMPv1=1).
        security_level: The security level (0=noAuthNoPriv, 1=authNoPriv, 2=authPriv).
        access_policy: The access policy for this entry.
    """
    
    def __init__(
        self,
        group_name: str,
        security_model: int,
        security_level: int = 0,
    ) -> None:
        self.group_name = group_name
        self.security_model = security_model
        self.security_level = security_level
        self.access_policy = AccessPolicy(security_level=security_level)
    
    def check_read_access(self, oid: str) -> bool:
        """Check read access for an OID."""
        return self.access_policy.check_read_access(oid)
    
    def check_write_access(self, oid: str) -> bool:
        """Check write access for an OID."""
        return self.access_policy.check_write_access(oid)
    
    def check_notify_access(self, oid: str) -> bool:
        """Check notify access for an OID."""
        return self.access_policy.check_notify_access(oid)
    
    def __repr__(self) -> str:
        return (
            f"AccessEntry(group={self.group_name!r}, "
            f"model={self.security_model}, "
            f"level={self.security_level})"
        )


# =============================================================================
# VACM Access Control
# =============================================================================

class VACMAccessControl:
    """VACM access control database.
    
    RFC 3415 §3: The VACM access control database stores the list of
    access entries, group mappings, and views.
    
    Usage:
        >>> vacm = VACMAccessControl()
        >>> vacm.add_view("public", "read", "1.3.6.1.2.1.1")
        >>> vacm.add_view("public", "read", "1.3.6.1.2.1.2")
        >>> vacm.add_access_entry(
        ...     group="public",
        ...     security_model=3,
        ...     security_level=0,
        ...     read_view="read",
        ...     write_view=None
        ... )
        >>> vacm.check_read_access("public", "1.3.6.1.2.1.1.1", 3, 0)
        True
    """
    
    def __init__(self) -> None:
        self._groups: dict[str, list[tuple[str, int, str]]] = {}
        self._entries: dict[str, AccessEntry] = {}
        self._views: dict[str, VACMView] = {}
    
    # ==================================================================
    # View Management
    # ==================================================================
    
    def add_view(self, view_name: str, prefix: str, included: bool = True) -> None:
        """Add an OID subtree to a named view.
        
        Args:
            view_name: The view name (e.g., "read", "write").
            prefix: OID prefix to add to the view.
            included: True to include, False to exclude.
        """
        if view_name not in self._views:
            self._views[view_name] = VACMView()
        self._views[view_name].add_subtree(prefix, included)
    
    def remove_view(self, view_name: str, prefix: str) -> bool:
        """Remove an OID subtree from a named view.
        
        Args:
            view_name: The view name.
            prefix: OID prefix to remove.
            
        Returns:
            True if found and removed.
        """
        if view_name in self._views:
            return self._views[view_name].remove_subtree(prefix)
        return False
    
    def get_view(self, view_name: str) -> VACMView:
        """Get a view by name.
        
        Args:
            view_name: The view name.
            
        Returns:
            VACMView or empty view if not found.
        """
        return self._views.get(view_name, VACMView())
    
    # ==================================================================
    # Group Management
    # ==================================================================
    
    def add_group(self, name: str, security_model: int, usernames: list[str]) -> None:
        """Add a group with its member usernames.
        
        Args:
            name: The group name.
            security_model: The security model ID.
            usernames: List of usernames in the group.
        """
        self._groups[name] = [(username, security_model) for username in usernames]
    
    def get_group_users(self, name: str) -> list[str]:
        """Get usernames in a group.
        
        Args:
            name: The group name.
            
        Returns:
            List of usernames.
        """
        if name in self._groups:
            return [u for u, _ in self._groups[name]]
        return []
    
    def delete_group(self, name: str) -> bool:
        """Delete a group."""
        if name in self._groups:
            del self._groups[name]
            return True
        return False
    
    # ==================================================================
    # Access Entry Management
    # ==================================================================
    
    def add_access_entry(
        self,
        group_name: str,
        security_model: int,
        security_level: int = 0,
        read_view: Optional[str] = None,
        write_view: Optional[str] = None,
        notify_view: Optional[str] = None,
    ) -> AccessEntry:
        """Add an access entry mapping a group to access policy.
        
        Args:
            group_name: The group name.
            security_model: The security model ID.
            security_level: The security level (0=noAuthNoPriv, 1=authNoPriv, 2=authPriv).
            read_view: Name of the view for read operations.
            write_view: Name of the view for write operations.
            notify_view: Name of the view for notify operations.
            
        Returns:
            The created AccessEntry.
        """
        entry = AccessEntry(group_name, security_model, security_level)
        
        if read_view and read_view in self._views:
            entry.access_policy.read_view = self._views[read_view]
        if write_view and write_view in self._views:
            entry.access_policy.write_view = self._views[write_view]
        if notify_view and notify_view in self._views:
            entry.access_policy.notify_view = self._views[notify_view]
        
        key = f"{group_name}:{security_model}:{security_level}"
        self._entries[key] = entry
        return entry
    
    # ==================================================================
    # Access Checking
    # ==================================================================
    
    def check_read_access(
        self,
        username: str,
        oid: str,
        security_model: int,
        security_level: int,
    ) -> bool:
        """Check if a user can read an OID at a given security level.
        
        RFC 3415 §3.4.2: The VACM access check algorithm:
        1. Find the group for the username
        2. Find the access entry for the group + security level
        3. Check if the OID is in the read view
        
        Args:
            username: The SNMPv3 username.
            oid: The OID to check.
            security_model: The security model ID.
            security_level: The security level.
            
        Returns:
            True if read access is allowed.
        """
        # Step 1: Find the group for the username
        group_name = None
        for name, members in self._groups.items():
            if any(u == username for u, _ in members):
                group_name = name
                break
        
        if not group_name:
            return False
        
        # Step 2: Find the access entry
        key = f"{group_name}:{security_model}:{security_level}"
        entry = self._entries.get(key)
        
        if not entry:
            return False
        
        # Step 3: Check if OID is in the read view
        return entry.check_read_access(oid)
    
    def check_write_access(
        self,
        username: str,
        oid: str,
        security_model: int,
        security_level: int,
    ) -> bool:
        """Check if a user can write to an OID at a given security level."""
        group_name = None
        for name, members in self._groups.items():
            if any(u == username for u, _ in members):
                group_name = name
                break
        
        if not group_name:
            return False
        
        key = f"{group_name}:{security_model}:{security_level}"
        entry = self._entries.get(key)
        
        if not entry:
            return False
        
        return entry.check_write_access(oid)
    
    def check_notify_access(
        self,
        username: str,
        oid: str,
        security_model: int,
        security_level: int,
    ) -> bool:
        """Check if a user can send notifications at a given security level."""
        group_name = None
        for name, members in self._groups.items():
            if any(u == username for u, _ in members):
                group_name = name
                break
        
        if not group_name:
            return False
        
        key = f"{group_name}:{security_model}:{security_level}"
        entry = self._entries.get(key)
        
        if not entry:
            return False
        
        return entry.check_notify_access(oid)
    
    # ==================================================================
    # Utility
    # ==================================================================
    
    def list_groups(self) -> list[str]:
        """List all group names."""
        return list(self._groups.keys())
    
    def list_entries(self) -> list[tuple[str, int, int]]:
        """List all access entries."""
        for key in self._entries:
            parts = key.rsplit(":", 2)
            yield (parts[0], int(parts[1]), int(parts[2]))
    
    def clear(self) -> None:
        """Remove all entries and views."""
        self._groups.clear()
        self._entries.clear()
        self._views.clear()


# =============================================================================
# Exported Names
# =============================================================================

__all__ = [
    "AccessPolicy",
    "VACMView",
    "AccessEntry",
    "VACMAccessControl",
]