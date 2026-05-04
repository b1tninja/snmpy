"""SNMP security and authentication module.

Implements RFC 1157 §8: Security Considerations.

This module provides:
    - Community validation (RFC 1157 §3.2.5)
    - Authentication failure trap generation (RFC 1157 §4.1.6.5)
    - Community profile enforcement
    - Message size limits (RFC 1157 §4)
"""

from __future__ import annotations

from typing import Optional

from snmp.pdus import Trap
from snmp.mib import sysDescr

# ---------------------------------------------------------------------------
# Type aliases for SNMP security operations
# ---------------------------------------------------------------------------

MIBPrefix = str
"""A string representing an OID prefix pattern."""


# =============================================================================
# Exceptions
# =============================================================================

class AuthenticationError(Exception):
    """Raised when SNMP message authentication fails.

    RFC 1157 §8: "The community name is sent in the clear. A third party
    can easily determine the community name of any network element by
    eavesdropping on the network."
    """

    def __init__(self, community: str, host: str = "") -> None:
        self.community = community
        self.host = host
        super().__init__(f"Authentication failed for community '{community}' from {host}")


# =============================================================================
# Community Policy
# =============================================================================

class CommunityPolicy:
    """Defines access policies per community name.

    A community represents a grouping of management entities that share
    common access rules. Each community has:
    - A name (string of octets)
    - Read-only OIDs (available for get/trap operations)
    - Read-write OIDs (available for set operations)

    RFC 1157 §3.2.5
    """

    def __init__(
        self,
        name: str,
        read_only: Optional[list[str]] = None,
        read_write: Optional[list[str]] = None,
        hosts: Optional[list[str]] = None,
    ) -> None:
        """Initialize community policy.

        Args:
            name: The community name.
            read_only: List of OID patterns this community can read.
                       Use "*" for all OIDs, or specific OIDs like "1.3.6.1.2.1.1".
            read_write: List of OID patterns this community can write.
                       Use "*" for all OIDs, or specific OIDs.
            hosts: List of allowed IP addresses. None means all hosts.
        """
        self.name = name
        self.read_only: list[str] = read_only or []
        self.read_write: list[str] = read_write or []
        self.hosts: Optional[list[str]] = hosts  # None = allow all

    def is_allowed(self, host: str) -> bool:
        """Check if a host is allowed to use this community.

        Args:
            host: The IP address to check.

        Returns:
            True if the host is allowed.
        """
        if self.hosts is None:
            return True
        return host in self.hosts

    def can_read(self, oid: str) -> bool:
        """Check if an OID is readable under this policy.

        Args:
            oid: The Object Identifier to check.

        Returns:
            True if the OID can be read.
        """
        if not self.read_only:
            return False
        # If "*" is in the list, all OIDs are readable
        if "*" in self.read_only:
            return True
        # Check if OID starts with any of the allowed prefixes
        for pattern in self.read_only:
            if oid.startswith(pattern):
                return True
        return False

    def can_write(self, oid: str) -> bool:
        """Check if an OID is writable under this policy.

        Args:
            oid: The Object Identifier to check.

        Returns:
            True if the OID can be written.
        """
        if not self.read_write:
            return False
        if "*" in self.read_write:
            return True
        for pattern in self.read_write:
            if oid.startswith(pattern):
                return True
        return False


class CommunityDatabase:
    """Database of community policies.

    Manages the mapping between community names and their access policies.

    Per RFC 2576 §5.3, the snmpCommunityTable provides mappings between
    community strings and version-independent SNMP message parameters.
    Authentication fails when no matching community entry is found.
    """

    def __init__(self) -> None:
        self._policies: dict[str, CommunityPolicy] = {}
        self._known_communities: set[str] = set()

    def add_policy(self, policy: CommunityPolicy) -> None:
        """Add a community policy.

        Args:
            policy: The CommunityPolicy to add.
        """
        self._policies[policy.name] = policy
        self._known_communities.add(policy.name)

    def get_policy(self, community: str) -> Optional[CommunityPolicy]:
        """Get the policy for a community name.

        Args:
            community: The community name to look up.

        Returns:
            The CommunityPolicy, or None if not found.
        """
        return self._policies.get(community)

    def validate_community(self, community: str, host: str = "") -> bool:
        """Validate that a community name is known and available.

        Per RFC 2576 §5.2.1: If no matching snmpCommunityTable entry is
        found, an authentication failure occurs and snmpInBadCommunityNames
        counter is incremented.

        Args:
            community: The community name from the SNMP message.
            host: The source IP address (used for transport tag filtering).

        Returns:
            True if the community is valid.
        """
        if community not in self._known_communities:
            return False

        policy = self.get_policy(community)
        if policy is None:
            return False

        return policy.is_allowed(host)

    def validate(
        self,
        community: str,
        host: str,
        oid: Optional[str] = None,
        operation: str = "get",
    ) -> bool:
        """Validate a community against a host and operation.

        Args:
            community: The community name from the SNMP message.
            host: The source IP address.
            oid: The OID being accessed (optional).
            operation: Either "get" or "set".

        Returns:
            True if the operation is allowed.

        Raises:
            AuthenticationError: If the community is invalid or not allowed.
        """
        policy = self.get_policy(community)
        if policy is None:
            raise AuthenticationError(community, host)

        if not policy.is_allowed(host):
            raise AuthenticationError(community, host)

        if oid:
            if operation == "get":
                if not policy.can_read(oid):
                    raise AuthenticationError(community, host)
            else:
                if not policy.can_write(oid):
                    raise AuthenticationError(community, host)

        return True


class MessageSizeLimit:
    """Enforces RFC 1157 §4 message size limits.

    RFC 1157 states: "An implementation of this protocol need not accept
    messages whose length exceeds 484 octets."
    """

    def __init__(self, max_size: int = 484) -> None:
        """Initialize message size limit.

        Args:
            max_size: Maximum message size in octets. Default 484 per RFC 1157.
        """
        self.max_size = max_size

    def check_size(self, data: bytes) -> bool:
        """Check if data exceeds the message size limit.

        Args:
            data: The raw bytes to check.

        Returns:
            True if the data is within the size limit.
        """
        return len(data) <= self.max_size


# =============================================================================
# Community Profile (§3.2.5)
# =============================================================================


class CommunityProfile:
    """Defines a named community profile with associated policies.

    A community profile is a named set of communities with associated
    parameters. RFC 1157 §3.2.5 defines a community profile as a way
    to group management entities with common access rules.

    Attributes:
        name: The profile name (e.g., "public", "private").
        read_only: List of OID patterns this profile can read.
        read_write: List of OID patterns this profile can write.
        allowed_hosts: List of allowed IP addresses. None means all.
        max_message_size: Maximum message size per RFC 1157 §4.
    """

    def __init__(
        self,
        name: str,
        read_only: Optional[list[str]] = None,
        read_write: Optional[list[str]] = None,
        allowed_hosts: Optional[list[str]] = None,
        max_message_size: int = 484,
    ) -> None:
        self.name = name
        self.read_only: list[str] = read_only or ["*"]
        self.read_write: list[str] = read_write or []
        self.allowed_hosts: Optional[list[str]] = allowed_hosts
        self.max_message_size = max_message_size

    def is_allowed(self, host: str) -> bool:
        """Check if a host is allowed to use this profile."""
        if self.allowed_hosts is None:
            return True
        return host in self.allowed_hosts

    def can_read(self, oid: str) -> bool:
        """Check if an OID is readable under this profile."""
        if "*" in self.read_only:
            return True
        for pattern in self.read_only:
            if oid.startswith(pattern):
                return True
        return False

    def can_write(self, oid: str) -> bool:
        """Check if an OID is writable under this profile."""
        if not self.read_write:
            return False
        if "*" in self.read_write:
            return True
        for pattern in self.read_write:
            if oid.startswith(pattern):
                return True
        return False

    def to_policy(self) -> CommunityPolicy:
        """Convert this profile to a CommunityPolicy."""
        return CommunityPolicy(
            name=self.name,
            read_only=self.read_only,
            read_write=self.read_write,
            hosts=self.allowed_hosts,
        )


class ProfileDatabase:
    """Database of community profiles.

    Manages the mapping between profile names and their configurations.
    """

    def __init__(self) -> None:
        self._profiles: dict[str, CommunityProfile] = {}

    def add_profile(self, profile: CommunityProfile) -> None:
        """Add a community profile."""
        self._profiles[profile.name] = profile

    def get_profile(self, name: str) -> Optional[CommunityProfile]:
        """Get a community profile by name."""
        return self._profiles.get(name)

    def validate(
        self,
        community: str,
        host: str,
        oid: Optional[str] = None,
        operation: str = "get",
    ) -> bool:
        """Validate a community against a host and operation.

        Args:
            community: The community name to validate.
            host: The source IP address.
            oid: The OID being accessed (optional).
            operation: Either "get" or "set".

        Returns:
            True if valid.

        Raises:
            AuthenticationError: If the profile is invalid or not allowed.
        """
        profile = self.get_profile(community)
        if profile is None:
            raise AuthenticationError(community, host)

        if not profile.is_allowed(host):
            raise AuthenticationError(community, host)

        if oid and operation == "get" and not profile.can_read(oid):
            raise AuthenticationError(community, host)

        if oid and operation == "set" and not profile.can_write(oid):
            raise AuthenticationError(community, host)

        return True


# =============================================================================
# MIB View Filtering (§3.2.5)
# =============================================================================


class MIBViewFilter:
    """Defines a view of the MIB for a specific community/profile.

    RFC 1157 §3.2.5: A managed system contains a MIB, which is a collection
    of information about the managed entities on the network. The MIB is
    organized as a set of subtrees. A MIB view is a subset of these subtrees
    that is made available to a particular community.

    Attributes:
        name: The view name (e.g., "full", "restricted", "custom").
        included: List of OID prefixes that are IN the view.
        excluded: List of OID prefixes that are OUT of the view.
    """

    def __init__(
        self,
        name: str,
        included: Optional[list[str]] = None,
        excluded: Optional[list[str]] = None,
    ) -> None:
        self.name = name
        self.included: list[str] = included or []
        self.excluded: list[str] = excluded or []

    def is_visible(self, oid: str) -> bool:
        """Check if an OID is visible in this view.

        Rules:
        - If included is empty and excluded is empty: all OIDs visible
        - If included is set: OID must match an included prefix
        - If excluded is set: OID must NOT match an excluded prefix
        - Exclusions take priority over included

        Args:
            oid: The Object Identifier to check.

        Returns:
            True if the OID is visible in this view.
        """
        if not self.included and not self.excluded:
            return True

        for prefix in self.excluded:
            if oid.startswith(prefix):
                return False

        if self.included:
            for prefix in self.included:
                if oid.startswith(prefix):
                    return True
            return False

        return True


# Backward compatibility alias
MIBView = MIBViewFilter


class MIBViewTree:
    """Hierarchical MIB view filtering.

    Maintains a tree of included/excluded subtrees for efficient
    visibility checks. RFC 1157 §3.2.5.
    """

    def __init__(self) -> None:
        self._entries: list[tuple[str, bool]] = []

    def add_view(self, oid: str, visible: bool) -> None:
        """Add a view entry for an OID prefix.

        Args:
            oid: The OID prefix to filter.
            visible: True to include, False to exclude.
        """
        self._entries.append((oid, visible))

    def is_visible(self, oid: str) -> bool:
        """Check if an OID is visible, using most specific match.

        Args:
            oid: The Object Identifier to check.

        Returns:
            True if the OID is visible.
        """
        if not self._entries:
            return True

        best_match: Optional[tuple[str, bool]] = None
        for prefix, visible in self._entries:
            if oid.startswith(prefix) and (
                best_match is None or len(prefix) > len(best_match[0])
            ):
                best_match = (prefix, visible)

        return best_match[1] if best_match else True


# =============================================================================
# Proxy Agent Support (§3.2.5)
# =============================================================================


class ProxyAgent:
    """Represents a remote SNMP agent that can be proxied.

    RFC 1157 §3.2.5: An SNMP agent may forward requests to other agents
    on behalf of a management station. This is called proxy agent support.

    Attributes:
        name: Human-readable agent name.
        host: IP address of the remote agent.
        port: UDP port (default 161).
        community: Community name for authentication.
        view: OID view filter for this agent.
    """

    def __init__(
        self,
        name: str,
        host: str,
        port: int = 161,
        community: str = "public",
        view: Optional[MIBViewTree] = None,
    ) -> None:
        self.name = name
        self.host = host
        self.port = port
        self.community = community
        self.view: MIBViewTree = view or MIBViewTree()

    def should_proxy(self, oid: str) -> bool:
        """Check if an OID should be proxied to this agent.

        Args:
            oid: The Object Identifier to check.

        Returns:
            True if the OID should be proxied.
        """
        return self.view.is_visible(oid)


class ProxyAgentRegistry:
    """Registry of proxy agents for a management station.

    Manages the list of remote agents that can be proxied.
    RFC 1157 §3.2.5.
    """

    def __init__(self) -> None:
        self._agents: dict[str, ProxyAgent] = {}

    def add_agent(self, agent: ProxyAgent) -> None:
        """Add a proxy agent to the registry.

        Args:
            agent: The ProxyAgent to add.
        """
        self._agents[agent.name] = agent

    def get_agent(self, name: str) -> Optional[ProxyAgent]:
        """Get a proxy agent by name.

        Args:
            name: The agent name.

        Returns:
            The ProxyAgent, or None if not found.
        """
        return self._agents.get(name)

    def find_proxy(self, oid: str) -> Optional[ProxyAgent]:
        """Find the first proxy agent that should handle this OID.

        Args:
            oid: The Object Identifier to check.

        Returns:
            The first ProxyAgent that should proxy this OID, or None.
        """
        for agent in self._agents.values():
            if agent.should_proxy(oid):
                return agent
        return None


# =============================================================================
# Authentication Service (§4.1, §8)
# =============================================================================


class AuthenticationService:
    """RFC 1157 §4.1 Authentication Service.

    The authentication service validates the authenticity of SNMP messages.
    For SNMPv1/v2c, authentication is based on community name matching
    against the community database (RFC 2576 §5.3).

    RFC 2576 §5.2.1: If no matching snmpCommunityTable entry is found,
    an authentication failure occurs and snmpInBadCommunityNames counter
    is incremented.

    RFC 1157 §8: "The community name is sent in the clear. A third party
    can easily determine the community name of any network element by
    eavesdropping on the network."
    """

    def __init__(
        self,
        community_db: Optional[CommunityDatabase] = None,
        profile_db: Optional[ProfileDatabase] = None,
        message_size_limit: int = 484,
        generate_traps: bool = True,
    ) -> None:
        """Initialize authentication service.

        Args:
            community_db: Database of community policies (RFC 2576).
            profile_db: Database of community profiles.
            message_size_limit: Maximum message size in octets (default 484).
            generate_traps: Whether to generate auth failure traps.
        """
        self.community_db: CommunityDatabase = community_db or CommunityDatabase()
        self.profile_db: ProfileDatabase = profile_db or ProfileDatabase()
        self.message_size_limit = message_size_limit
        self.generate_traps = generate_traps

    def authenticate(
        self,
        community: str,
        host: str,
        oid: Optional[str] = None,
        operation: str = "get",
    ) -> bool:
        """Authenticate a community name against the profile database.

        Args:
            community: The community name from the SNMP message.
            host: The source IP address.
            oid: The OID being accessed (optional).
            operation: Either "get" or "set".

        Returns:
            True if authenticated.

        Raises:
            AuthenticationError: If authentication fails.
        """
        return self.profile_db.validate(community, host, oid, operation)

    def check_message_size(self, data: bytes) -> bool:
        """Check if a message exceeds the size limit.

        RFC 1157 §4: "An implementation of this protocol need not accept
        messages whose length exceeds 484 octets."

        Args:
            data: The raw message bytes.

        Returns:
            True if within size limit.
        """
        return len(data) <= self.message_size_limit

    def validate_community(
        self,
        community: Optional[str],
        host: str,
    ) -> bool:
        """Validate a community name against the community database.

        Per RFC 2576 §5.2.1: If no matching snmpCommunityTable entry
        is found for the incoming community string, authentication fails.

        Args:
            community: The community name to validate.
            host: The source IP address (for transport tag filtering).

        Returns:
            True if the community is valid and the host is allowed.

        Raises:
            AuthenticationError: If community is empty, None, or unknown.
        """
        if not community:
            raise AuthenticationError(community or "", host)

        return self.community_db.validate_community(community, host)

    def get_policy(self, community: str) -> Optional[CommunityPolicy]:
        """Get the policy for a community name."""
        return self.community_db.get_policy(community)

    def get_profile(self, community: str) -> Optional[CommunityProfile]:
        """Get the profile for a community name."""
        return self.profile_db.get_profile(community)


# Global authentication service instance
_auth_service: Optional[AuthenticationService] = None


def get_authentication_service() -> AuthenticationService:
    """Get the global authentication service instance."""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthenticationService()
    return _auth_service


def generate_authentication_failure_trap(
    agent_addr: str = "0.0.0.0",
    enterprise: str = "0.0.0.0",
    specific_code: int = 0,
    variables: Optional[list[tuple[str, object]]] = None,
) -> Trap:
    """Generate an authenticationFailure trap (RFC 1157 §4.1.6.5).

    This trap is generated when an SNMP message could not be authenticated.

    Args:
        agent_addr: IP address of the interface that detected the failure.
        enterprise: Enterprise OID identifying the vendor.
        specific_code: Specific code for enterprise-specific traps.
        variables: List of (oid, value) tuples for trap variable bindings.

    Returns:
        A Trap-PDU with generic-trap = authenticationFailure(4).
    """
    trap_vars = variables if variables else []

    return Trap.from_trap_type(
        trap_type=Trap.AUTHENTICATION_FAILURE,
        enterprise=enterprise,
        agent_addr=agent_addr,
        specific_code=specific_code,
        variables=trap_vars,
    )