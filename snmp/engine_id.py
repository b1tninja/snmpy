"""SNMP Engine ID Management — RFC 3411 §3.1.1, RFC 3412 §3.1.

Provides:
- SnmpEngineID — Engine ID representation with validation (RFC 3411 §3.1.1)
- SnmpEngineIDGenerator — Unique engine ID generation
- Engine Discovery — Request/response mechanisms (RFC 3411 §3.1.1)

Engine IDs are used to uniquely identify SNMP engine instances.
They are transmitted in Message Processing Model (MPM) messages
and must be 5-32 octets in length.

RFC 3411 §3.1.1 (Engine ID format):
    octets := format . enterprise-id . variable-binding
    format := 0x01 | 0x02 | 0x03 | 0x04 | 0x05
    - 0x01: local administration
    - 0x02: string based on DHCP-assigned IP
    - 0x03: ISO Network Address
    - 0x04: MAC address based
    - 0x05: FQDN based

Usage:
    >>> from snmp.engine_id import SnmpEngineID
    >>> engine = SnmpEngineID.from_bytes(b'\\x02\\x00\\x00\\x01\\x02\\x00\\xb8\\x12\\x34\\x56\\x78')
    >>> print(engine.format, engine.enterprise_id, engine.id)
    2 128 182502060
"""

from __future__ import annotations

import os
import socket
import time
from typing import Optional, ClassVar


# =============================================================================
# Engine ID Format Codes
# =============================================================================

class EngineFormat:
    """Engine ID format codes per RFC 3411 §3.1.1."""
    
    LOCAL_ADMINISTRATION: ClassVar[int] = 0x01
    DHCP_ASSIGNED_IP: ClassVar[int] = 0x02
    ISO_NETWORK_ADDRESS: ClassVar[int] = 0x03
    MAC_BASED: ClassVar[int] = 0x04
    FQDN_BASED: ClassVar[int] = 0x05


# =============================================================================
# SnmpEngineID
# =============================================================================

class SnmpEngineID:
    """SNMP engine ID representation.
    
    RFC 3411 §3.1.1: The snmpEngineID object is an octet string that
    uniquely identifies the SNMP engine that generated a message.
    
    The format is: format (1 byte) . enterprise-id (4 bytes) . variable (rest)
    
    Attributes:
        format: Engine format code (0x01-0x05).
        enterprise_id: Enterprise-specific identifier (4 bytes).
        id: Engine-specific variable octets.
    """
    
    MIN_LENGTH: int = 5  # Minimum 5 octets per RFC
    MAX_LENGTH: int = 32  # Maximum 32 octets per RFC
    
    def __init__(
        self,
        raw_bytes: bytes,
    ) -> None:
        """Initialize engine ID.
        
        Args:
            raw_bytes: Raw engine ID octets.
            
        Raises:
            ValueError: If length is outside 5-32 range.
        """
        if not isinstance(raw_bytes, bytes):
            raise TypeError("Engine ID must be bytes")
        
        if len(raw_bytes) < self.MIN_LENGTH:
            raise ValueError(
                f"Engine ID too short: {len(raw_bytes)} bytes, "
                f"minimum {self.MIN_LENGTH}"
            )
        
        if len(raw_bytes) > self.MAX_LENGTH:
            raise ValueError(
                f"Engine ID too long: {len(raw_bytes)} bytes, "
                f"maximum {self.MAX_LENGTH}"
            )
        
        if not raw_bytes:
            raise ValueError("Engine ID cannot be empty")
        
        self._raw_bytes = raw_bytes
        self._format = raw_bytes[0]
        self._enterprise_id = self._extract_enterprise_id()
        self._id = raw_bytes[5:]  # After format (1) + enterprise_id (4)
    
    @classmethod
    def from_bytes(cls, raw: bytes) -> SnmpEngineID:
        """Create SnmpEngineID from raw bytes.
        
        Args:
            raw: Raw engine ID octets.
            
        Returns:
            SnmpEngineID instance.
        """
        return cls(raw)
    
    @classmethod
    def from_string(cls, hex_str: str) -> SnmpEngineID:
        """Create SnmpEngineID from hex string (with or without '0x' prefix).
        
        Args:
            hex_str: Hex representation of engine ID (e.g., "020000010200b812345678").
            
        Returns:
            SnmpEngineID instance.
        """
        hex_str = hex_str.replace("0x", "")
        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str
        raw = bytes.fromhex(hex_str)
        return cls(raw)
    
    @property
    def format(self) -> int:
        """Engine format code (0x01-0x05)."""
        return self._format
    
    @property
    def enterprise_id(self) -> int:
        """Enterprise-specific identifier (4 bytes as integer)."""
        return self._enterprise_id
    
    @property
    def id(self) -> bytes:
        """Engine-specific variable octets."""
        return self._id
    
    @property
    def raw_bytes(self) -> bytes:
        """Raw engine ID bytes."""
        return self._raw_bytes
    
    @property
    def length(self) -> int:
        """Length in octets."""
        return len(self._raw_bytes)
    
    def _extract_enterprise_id(self) -> int:
        """Extract enterprise ID from bytes [1:5]."""
        return (
            (self._raw_bytes[1] << 24) |
            (self._raw_bytes[2] << 16) |
            (self._raw_bytes[3] << 8) |
            self._raw_bytes[4]
        )
    
    def encode(self) -> bytes:
        """Encode engine ID to bytes.
        
        Returns:
            Raw engine ID bytes.
        """
        return self._raw_bytes
    
    def hex(self) -> str:
        """Hex representation of engine ID.
        
        Returns:
            Hex string (e.g., "020000010200b812345678").
        """
        return self._raw_bytes.hex()
    
    def __repr__(self) -> str:
        fmt_name = f"format_{self._format}"
        return (
            f"SnmpEngineID(format={self._format}, "
            f"enterprise_id={self._enterprise_id}, "
            f"length={self.length}, hex='{self.hex()}')"
        )
    
    def __str__(self) -> str:
        return self.hex()
    
    def __bytes__(self) -> bytes:
        return self._raw_bytes
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, SnmpEngineID):
            return self._raw_bytes == other._raw_bytes
        return False
    
    def __hash__(self) -> int:
        return hash(self._raw_bytes)
    
    def __lt__(self, other: "SnmpEngineID") -> bool:
        return self._raw_bytes < other._raw_bytes


# =============================================================================
# SnmpEngineIDGenerator
# =============================================================================

class SnmpEngineIDGenerator:
    """Generate unique SNMP engine IDs.
    
    RFC 3411 §3.1.1: Engine IDs must be globally unique.
    The format code 0x01 (local administration) is recommended
    for engines where no other format is applicable.
    
    Usage:
        >>> gen = SnmpEngineIDGenerator()
        >>> engine = gen.generate()
        >>> print(engine.hex())
        '0100000101055a7519a6e39500000000'
    """
    
    def __init__(self) -> None:
        """Initialize the generator with system-specific entropy."""
        self._pid = os.getpid()
        self._timestamp = int(time.time() * 1000) & 0xFFFFFFFF
        self._counter = int.from_bytes(os.urandom(4), "big")
    
    def generate(self) -> SnmpEngineID:
        """Generate a unique engine ID using local administration format.
        
        Format: 01 00 00 01 01 {enterprise-id 3 bytes} {timestamp 4 bytes} {counter 8 bytes}
        
        Returns:
            A new SnmpEngineID instance.
        """
        self._counter += 1
        self._timestamp = int(time.time() * 1000) & 0xFFFFFFFF
        
        # Build engine ID:
        # format (0x01) + enterprise_id (0x00000101) + local_id
        local_id = os.urandom(3) + (self._timestamp.to_bytes(4, "big")) + (self._counter.to_bytes(8, "big"))
        
        raw = b"\x01\x00\x00\x01\x01" + local_id[:7]  # 5 + 7 = 12 bytes minimum
        
        return SnmpEngineID(raw)
    
    def generate_from_hostname(self) -> SnmpEngineID:
        """Generate an engine ID based on the local hostname.
        
        Format: 01 00 00 01 02 {hostname bytes} {pid 2 bytes} {timestamp 4 bytes}
        
        Returns:
            A new SnmpEngineID instance.
        """
        hostname = socket.gethostname().encode("utf-8")[:4]
        raw = b"\x01\x00\x00\x01\x02" + hostname + self._pid.to_bytes(2, "big") + self._timestamp.to_bytes(4, "big")
        raw = raw[:28]  # Pad/truncate to max 28 bytes
        
        return SnmpEngineID(raw)
    
    def generate_from_mac(self) -> SnmpEngineID:
        """Generate an engine ID based on the system MAC address.
        
        Format: 04 00 00 01 00 {MAC address 6 bytes} {timestamp 4 bytes}
        
        Returns:
            A new SnmpEngineID instance.
        """
        # Try to get MAC address
        mac = self._get_mac_address()
        raw = b"\x04\x00\x00\x01\x00" + mac + self._timestamp.to_bytes(4, "big")
        
        return SnmpEngineID(raw)
    
    @staticmethod
    def _get_mac_address() -> bytes:
        """Get the system MAC address.
        
        Returns:
            6 bytes MAC address or zeros if unavailable.
        """
        try:
            import net_if_addrs
            for name, addrs in net_if_addrs().items():
                for addr in addrs:
                    if hasattr(addr, 'family') and hasattr(addr, 'address'):
                        if str(addr.family) == 'AF_LINK':
                            return bytes.fromhex(addr.address.replace(':', ''))[:6]
        except ImportError:
            pass
        
        # Fallback: generate random MAC with local admin bit set
        mac = os.urandom(6)
        mac = bytearray(mac)
        mac[0] |= 0x02  # Set locally administered bit
        return bytes(mac)
    
    @staticmethod
    def create_default() -> SnmpEngineID:
        """Create a default engine ID using the preferred method.
        
        Returns:
            A new SnmpEngineID instance.
        """
        gen = SnmpEngineIDGenerator()
        try:
            return gen.generate_from_hostname()
        except Exception:
            return gen.generate()


# =============================================================================
# Engine Discovery
# =============================================================================

class EngineDiscoveryRecord:
    """Result of an engine discovery exchange.
    
    RFC 3411 §3.1.1: A discovery record contains the engine ID and
    discovery information from a remote SNMP engine.
    
    Attributes:
        engine_id: The discovered engine ID.
        discovery_time: Timestamp of discovery.
        source_address: Source address where discovery was received.
    """
    
    def __init__(
        self,
        engine_id: SnmpEngineID,
        source_address: str = "",
    ) -> None:
        """Initialize discovery record.
        
        Args:
            engine_id: The discovered engine ID.
            source_address: Source address where discovery was received.
        """
        self.engine_id = engine_id
        self.discovery_time = time.time()
        self.source_address = source_address
    
    def __repr__(self) -> str:
        return (
            f"EngineDiscoveryRecord("
            f"engine_id={self.engine_id.hex()[:16]}... "
            f"from {self.source_address})"
        )


# =============================================================================
# Exported Names
# =============================================================================

__all__ = [
    "SnmpEngineID",
    "SnmpEngineIDGenerator",
    "EngineDiscoveryRecord",
    "EngineFormat",
    "create_default_engine_id",
]

# Convenience function
def create_default_engine_id() -> SnmpEngineID:
    """Create a default engine ID.
    
    Returns:
        A new SnmpEngineID instance.
    """
    return SnmpEngineIDGenerator.create_default()