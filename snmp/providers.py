"""Real system information providers for SNMP MIB.

Provides classes that collect real system data and expose it through
SNMP handler interfaces.

RFC 1156 — MIB-2: System group (sysDescr, sysObjectID, sysUpTime,
         sysContact, sysName, sysLocation, sysServices)
RFC 1156 — MIB-2: Interfaces group (ifNumber, ifTable)
RFC 2863 — ifXTable: Extended Interface MIB
"""

from __future__ import annotations

import os
import platform
import socket
import time
from typing import Any, Iterator, Optional, Sequence
from collections.abc import Iterator as IteratorABC

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


class SystemInfoProvider:
    """Collects real system information for SNMP scalar objects.

    Exposes:
    - sysName (.1.3.6.1.2.1.1.5): Hostname of the system
    - sysDescr (.1.3.6.1.2.1.1.1): System description
    - sysContact (.1.3.6.1.2.1.1.4): Contact information
    - sysLocation (.1.3.6.1.2.1.1.6): Physical location
    - sysServices (.1.3.6.1.2.1.1.7): Supported services
    - sysUpTime (.1.3.6.1.2.1.1.3): Time since last restart
    """

    def __init__(self) -> None:
        """Initialize the provider."""
        self._start_time: float = time.time()
        self._contact: str = os.environ.get("SNMP_CONTACT", "root@localhost")
        self._location: str = os.environ.get("SNMP_LOCATION", "Server Room")

    def get_sys_name(self) -> str:
        """Get the system hostname."""
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"

    def get_sys_descr(self) -> str:
        """Get the system description."""
        try:
            return f"{platform.system()} {platform.release()} ({platform.machine()}) Python {platform.python_version()}"
        except Exception:
            return "Unknown System"

    def get_sys_contact(self) -> str:
        """Get the contact information."""
        return self._contact

    def set_sys_contact(self, value: str) -> None:
        """Set the contact information."""
        self._contact = value

    def get_sys_location(self) -> str:
        """Get the physical location."""
        return self._location

    def get_sys_services(self) -> int:
        """Get the services OID (RFC 1212 — 7 = internet-ns)."""
        return 7  # Standard internet services

    def get_sys_up_time(self) -> int:
        """Get the system up time in hundredths of seconds since boot."""
        return int((time.time() - self._start_time) * 100)


class NetworkInterfaceInfo:
    """Single network interface information.

    Contains all ifTable (RFC 1213) and ifXTable (RFC 2863) fields:
    - ifTable: 18 columns (.2 - .18)
    - ifXTable: 22 columns (.1.1.1.1 - .1.1.1.29)
    """

    def __init__(
        self,
        index: int,
        name: str,
        description: str,
        type_: int,
        mtu: int,
        admin_status: int,
        oper_status: int,
        mac_address: str,
        ip_address: str,
        speed: int,
        in_octets: int,
        out_octets: int,
        # ifXTable fields (RFC 2863)
        if_alias: str = "",
        if_identifier: str = "",
        if_in_ucast_pkts: int = 0,
        if_in_multicast_pkts: int = 0,
        if_in_broadcast_pkts: int = 0,
        if_out_ucast_pkts: int = 0,
        if_out_multicast_pkts: int = 0,
        if_out_broadcast_pkts: int = 0,
        if_in_discards: int = 0,
        if_out_discards: int = 0,
        if_in_errors: int = 0,
        if_out_errors: int = 0,
        if_last_change: int = 0,
        if_in_hc_octets: int = 0,
        if_out_hc_octets: int = 0,
    ):
        self.index = index
        self.name = name
        self.description = description
        self.type_ = type_
        self.mtu = mtu
        self.admin_status = admin_status
        self.oper_status = oper_status
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.speed = speed
        self.in_octets = in_octets
        self.out_octets = out_octets
        self.if_alias = if_alias
        self.if_identifier = if_identifier
        self.if_in_ucast_pkts = if_in_ucast_pkts
        self.if_in_multicast_pkts = if_in_multicast_pkts
        self.if_in_broadcast_pkts = if_in_broadcast_pkts
        self.if_out_ucast_pkts = if_out_ucast_pkts
        self.if_out_multicast_pkts = if_out_multicast_pkts
        self.if_out_broadcast_pkts = if_out_broadcast_pkts
        self.if_in_discards = if_in_discards
        self.if_out_discards = if_out_discards
        self.if_in_errors = if_in_errors
        self.if_out_errors = if_out_errors
        self.if_last_change = if_last_change
        self.if_in_hc_octets = if_in_hc_octets
        self.if_out_hc_octets = if_out_hc_octets


class NetworkInterfaceProvider:
    """Collects real network interface data.

    Exposes the ifTable (RFC 1212, RFC 2233):
    - ifNumber (.1.3.6.1.2.1.2.1.0): Number of interfaces
    - ifTable (.1.3.6.1.2.1.2.2.1): Interface information table

    Each interface row has 18 columns including:
    - ifDescr (.2): Interface description
    - ifType (.3): Interface type (1=ethernet, 6=ethernet-csmacd, 242=tokenRing)
    - ifMtu (.4): Maximum transmission unit
    - ifSpeed (.9): Current bandwidth (speed)
    - ifPhysAddress (.6): Physical/MAC address
    - ifAdminStatus (.7): Administrative status (1=up, 2=down, 3=testing)
    - ifOperStatus (.8): Operational status (1=up, 2=down, 3=testing, 4=unknown, etc.)
    - ifLastChange (.10): Last change in msec
    - ifInOctets (.10): Packets received
    - ifOutOctets (.14): Packets sent

    Also exposes ifXTable (RFC 2863) 64-bit counters and additional attributes.
    """

    ETHERNET_TYPE = 6
    TOKEN_RING_TYPE = 242
    LOOPBACK_TYPE = 24
    VIRTUAL_TYPE = 53

    @classmethod
    def get_interfaces(cls) -> list[NetworkInterfaceInfo]:
        """Get all network interfaces with real data.

        Uses psutil for interface enumeration (required on Windows, preferred
        on all platforms for compatibility). Names match psutil.net_io_counters()
        keys. Falls back to socket.if_nameindex() on Linux/Unix, or
        _fallback_get_interfaces() on platforms without psutil.

        Returns:
            List of NetworkInterfaceInfo objects.
        """
        if _HAS_PSUTIL:
            return cls._get_psutil_interfaces()

        try:
            iface_list = socket.if_nameindex()
        except (AttributeError, OSError):
            return cls._fallback_get_interfaces()

        interfaces: list[NetworkInterfaceInfo] = []
        index = 0

        for idx, name in iface_list:
            index += 1
            try:
                is_loopback = "lo" in name or "loopback" in name.lower()
                type_ = cls.LOOPBACK_TYPE if is_loopback else cls._detect_interface_type(name)

                if is_loopback:
                    continue

                try:
                    iface_index = socket.if_nametoindex(name)
                    is_up = True
                    mac = ""
                    ip = ""
                except OSError:
                    is_up = False
                    mac = ""
                    ip = ""

                interfaces.append(NetworkInterfaceInfo(
                    index=index,
                    name=name,
                    description=name,
                    type_=type_,
                    mtu=1500,
                    admin_status=1 if is_up else 2,
                    oper_status=1 if is_up else 2,
                    mac_address=mac,
                    ip_address=ip,
                    speed=0,
                    in_octets=0,
                    out_octets=0,
                ))
            except Exception:
                continue

        return interfaces if interfaces else cls._fallback_get_interfaces()

    @classmethod
    def _get_psutil_interfaces(cls) -> list[NetworkInterfaceInfo]:
        """Get interfaces using psutil for name matching with net_io_counters()."""
        interfaces: list[NetworkInterfaceInfo] = []
        index = 0

        try:
            counters = psutil.net_io_counters(pernic=True)
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except Exception:
            return cls._fallback_get_interfaces()

        for name in sorted(counters.keys()):
            index += 1
            counter = counters[name]
            nic_stats = stats.get(name)
            nic_addrs = addrs.get(name, [])

            # Skip loopback
            lower = name.lower()
            if "loopback" in lower or lower == "lo":
                continue

            is_up = nic_stats.isup if nic_stats else False
            type_ = cls._detect_interface_type(name)

            # Get MAC and IP
            mac_str = ""
            ip_str = ""
            for addr in nic_addrs:
                if hasattr(addr, 'family'):
                    try:
                        if addr.family == socket.AF_PACKET:
                            mac_str = addr.address
                    except (AttributeError, TypeError):
                        pass
                    try:
                        if addr.family in (socket.AF_INET, socket.AF_INET6):
                            if not ip_str:
                                ip_str = addr.address
                    except (AttributeError, TypeError):
                        pass

            # Speed from psutil (Mbps on most platforms)
            speed = 0
            if nic_stats and hasattr(nic_stats, 'speed') and nic_stats.speed:
                speed = int(nic_stats.speed * 1000)

            # Get per-interface counters for detailed stats
            io_counters = counters
            in_ucast = int(io_counters[name].packets_recv)
            out_ucast = int(io_counters[name].packets_sent)
            in_discards = int(io_counters[name].dropin) if hasattr(io_counters[name], 'dropin') else 0
            out_discards = int(io_counters[name].dropout) if hasattr(io_counters[name], 'dropout') else 0
            in_errors = int(io_counters[name].errin) if hasattr(io_counters[name], 'errin') else 0
            out_errors = int(io_counters[name].errout) if hasattr(io_counters[name], 'errout') else 0

            interfaces.append(NetworkInterfaceInfo(
                index=index,
                name=name,
                description=name,
                type_=type_,
                mtu=1500,
                admin_status=1 if is_up else 2,
                oper_status=1 if is_up else 2,
                mac_address=mac_str,
                ip_address=ip_str,
                speed=speed,
                in_octets=int(counter.bytes_recv),
                out_octets=int(counter.bytes_sent),
                # ifXTable fields
                if_alias=name,
                if_identifier=name,
                if_in_ucast_pkts=in_ucast,
                if_in_multicast_pkts=0,
                if_in_broadcast_pkts=0,
                if_out_ucast_pkts=out_ucast,
                if_out_multicast_pkts=0,
                if_out_broadcast_pkts=0,
                if_in_discards=in_discards,
                if_out_discards=out_discards,
                if_in_errors=in_errors,
                if_out_errors=out_errors,
                if_last_change=0,
                if_in_hc_octets=int(counter.bytes_recv),
                if_out_hc_octets=int(counter.bytes_sent),
            ))

        return interfaces

    @classmethod
    def _detect_interface_type(cls, name: str) -> int:
        """Detect interface type from name."""
        lower = name.lower()
        if "loopback" in lower or "lo" == lower:
            return cls.LOOPBACK_TYPE
        if "ethernet" in lower or "eth" in lower or "net" in lower:
            return cls.ETHERNET_TYPE
        if "wi-fi" in lower or "wireless" in lower or "wlan" in lower:
            return cls.ETHERNET_TYPE
        if "virtual" in lower or "vnic" in lower or "vmnet" in lower:
            return cls.VIRTUAL_TYPE
        return cls.ETHERNET_TYPE

    @classmethod
    def _fallback_get_interfaces(cls) -> list[NetworkInterfaceInfo]:
        """Fallback interface detection when if_nameindex() is not available."""
        interfaces: list[NetworkInterfaceInfo] = []
        index = 0

        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"

        index += 1
        try:
            interfaces.append(NetworkInterfaceInfo(
                index=index,
                name=hostname,
                description=hostname,
                type_=cls.LOOPBACK_TYPE,
                mtu=65536,
                admin_status=1,
                oper_status=1,
                mac_address="",
                ip_address="127.0.0.1",
                speed=0,
                in_octets=0,
                out_octets=0,
            ))
        except Exception:
            pass

        return interfaces

    @classmethod
    def get_if_number(cls) -> int:
        """Get the number of interfaces (ifNumber)."""
        return len(cls.get_interfaces())

    @classmethod
    def get_interface(cls, index: int) -> Optional[NetworkInterfaceInfo]:
        """Get a specific interface by index."""
        for iface in cls.get_interfaces():
            if iface.index == index:
                return iface
        return None

    @classmethod
    def iter_interfaces(cls) -> Iterator[NetworkInterfaceInfo]:
        """Iterate over interfaces lazily."""
        for iface in cls.get_interfaces():
            yield iface