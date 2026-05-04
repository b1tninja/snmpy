"""MIB View Abstract Base Classes (ABC).

Implements the MIB view pattern for structured SNMP data access.

This module provides:
- Dataclasses for structured SNMP data (InterfaceInfo, SystemMetrics, BatteryInfo, etc.)
- MIBView ABC with abstract methods for common MIB operations
- Default implementations for format helpers (uptime, bytes, speeds, etc.)
- RFC cross-references for each method

Subclasses can override abstract methods to provide domain-specific MIB views:
    - IFTableView: Interface MIB (IF-MIB) focused view
    - UCDView: UCD-HOST-MIB / UCD-POWER-MIB focused view
    - HostResourcesView: HOST-RESOURCES-MIB focused view

RFC 1156, RFC 1213, RFC 1907, RFC 2578 (SMI/SMIv2)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

from snmp.client import SNMPClient
from ber.object import Object, ObjectIdentifier, OctetString, Integer

# Re-export MIBViewFilter from security for cross-package access
try:
    from snmp.security import MIBViewFilter
except ImportError:
    MIBViewFilter = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# ===========================================================================
# Data Classes — Structured Return Types
# ===========================================================================

@dataclass
class InterfaceInfo:
    """Human-readable interface information from ifTable walk."""
    index: int
    name: str
    type_: int
    descr: str
    mtu: int
    speed: int
    mac_address: str
    admin_status: int
    oper_status: int
    in_octets: int
    out_octets: int
    in_packets: int
    out_packets: int
    in_errors: int
    out_errors: int


@dataclass
class CpuStats:
    """CPU and load average statistics."""
    cpu_usage_percent: float = 0.0
    cpu_count: int = 0
    cpu_count_physical: int = 0
    load_avg_1: float = 0.0
    load_avg_5: float = 0.0
    load_avg_15: float = 0.0


@dataclass
class MemoryStats:
    """Memory statistics in KB."""
    total_kb: int = 0
    free_kb: int = 0
    used_kb: int = 0
    percent: float = 0.0
    buffers_kb: int = 0
    cached_kb: int = 0


@dataclass
class DiskStats:
    """Disk/storage metrics for a single storage entry."""
    descr: str = ""
    index: str = ""
    total_kb: int = 0
    used_kb: int = 0
    avail_kb: int = 0


@dataclass
class TcpStats:
    """TCP connection state counts."""
    established: int = 0
    listen: int = 0
    timewait: int = 0
    close_wait: int = 0
    close: int = 0
    last_ack: int = 0


@dataclass
class SnmpStats:
    """SNMP protocol statistics counters."""
    in_pkts: int = 0
    in_bad_versions: int = 0
    in_bad_community_names: int = 0
    in_bad_community_uses: int = 0
    in_asn_parse_errs: int = 0
    out_pkts: int = 0
    out_bad_versions: int = 0
    out_bad_community_names: int = 0
    out_asn_parse_errs: int = 0
    in_total_stats_errors: int = 0
    out_total_stats_errors: int = 0


@dataclass
class ProcessUserStats:
    """Process and user statistics."""
    process_count: int = 0
    user_count: int = 0


@dataclass
class SystemMetrics:
    """Combined CPU and memory metrics."""
    cpu: CpuStats = field(default_factory=CpuStats)
    memory: MemoryStats = field(default_factory=MemoryStats)


@dataclass
class BatteryInfo:
    """Battery/AC power status."""
    status: int = 1  # 1=AC, 2=Battery, 3=Low
    percent: float = 100.0
    seconds_left: int = -1
    status_text: str = "AC Power"


# ===========================================================================
# MIB View ABC
# ===========================================================================

class MIBView(ABC):
    """Abstract base class for MIB view implementations.

    Provides a structured interface for querying and interpreting SNMP MIB data.
    Subclasses implement abstract methods to provide domain-specific views.

    RFC 1156, RFC 1213, RFC 1907, RFC 2578
    """

    def __init__(self, client: SNMPClient) -> None:
        """Initialize the view with an SNMP client.

        Args:
            client: SNMPClient instance for sending requests.
        """
        self.client = client

    # ------------------------------------------------------------------
    # Abstract methods — MUST be implemented by subclasses
    # ------------------------------------------------------------------

    @abstractmethod
    async def walk_interfaces(self, host: str, port: int = 161) -> list[InterfaceInfo]:
        """Walk the ifTable (IF-MIB) and return InterfaceInfo objects."""
        ...

    @abstractmethod
    async def get_cpu_stats(self, host: str, port: int = 161) -> CpuStats:
        """Get CPU and load average statistics."""
        ...

    @abstractmethod
    async def get_memory_stats(self, host: str, port: int = 161) -> MemoryStats:
        """Get memory statistics."""
        ...

    @abstractmethod
    async def get_battery(self, host: str, port: int = 161) -> Optional[BatteryInfo]:
        """Get battery/AC power status."""
        ...

    @abstractmethod
    async def get_snmp_stats(self, host: str, port: int = 161) -> SnmpStats:
        """Get SNMP protocol statistics counters."""
        ...

    @abstractmethod
    async def get_tcp_stats(self, host: str, port: int = 161) -> TcpStats:
        """Get TCP connection state counts."""
        ...

    @abstractmethod
    async def get_process_user_stats(self, host: str, port: int = 161) -> ProcessUserStats:
        """Get process and user statistics."""
        ...

    @abstractmethod
    async def get_disk_stats(self, host: str, port: int = 161) -> list[DiskStats]:
        """Get disk/storage metrics."""
        ...

    # ------------------------------------------------------------------
    # Concrete helper methods
    # ------------------------------------------------------------------

    @staticmethod
    def format_uptime(value: object) -> str:
        """Format sysUpTime (hundredths of seconds) as human-readable string.

        Args:
            value: Raw sysUpTime value — Python int, BER Integer Object, or bytes.

        Returns:
            Formatted uptime string, e.g. "1:51:46" or "2 days, 1:51:46".
        """
        if value is None:
            return "(unknown)"

        hundredths: int = 0
        if hasattr(value, "__int__"):
            try:
                hundredths = int(value)
            except (TypeError, ValueError):
                pass

        if hundredths == 0 and isinstance(value, bytes):
            try:
                hundredths = int.from_bytes(value, byteorder="big")
            except (TypeError, ValueError):
                pass

        if hundredths == 0:
            try:
                hundredths = int(value)
            except (TypeError, ValueError):
                return "(invalid)"

        if hundredths == 0:
            return "0:00:00"

        total_seconds = hundredths // 100
        td = timedelta(seconds=total_seconds)
        return str(td)

    def get_uptime(self, host: str, port: int = 161) -> str:
        """Get formatted sysUpTime from a host."""
        try:
            result = self.client.get(host, "1.3.6.1.2.1.1.3.0", port)
            return self.format_uptime(result)
        except (OSError, ValueError, TypeError, KeyError, TimeoutError):
            logger.debug("get_uptime failed: host=%s port=%d", host, port)
            return "(unknown)"

    @staticmethod
    def format_if_type(type_: int) -> str:
        """Format ifType INTEGER as human-readable string."""
        type_map = {
            1: "other", 2: "regular1822", 3: "hdh1822", 4: "ddn-x25",
            5: "rfc877-x25", 6: "ethernet-csmacd", 7: "iso88023-csmacd",
            8: "iso88024-tokenBus", 9: "iso88025-tokenRing", 10: "iso88026-man",
            11: "starLan", 12: "proteon-10Mbit", 13: "proteon-80Mbit",
            14: "hyperchannel", 15: "fddi", 16: "lapb", 17: "sdlc",
            18: "ds1", 19: "e1", 20: "basicISDN", 21: "primaryISDN",
            22: "propPointToPointSerial", 23: "ppp", 24: "softwareLoopback",
            25: "eon", 26: "ethernet-3Mbit", 27: "nsip", 28: "slip",
            29: "ultra", 30: "ds3", 31: "sip", 32: "frame-relay",
        }
        return type_map.get(type_, f"unknown({type_})")

    @staticmethod
    def format_admin_status(status: int) -> str:
        """Format ifAdminStatus as text."""
        return {1: "up", 2: "down", 3: "testing"}.get(status, f"unknown({status})")

    @staticmethod
    def format_oper_status(status: int) -> str:
        """Format ifOperStatus as text."""
        return {1: "up", 2: "down", 3: "testing"}.get(status, f"unknown({status})")

    @staticmethod
    def format_bytes(num: int) -> str:
        """Format bytes with SI unit prefix."""
        if num is None or num == 0:
            return "0 B"
        if num < 1024:
            return f"{num} B"
        if num < 1024 * 1024:
            return f"{num / 1024:.1f} KB"
        if num < 1024 * 1024 * 1024:
            return f"{num / (1024 * 1024):.1f} MB"
        return f"{num / (1024 * 1024 * 1024):.1f} GB"

    @staticmethod
    def format_speed(bps: int) -> str:
        """Format bytes per second with SI unit prefix."""
        if bps is None or bps == 0:
            return "0 bps"
        if bps < 1000:
            return f"{bps} bps"
        if bps < 1_000_000:
            return f"{bps / 1000:.1f} Kbps"
        if bps < 1_000_000_000:
            return f"{bps / 1_000_000:.1f} Mbps"
        return f"{bps / 1_000_000_000:.1f} Gbps"

    def print_interfaces(self, interfaces: list[InterfaceInfo]) -> None:
        """Pretty-print interface information."""
        print(f"{'Index':>5s}  {'Name':<20s}  {'Type':<25s}  {'Status':>8s}  {'In Octets':>12s}  {'Out Octets':>12s}")
        print("    " + "-" * 90)
        for iface in interfaces:
            status = f"{self.format_admin_status(iface.admin_status)}/{self.format_oper_status(iface.oper_status)}"
            print(
                f"{iface.index:>5d}  {iface.name:<20s}  {self.format_if_type(iface.type_):<25s}  "
                f"{status:>8s}  {self.format_bytes(iface.in_octets):>12s}  "
                f"{self.format_bytes(iface.out_octets):>12s}"
            )

    def print_uptime(self, host: str, port: int = 161) -> None:
        """Print formatted sysUpTime."""
        uptime = self.get_uptime(host, port)
        print(f"  sysUpTime: {uptime}")


# ===========================================================================
# Helper: parse ifTable walk results
# ===========================================================================

def _parse_if_table_results(
    results: list[tuple[str, object]],
) -> dict[int, dict[str, object]]:
    """Group ifTable walk results by interface index.

    Args:
        results: List of (oid_str, value) from client.walk().

    Returns:
        Dict mapping ifIndex -> dict of column_name -> value.
    """
    interface_data: dict[int, dict[str, object]] = {}

    for oid_str, value in results:
        if not isinstance(value, Object):
            continue
        parts = oid_str.split(".")
        if len(parts) < 11:
            continue
        try:
            column_idx = int(parts[9])
            iface_idx = int(parts[10])
        except (ValueError, IndexError):
            continue

        if iface_idx not in interface_data:
            interface_data[iface_idx] = {}

        column_map = {
            2: "name", 3: "type_", 4: "mtu", 5: "speed",
            6: "mac_address", 7: "admin_status", 8: "oper_status",
            9: "if_last_change", 10: "in_octets", 11: "in_packets",
            12: "in_nucast_pkts", 13: "in_discards", 14: "in_errors",
            15: "in_unknown", 16: "out_octets", 17: "out_packets",
            18: "out_nucast_pkts", 19: "out_discards", 20: "out_errors",
        }

        field_name = column_map.get(column_idx)
        if field_name is None:
            continue

        if isinstance(value, OctetString):
            interface_data[iface_idx][field_name] = str(value)
        elif isinstance(value, Integer):
            interface_data[iface_idx][field_name] = int(value)
        elif isinstance(value, ObjectIdentifier):
            interface_data[iface_idx][field_name] = str(value)
        elif isinstance(value, Object):
            try:
                interface_data[iface_idx][field_name] = int(value)
            except (ValueError, TypeError):
                interface_data[iface_idx][field_name] = str(value)
        else:
            interface_data[iface_idx][field_name] = value

    return interface_data


# ===========================================================================
# Concrete Implementations
# ===========================================================================

class IFTableView(MIBView):
    """Interface Table (IF-MIB) focused view."""

    async def walk_interfaces(self, host: str, port: int = 161) -> list[InterfaceInfo]:
        """Walk the ifTable and return InterfaceInfo objects."""
        results: list[tuple[str, object]] = []
        try:
            results = await self.client.walk(host, "1.3.6.1.2.1.2.2.1", port)
        except (OSError, TimeoutError):
            logger.debug("walk_interfaces(ifTable) failed: host=%s port=%d", host, port)
            return []

        interface_data = _parse_if_table_results(results)

        interfaces: list[InterfaceInfo] = []
        for idx in sorted(interface_data.keys()):
            data = interface_data[idx]
            interfaces.append(InterfaceInfo(
                index=idx,
                name=data.get("name", "unknown"),
                type_=data.get("type_", 0),
                descr=data.get("name", "unknown"),
                mtu=data.get("mtu", 0),
                speed=data.get("speed", 0),
                mac_address=data.get("mac_address", ""),
                admin_status=data.get("admin_status", 0),
                oper_status=data.get("oper_status", 0),
                in_octets=data.get("in_octets", 0),
                out_octets=data.get("out_octets", 0),
                in_packets=data.get("in_packets", 0),
                out_packets=data.get("out_packets", 0),
                in_errors=data.get("in_errors", 0),
                out_errors=data.get("out_errors", 0),
            ))
        return interfaces

    async def get_cpu_stats(self, host: str, port: int = 161) -> CpuStats:
        return CpuStats()

    async def get_memory_stats(self, host: str, port: int = 161) -> MemoryStats:
        return MemoryStats()

    async def get_battery(self, host: str, port: int = 161) -> Optional[BatteryInfo]:
        return None

    async def get_snmp_stats(self, host: str, port: int = 161) -> SnmpStats:
        return SnmpStats()

    async def get_tcp_stats(self, host: str, port: int = 161) -> TcpStats:
        return TcpStats()

    async def get_process_user_stats(self, host: str, port: int = 161) -> ProcessUserStats:
        return ProcessUserStats()

    async def get_disk_stats(self, host: str, port: int = 161) -> list[DiskStats]:
        return []


class UCDView(MIBView):
    """UCD-HOST-MIB / UCD-POWER-MIB focused view."""

    _UCD_HOST = "1.3.6.1.4.1.2021"
    _UCD_POWER = "1.3.6.1.4.1.2021.33"

    async def walk_interfaces(self, host: str, port: int = 161) -> list[InterfaceInfo]:
        """Walk ifTable using IF-MIB-2."""
        results: list[tuple[str, object]] = []
        try:
            results = await self.client.walk(host, "1.3.6.1.2.1.2.2.1", port)
        except (OSError, TimeoutError):
            logger.debug("walk_interfaces(IF-MIB) failed: host=%s port=%d", host, port)
            return []

        interface_data = _parse_if_table_results(results)

        interfaces: list[InterfaceInfo] = []
        for idx in sorted(interface_data.keys()):
            data = interface_data[idx]
            interfaces.append(InterfaceInfo(
                index=idx,
                name=data.get("name", "unknown"),
                type_=data.get("type_", 0),
                descr=data.get("name", "unknown"),
                mtu=data.get("mtu", 0),
                speed=data.get("speed", 0),
                mac_address=data.get("mac_address", ""),
                admin_status=data.get("admin_status", 0),
                oper_status=data.get("oper_status", 0),
                in_octets=data.get("in_octets", 0),
                out_octets=data.get("out_octets", 0),
                in_packets=data.get("in_packets", 0),
                out_packets=data.get("out_packets", 0),
                in_errors=data.get("in_errors", 0),
                out_errors=data.get("out_errors", 0),
            ))
        return interfaces

    async def get_cpu_stats(self, host: str, port: int = 161) -> CpuStats:
        """Get CPU stats from UCD-HOST-MIB (1.3.6.1.4.1.2021.11.x)."""
        result = CpuStats()
        try:
            idle_pct = await self.client.get(host, f"{self._UCD_HOST}.11.53", port)
            if idle_pct is not None:
                idle = int(idle_pct)
                result.cpu_usage_percent = round(100.0 - idle, 1)

            cpu_count = await self.client.get(host, f"{self._UCD_HOST}.11.54", port)
            if cpu_count is not None:
                result.cpu_count = int(cpu_count)

            cpu_physical = await self.client.get(host, f"{self._UCD_HOST}.11.55", port)
            if cpu_physical is not None:
                result.cpu_count_physical = int(cpu_physical)

            load1 = await self.client.get(host, f"{self._UCD_HOST}.10.1", port)
            if load1 is not None:
                result.load_avg_1 = float(load1)
            load5 = await self.client.get(host, f"{self._UCD_HOST}.10.2", port)
            if load5 is not None:
                result.load_avg_5 = float(load5)
            load15 = await self.client.get(host, f"{self._UCD_HOST}.10.3", port)
            if load15 is not None:
                result.load_avg_15 = float(load15)
        except (OSError, TimeoutError, ValueError, TypeError, KeyError):
            logger.debug("get_cpu_stats(UCD-HOST-MIB) failed: host=%s port=%d", host, port)
        return result

    async def get_memory_stats(self, host: str, port: int = 161) -> MemoryStats:
        """Get memory stats from UCD-HOST-MIB (1.3.6.1.4.1.2021.4.x)."""
        result = MemoryStats()
        try:
            total = await self.client.get(host, f"{self._UCD_HOST}.4.5", port)
            free = await self.client.get(host, f"{self._UCD_HOST}.4.6", port)
            buffers = await self.client.get(host, f"{self._UCD_HOST}.4.10", port)
            cached = await self.client.get(host, f"{self._UCD_HOST}.4.11", port)

            if total is not None:
                result.total_kb = int(total)
            if free is not None:
                result.free_kb = int(free)
            if buffers is not None:
                result.buffers_kb = int(buffers)
            if cached is not None:
                result.cached_kb = int(cached)

            if result.total_kb > 0:
                result.used_kb = result.total_kb - result.free_kb
                result.percent = round(((result.total_kb - result.free_kb) / result.total_kb) * 100, 1)
        except (OSError, TimeoutError, ValueError, TypeError, KeyError):
            logger.debug("get_memory_stats(UCD-HOST-MIB) failed: host=%s port=%d", host, port)
        return result

    async def get_battery(self, host: str, port: int = 161) -> Optional[BatteryInfo]:
        """Get battery status from UCD-POWER-MIB (1.3.6.1.4.1.2021.33.x)."""
        try:
            status_raw = await self.client.get(host, f"{self._UCD_POWER}.1", port)
        except (OSError, TimeoutError, ValueError):
            logger.debug("get_battery(UCD-POWER) query failed: host=%s port=%d", host, port)
            return None

        if status_raw is None:
            return None

        status = 1
        try:
            status = int(status_raw)
        except (TypeError, ValueError):
            status = 1

        percent = 100.0
        try:
            perc_raw = await self.client.get(host, f"{self._UCD_POWER}.2", port)
            if perc_raw is not None:
                percent = float(perc_raw)
        except (OSError, TimeoutError, ValueError, TypeError):
            logger.debug("get_battery(percent) failed: host=%s port=%d", host, port)

        secs = -1
        try:
            secs_raw = await self.client.get(host, f"{self._UCD_POWER}.3", port)
            if secs_raw is not None:
                secs = int(secs_raw)
        except (OSError, TimeoutError, ValueError, TypeError):
            logger.debug("get_battery(seconds_left) failed: host=%s port=%d", host, port)

        status_text = {1: "AC Power", 2: "Battery", 3: "Low Battery"}.get(
            status, f"Unknown({status})"
        )

        return BatteryInfo(status=status, percent=percent, seconds_left=secs, status_text=status_text)

    async def get_snmp_stats(self, host: str, port: int = 161) -> SnmpStats:
        """Get SNMP protocol statistics (1.3.6.1.2.1.11.x)."""
        stats = SnmpStats()
        oids: dict[str, str] = {
            "in_pkts": "1.3.6.1.2.1.11.1",
            "in_bad_versions": "1.3.6.1.2.1.11.3",
            "in_bad_community_names": "1.3.6.1.2.1.11.4",
            "in_bad_community_uses": "1.3.6.1.2.1.11.5",
            "in_asn_parse_errs": "1.3.6.1.2.1.11.6",
            "out_pkts": "1.3.6.1.2.1.11.26",
            "out_bad_versions": "1.3.6.1.2.1.11.27",
            "out_bad_community_names": "1.3.6.1.2.1.11.28",
            "out_asn_parse_errs": "1.3.6.1.2.1.11.29",
            "in_total_stats_errors": "1.3.6.1.2.1.11.30",
            "out_total_stats_errors": "1.3.6.1.2.1.11.31",
        }
        for field_name, oid in oids.items():
            try:
                val = await self.client.get(host, oid, port)
                setattr(stats, field_name, int(val) if val is not None else 0)
            except (OSError, TimeoutError, ValueError, TypeError, KeyError):
                logger.debug("get_snmp_stats(key=%s) failed: host=%s port=%d", field_name, host, port)
                setattr(stats, field_name, 0)
        return stats

    async def get_tcp_stats(self, host: str, port: int = 161) -> TcpStats:
        """Get TCP connection state counts from UCD-HOST-MIB (1.3.6.1.4.1.2021.6.x)."""
        result = TcpStats()
        oids: dict[str, str] = {
            "established": f"{self._UCD_HOST}.6.1",
            "listen": f"{self._UCD_HOST}.6.2",
            "timewait": f"{self._UCD_HOST}.6.3",
            "close_wait": f"{self._UCD_HOST}.6.4",
            "close": f"{self._UCD_HOST}.6.5",
            "last_ack": f"{self._UCD_HOST}.6.6",
        }
        for field_name, oid in oids.items():
            try:
                val = await self.client.get(host, oid, port)
                if val is not None:
                    setattr(result, field_name, int(val))
            except (OSError, TimeoutError, ValueError, TypeError, KeyError):
                logger.debug("get_tcp_stats(key=%s) failed: host=%s port=%d", field_name, host, port)
        return result

    async def get_process_user_stats(self, host: str, port: int = 161) -> ProcessUserStats:
        """Get process and user stats from UCD-HOST-MIB (1.3.6.1.4.1.2021.99.x)."""
        result = ProcessUserStats()
        try:
            val = await self.client.get(host, f"{self._UCD_HOST}.99.1", port)
            if val is not None:
                result.process_count = int(val)
        except (OSError, TimeoutError, ValueError, TypeError):
            logger.debug("get_process_user_stats(process_count) failed: host=%s port=%d", host, port)
        try:
            val = await self.client.get(host, f"{self._UCD_HOST}.99.2", port)
            if val is not None:
                result.user_count = int(val)
        except (OSError, TimeoutError, ValueError, TypeError):
            logger.debug("get_process_user_stats(user_count) failed: host=%s port=%d", host, port)
        return result

    async def get_disk_stats(self, host: str, port: int = 161) -> list[DiskStats]:
        """Get disk/storage metrics from UCD-HOST-MIB hrStorage (1.3.6.1.4.1.2021.9.x)."""
        results: list[DiskStats] = []
        try:
            descr_data = await self.client.walk(host, f"{self._UCD_HOST}.9.1.1", port)
            if not descr_data:
                return results

            for oid, value in descr_data:
                parts = oid.split(".")
                if len(parts) > 9:
                    try:
                        idx = oid.rsplit(".", 1)[1]
                        descr = str(value) if value else ""
                        if not descr:
                            continue

                        size_oid = f"{self._UCD_HOST}.9.1.3.{idx}"
                        used_oid = f"{self._UCD_HOST}.9.1.4.{idx}"
                        avail_oid = f"{self._UCD_HOST}.9.1.5.{idx}"

                        size_val = await self.client.get(host, size_oid, port)
                        used_val = await self.client.get(host, used_oid, port)
                        avail_val = await self.client.get(host, avail_oid, port)

                        alloc_unit = 1024
                        results.append(DiskStats(
                            descr=descr,
                            index=idx,
                            total_kb=int(size_val) * alloc_unit // 1024 if size_val else 0,
                            used_kb=int(used_val) * alloc_unit // 1024 if used_val else 0,
                            avail_kb=int(avail_val) * alloc_unit // 1024 if avail_val else 0,
                        ))
                    except (OSError, ValueError, TypeError, KeyError):
                        logger.debug("get_disk_stats(entry index=%s) failed: host=%s port=%d", idx, host, port)
                        continue
        except (OSError, TimeoutError):
            logger.debug("get_disk_stats(hrStorage walk) failed: host=%s port=%d", host, port)
        return results

    def print_disk_stats(self, host: str, port: int = 161) -> None:
        """Print formatted disk storage statistics."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            stats = loop.run_until_complete(self.get_disk_stats(host, port))
        except (RuntimeError, OSError, TimeoutError):
            logger.debug("print_disk_stats failed: host=%s port=%d", host, port)
            print("  Disk statistics unavailable")
            return

        if not stats:
            print("  No disk storage information available")
            return

        print(f"  {'Description':<30s} {'Used':>10s} {'Total':>10s} {'Free':>10s}")
        print("    " + "-" * 60)
        for disk in stats:
            descr = disk.descr[:28] if len(disk.descr) <= 28 else disk.descr[:26] + ".."
            used_mb = disk.used_kb / 1024
            total_mb = disk.total_kb / 1024
            avail_mb = disk.avail_kb / 1024
            print(f"  {descr:<28s} {used_mb:>9.0f} MB {total_mb:>9.0f} MB {avail_mb:>9.0f} MB")

    def print_snmp_stats(self, host: str, port: int = 161) -> None:
        """Print formatted SNMP statistics."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            stats = loop.run_until_complete(self.get_snmp_stats(host, port))
        except (RuntimeError, OSError, TimeoutError):
            logger.debug("print_snmp_stats failed: host=%s port=%d", host, port)
            print("  SNMP statistics unavailable")
            return

        print(f"  {'Counter':<30s} {'Value':>10s}")
        print("    " + "-" * 42)
        print(f"  In  Bad Community Names: {stats.in_bad_community_names:>10}")
        print(f"  In  Bad Community Uses:  {stats.in_bad_community_uses:>10}")
        print(f"  In  ASN Parse Errors:    {stats.in_asn_parse_errs:>10}")
        print(f"  In  Bad Versions:        {stats.in_bad_versions:>10}")
        print(f"  In  Total Stats Errors:  {stats.in_total_stats_errors:>10}")

    def print_tcp_stats(self, host: str, port: int = 161) -> None:
        """Print formatted TCP statistics."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            stats = loop.run_until_complete(self.get_tcp_stats(host, port))
        except (RuntimeError, OSError, TimeoutError):
            logger.debug("print_tcp_stats failed: host=%s port=%d", host, port)
            print("  TCP statistics unavailable")
            return

        print(f"  {'TCP State':<25s} {'Count':>10s}")
        print("    " + "-" * 35)
        print(f"  Established:           {stats.established:>10}")
        print(f"  Listen:                {stats.listen:>10}")
        print(f"  TimeWait:              {stats.timewait:>10}")
        print(f"  CloseWait:             {stats.close_wait:>10}")
        print(f"  Close:                 {stats.close:>10}")
        print(f"  LastAck:               {stats.last_ack:>10}")


class HostResourcesView(MIBView):
    """HOST-RESOURCES-MIB focused view."""

    _HR_MIB = "1.3.6.1.2.1.25"

    async def walk_interfaces(self, host: str, port: int = 161) -> list[InterfaceInfo]:
        """Walk ifTable using IF-MIB-2."""
        results: list[tuple[str, object]] = []
        try:
            results = await self.client.walk(host, "1.3.6.1.2.1.2.2.1", port)
        except (OSError, TimeoutError):
            logger.debug("walk_interfaces(IF-MIB, HostResourcesView) failed: host=%s port=%d", host, port)
            return []

        interface_data = _parse_if_table_results(results)

        interfaces: list[InterfaceInfo] = []
        for idx in sorted(interface_data.keys()):
            data = interface_data[idx]
            interfaces.append(InterfaceInfo(
                index=idx,
                name=data.get("name", "unknown"),
                type_=data.get("type_", 0),
                descr=data.get("name", "unknown"),
                mtu=data.get("mtu", 0),
                speed=data.get("speed", 0),
                mac_address=data.get("mac_address", ""),
                admin_status=data.get("admin_status", 0),
                oper_status=data.get("oper_status", 0),
                in_octets=data.get("in_octets", 0),
                out_octets=data.get("out_octets", 0),
                in_packets=data.get("in_packets", 0),
                out_packets=data.get("out_packets", 0),
                in_errors=data.get("in_errors", 0),
                out_errors=data.get("out_errors", 0),
            ))
        return interfaces

    async def get_cpu_stats(self, host: str, port: int = 161) -> CpuStats:
        """Get CPU stats from HOST-RESOURCES-MIB or UCD-HOST-MIB fallback."""
        result = CpuStats()
        try:
            idle_pct = await self.client.get(host, "1.3.6.1.4.1.2021.11.53", port)
            if idle_pct is not None:
                result.cpu_usage_percent = round(100.0 - int(idle_pct), 1)
            cpu_count = await self.client.get(host, "1.3.6.1.4.1.2021.11.54", port)
            if cpu_count is not None:
                result.cpu_count = int(cpu_count)
        except (OSError, TimeoutError, ValueError, TypeError):
            logger.debug("get_cpu_stats(HR-MIB) failed: host=%s port=%d", host, port)
        return result

    async def get_memory_stats(self, host: str, port: int = 161) -> MemoryStats:
        """Get memory stats from HOST-RESOURCES-MIB (hrMemorySize) or UCD fallback."""
        result = MemoryStats()
        try:
            total = await self.client.get(host, "1.3.6.1.4.1.2021.4.5", port)
            free = await self.client.get(host, "1.3.6.1.4.1.2021.4.6", port)
            if total is not None and free is not None:
                result.total_kb = int(total)
                result.free_kb = int(free)
                if result.total_kb > 0:
                    result.used_kb = result.total_kb - result.free_kb
                    result.percent = round(((result.total_kb - result.free_kb) / result.total_kb) * 100, 1)
        except (OSError, TimeoutError, ValueError, TypeError):
            logger.debug("get_memory_stats(HR-MIB) failed: host=%s port=%d", host, port)
        return result

    async def get_battery(self, host: str, port: int = 161) -> Optional[BatteryInfo]:
        """Get battery info from UCD-POWER-MIB or HOST-RESOURCES-MIB."""
        try:
            status_raw = await self.client.get(host, "1.3.6.1.4.1.2021.33.1", port)
        except (OSError, TimeoutError):
            return None
        if status_raw is None:
            return None

        status = 1
        try:
            status = int(status_raw)
        except (TypeError, ValueError):
            pass

        percent = 100.0
        try:
            perc_raw = await self.client.get(host, "1.3.6.1.4.1.2021.33.2", port)
            if perc_raw is not None:
                percent = float(perc_raw)
        except (OSError, TimeoutError, ValueError, TypeError):
            pass

        secs = -1
        try:
            secs_raw = await self.client.get(host, "1.3.6.1.4.1.2021.33.3", port)
            if secs_raw is not None:
                secs = int(secs_raw)
        except (OSError, TimeoutError, ValueError, TypeError):
            pass

        status_text = {1: "AC Power", 2: "Battery", 3: "Low Battery"}.get(
            status, f"Unknown({status})"
        )
        return BatteryInfo(status=status, percent=percent, seconds_left=secs, status_text=status_text)

    async def get_snmp_stats(self, host: str, port: int = 161) -> SnmpStats:
        """Get SNMP statistics from SNMP group (1.3.6.1.2.1.11.x)."""
        stats = SnmpStats()
        oids: dict[str, str] = {
            "in_pkts": "1.3.6.1.2.1.11.1",
            "in_bad_versions": "1.3.6.1.2.1.11.3",
            "in_bad_community_names": "1.3.6.1.2.1.11.4",
            "in_bad_community_uses": "1.3.6.1.2.1.11.5",
            "in_asn_parse_errs": "1.3.6.1.2.1.11.6",
            "out_pkts": "1.3.6.1.2.1.11.26",
            "out_bad_versions": "1.3.6.1.2.1.11.27",
            "out_bad_community_names": "1.3.6.1.2.1.11.28",
            "out_asn_parse_errs": "1.3.6.1.2.1.11.29",
            "in_total_stats_errors": "1.3.6.1.2.1.11.30",
            "out_total_stats_errors": "1.3.6.1.2.1.11.31",
        }
        for field_name, oid in oids.items():
            try:
                val = await self.client.get(host, oid, port)
                setattr(stats, field_name, int(val) if val is not None else 0)
            except (OSError, TimeoutError, ValueError, TypeError, KeyError):
                setattr(stats, field_name, 0)
        return stats

    async def get_tcp_stats(self, host: str, port: int = 161) -> TcpStats:
        """Get TCP stats from UCD-HOST-MIB."""
        result = TcpStats()
        oids: dict[str, str] = {
            "established": "1.3.6.1.4.1.2021.6.1",
            "listen": "1.3.6.1.4.1.2021.6.2",
            "timewait": "1.3.6.1.4.1.2021.6.3",
            "close_wait": "1.3.6.1.4.1.2021.6.4",
            "close": "1.3.6.1.4.1.2021.6.5",
            "last_ack": "1.3.6.1.4.1.2021.6.6",
        }
        for field_name, oid in oids.items():
            try:
                val = await self.client.get(host, oid, port)
                if val is not None:
                    setattr(result, field_name, int(val))
            except (OSError, TimeoutError, ValueError, TypeError, KeyError):
                pass
        return result

    async def get_process_user_stats(self, host: str, port: int = 161) -> ProcessUserStats:
        """Get process and user stats from UCD-HOST-MIB."""
        result = ProcessUserStats()
        try:
            val = await self.client.get(host, "1.3.6.1.4.1.2021.99.1", port)
            if val is not None:
                result.process_count = int(val)
        except (OSError, TimeoutError, ValueError, TypeError):
            pass
        try:
            val = await self.client.get(host, "1.3.6.1.4.1.2021.99.2", port)
            if val is not None:
                result.user_count = int(val)
        except (OSError, TimeoutError, ValueError, TypeError):
            pass
        return result

    async def get_disk_stats(self, host: str, port: int = 161) -> list[DiskStats]:
        """Get disk stats from hrStorage (UCD-HOST-MIB)."""
        results: list[DiskStats] = []
        try:
            descr_data = await self.client.walk(host, "1.3.6.1.4.1.2021.9.1.1", port)
            if not descr_data:
                return results

            for oid, value in descr_data:
                parts = oid.split(".")
                if len(parts) > 9:
                    try:
                        idx = oid.rsplit(".", 1)[1]
                        descr = str(value) if value else ""
                        if not descr:
                            continue
                        size_oid = f"1.3.6.1.4.1.2021.9.1.3.{idx}"
                        used_oid = f"1.3.6.1.4.1.2021.9.1.4.{idx}"
                        avail_oid = f"1.3.6.1.4.1.2021.9.1.5.{idx}"
                        size_val = await self.client.get(host, size_oid, port)
                        used_val = await self.client.get(host, used_oid, port)
                        avail_val = await self.client.get(host, avail_oid, port)
                        alloc_unit = 1024
                        results.append(DiskStats(
                            descr=descr, index=idx,
                            total_kb=int(size_val) * alloc_unit // 1024 if size_val else 0,
                            used_kb=int(used_val) * alloc_unit // 1024 if used_val else 0,
                            avail_kb=int(avail_val) * alloc_unit // 1024 if avail_val else 0,
                        ))
                    except (OSError, ValueError, TypeError, KeyError):
                        continue
        except (OSError, TimeoutError):
            pass
        return results


# ===========================================================================
# Exports
# ===========================================================================

__all__ = [
    # Data classes
    "InterfaceInfo",
    "CpuStats",
    "MemoryStats",
    "DiskStats",
    "TcpStats",
    "SnmpStats",
    "ProcessUserStats",
    "SystemMetrics",
    "BatteryInfo",
    # ABC
    "MIBView",
    # Re-exported from security (OID visibility filter)
    "MIBViewFilter",
    # Concrete implementations
    "IFTableView",
    "UCDView",
    "HostResourcesView",
    # Helper
    "_parse_if_table_results",
]