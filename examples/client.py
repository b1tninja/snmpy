"""Concrete SNMP client implementation with UDP transport and value representation.

This is the default implementation that handles socket creation,
datagram sending/receiving, response parsing, and value interpretation.

## Value Representation Layer

Re-exports MIB view classes from ``snmp.mib_view``:

- **UCDView** — Full-featured UCD-HOST-MIB / UCD-POWER-MIB view
- **IFTableView** — IF-MIB interface table only
- **HostResourcesView** — HOST-RESOURCES-MIB view

## Usage

.. code-block:: python

    from examples.client import SNMPClientImpl, UCDView, IFTableView

    client = SNMPClientImpl()
    view = UCDView(client)

    # Interface walk
    interfaces = await view.walk_interfaces("127.0.0.1", port=161)
    for iface in interfaces:
        print(f"  {iface.name}: {iface.speed} bps")

    # CPU stats
    cpu = await view.get_cpu_stats("127.0.0.1", port=161)
    print(f"  CPU Usage: {cpu['cpu_usage_percent']:.1f}%")

    # SNMP stats
    stats = await view.get_snmp_stats("127.0.0.1", port=161)
    print(f"  Bad Community Names: {stats['in_bad_community_names']}")
"""

from __future__ import annotations

from snmp.client import SNMPClientImpl
from snmp.mib_view import (
    MIBView,
    UCDView,
    IFTableView,
    HostResourcesView,
    InterfaceInfo,
    SystemMetrics,
    BatteryInfo,
    CpuStats,
    MemoryStats,
    DiskStats,
    TcpStats,
    SnmpStats,
    ProcessUserStats,
)


# ===========================================================================
# Convenience re-exports (aliases for common import patterns)
# ===========================================================================

# Legacy alias — users who want an "SNMPView" can use UCDView directly.
SNMPView = UCDView


# ===========================================================================
# Print helpers (standalone functions using UCDView internals)
# ===========================================================================

def print_interfaces(interfaces: list[InterfaceInfo]) -> None:
    """Pretty-print interface information.

    Args:
        interfaces: List of InterfaceInfo from walk_interfaces().
    """
    print(f"{'Index':>5s}  {'Name':<20s}  {'Type':<25s}  {'Status':>8s}  {'In Octets':>12s}  {'Out Octets':>12s}")
    print("    " + "-" * 90)
    for iface in interfaces:
        status_map = {1: "up", 2: "down", 3: "testing"}
        admin = status_map.get(iface.admin_status, f"unknown({iface.admin_status})")
        oper = status_map.get(iface.oper_status, f"unknown({iface.oper_status})")
        type_map = {
            6: "ethernet", 7: "iso88023", 8: "tokenBus", 9: "tokenRing",
            15: "fddi", 18: "ds1", 22: "ppp", 32: "frame-relay",
        }
        typ = type_map.get(iface.type_, f"unknown({iface.type_})")

        def fmt_bytes(n: int) -> str:
            if n < 1024: return f"{n} B"
            if n < 1024 * 1024: return f"{n / 1024:.1f} KB"
            if n < 1024 * 1024 * 1024: return f"{n / (1024 * 1024):.1f} MB"
            return f"{n / (1024 * 1024 * 1024):.1f} GB"

        print(
            f"{iface.index:>5d}  {iface.name:<20s}  {typ:<25s}  "
            f"{admin:>8s}/{oper:>8s}  {fmt_bytes(iface.in_octets):>12s}  "
            f"{fmt_bytes(iface.out_octets):>12s}"
        )


def print_snmp_stats(stats: SnmpStats) -> None:
    """Print formatted SNMP statistics.

    Args:
        stats: SnmpStats from get_snmp_stats().
    """
    print(f"  {'Counter':<30s} {'Value':>10s}")
    print("    " + "-" * 42)
    print(f"  In  Bad Community Names: {stats.in_bad_community_names:>10}")
    print(f"  In  Bad Community Uses:  {stats.in_bad_community_uses:>10}")
    print(f"  In  ASN Parse Errors:    {stats.in_asn_parse_errs:>10}")
    print(f"  In  Bad Versions:        {stats.in_bad_versions:>10}")
    print(f"  In  Total Stats Errors:  {stats.in_total_stats_errors:>10}")


def print_tcp_stats(stats: TcpStats) -> None:
    """Print formatted TCP statistics.

    Args:
        stats: TcpStats from get_tcp_stats().
    """
    print(f"  {'TCP State':<25s} {'Count':>10s}")
    print("    " + "-" * 35)
    print(f"  Established:           {stats.established:>10}")
    print(f"  Listen:                {stats.listen:>10}")
    print(f"  TimeWait:              {stats.timewait:>10}")
    print(f"  CloseWait:             {stats.close_wait:>10}")
    print(f"  Close:                 {stats.close:>10}")
    print(f"  LastAck:               {stats.last_ack:>10}")


# ===========================================================================
# SNMP Client Implementation — re-exported from snmp.client
# ===========================================================================
# SNMPClientImpl lives in snmp.client (binds 0.0.0.0, default v2c). Kept here
# so `from examples.client import SNMPClientImpl` continues to work.


__all__ = [
    # Client implementation
    "SNMPClientImpl",
    # MIB View ABC & implementations (re-exported from snmp.mib_view)
    "MIBView",
    "UCDView",
    "IFTableView",
    "HostResourcesView",
    # Legacy alias
    "SNMPView",
    # Data classes (re-exported from snmp.mib_view)
    "InterfaceInfo",
    "SystemMetrics",
    "BatteryInfo",
    "CpuStats",
    "MemoryStats",
    "DiskStats",
    "TcpStats",
    "SnmpStats",
    "ProcessUserStats",
    # Print helpers
    "print_interfaces",
    "print_snmp_stats",
    "print_tcp_stats",
]
