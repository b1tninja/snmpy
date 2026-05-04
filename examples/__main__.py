"""SNMP end-to-end demonstration - Real ExampleSNMPServer with SNMPClientImpl.

Run with: python -m examples

This demo shows the complete SNMP request/response cycle:
1. Client sends GetRequest via UDP -> Server receives
2. Server dispatches to handler -> Client receives GetResponse
3. Client decodes BER -> Presents human-readable value

All communication uses real SNMP protocol over UDP (localhost:1161).
"""

from __future__ import annotations

import asyncio

from examples.server import ExampleSNMPServer
from examples.client import SNMPClientImpl, UCDView
from snmp.enums import SNMPVersion


def _print_value(label: str, val: object) -> str:
    """Print and return a value safely."""
    if val is None:
        print(f"    {label} = None")
        return ""
    if isinstance(val, bytes):
        try:
            text = val.decode("utf-8", errors="replace")
            print(f"    {label} = {text}")
            return text
        except Exception:
            print(f"    {label} = {val!r}")
            return repr(val)
    else:
        print(f"    {label} = {val}")
        return str(val)


async def main() -> None:
    """Demonstrate SNMP server/client with end-to-end request/response flow."""
    print("=" * 70)
    print("SNMP End-to-End Demonstration")
    print("  Client <-> UDP (localhost:1161) <-> Server")
    print("=" * 70)

    # =========================================================================
    # 1. Start SNMP Server
    # =========================================================================
    print("\n=== 1. Starting SNMP Server ===")
    server = ExampleSNMPServer(
        community="public",
        community_rw="private",
        port=1161,
    )

    print(f"  Server: {type(server).__name__}")
    print(f"  Registered OIDs: {len(server.get_mib_keys())}")
    print(f"  Listening on: 127.0.0.1:1161")

    await server.start("127.0.0.1", 1161)
    await asyncio.sleep(0.3)

    # =========================================================================
    # 2. Create SNMP Client (UDP endpoint)
    # =========================================================================
    print("\n=== 2. SNMP Client Configuration ===")
    client = SNMPClientImpl(community="public", version=SNMPVersion.v1, timeout=2.0)
    print(f"  Community: {client.community}")
    print(f"  Version: SNMPv1")
    print(f"  Timeout: {client.timeout}s")

    # =========================================================================
    # 3. System Information (GetRequest for scalar OIDs)
    # =========================================================================
    print("\n=== 3. System Information (GetRequest) ===")

    # Get sysDescr
    print("\n  [GetRequest] sysDescr")
    await _demo_get(client, "127.0.0.1", 1161, "1.3.6.1.2.1.1.1.0", "System Description")

    # Get sysName
    print("  [GetRequest] sysName")
    await _demo_get(client, "127.0.0.1", 1161, "1.3.6.1.2.1.1.5.0", "System Name")

    # Get sysUpTime (formatted)
    print("  [GetRequest] sysUpTime")
    await _demo_get_with_format(client, "127.0.0.1", 1161, "1.3.6.1.2.1.1.3.0", "System Up Time")

    # =========================================================================
    # 4. Network Interfaces (GetNext walk)
    # =========================================================================
    print("\n=== 4. Network Interfaces (GetNext Walk) ===")
    await _demo_interfaces(client, "127.0.0.1", 1161)

    # =========================================================================
    # 5. System Metrics via UCD-HOST-MIB (GetRequest)
    # =========================================================================
    print("\n=== 5. System Metrics (UCD-HOST-MIB GetRequest) ===")
    await _demo_cpu(client, "127.0.0.1", 1161)
    await _demo_load_avg(client, "127.0.0.1", 1161)
    await _demo_memory(client, "127.0.0.1", 1161)

    # =========================================================================
    # 6. Disk/Storage Metrics (hrStorage Walk)
    # =========================================================================
    print("\n=== 6. Disk/Storage Metrics (hrStorage Walk) ===")
    await _demo_disk(client, "127.0.0.1", 1161)

    # =========================================================================
    # 7. TCP Connection Stats
    # =========================================================================
    print("\n=== 7. TCP Connection Statistics ===")
    await _demo_tcp(client, "127.0.0.1", 1161)

    # =========================================================================
    # 8. Process & User Stats
    # =========================================================================
    print("\n=== 8. Process & User Statistics ===")
    await _demo_proc_users(client, "127.0.0.1", 1161)

    # =========================================================================
    # 9. Battery/AC Power
    # =========================================================================
    print("\n=== 9. Battery/AC Power Status ===")
    await _demo_battery(client, "127.0.0.1", 1161)

    # =========================================================================
    # 10. Cleanup
    # =========================================================================
    print("\n=== 10. Cleanup ===")
    await client.close()
    await server.stop()
    print("  Client closed, server stopped")

    print("\n" + "=" * 70)
    print("End-to-end SNMP demonstration complete.")
    print("All communication was via UDP (localhost:1161)")
    print("=" * 70)


async def _demo_get(
    client: SNMPClientImpl, host: str, port: int, oid: str, desc: str
) -> None:
    """Demonstrate a GetRequest for a single OID."""
    print(f"    -> Sending GetRequest for {oid} ({desc})")
    value = await client.get(host, oid, port)
    _print_value(f"    <- Response", value)


async def _demo_get_with_format(
    client: SNMPClientImpl, host: str, port: int, oid: str, desc: str
) -> None:
    """Demonstrate GetRequest with formatted output."""
    print(f"    -> Sending GetRequest for {oid} ({desc})")
    value = await client.get(host, oid, port)
    formatted = UCDView.format_uptime(value)
    _print_value(f"    Raw value", value)
    print(f"    Formatted: {formatted}")


async def _demo_interfaces(
    client: SNMPClientImpl, host: str, port: int
) -> None:
    """Demonstrate ifTable walk using the UCDView interface contract."""
    view = UCDView(client)
    interface_list = await view.walk_interfaces(host, port)
    view.print_interfaces(interface_list)


async def _demo_cpu(client: SNMPClientImpl, host: str, port: int) -> None:
    """Demonstrate CPU statistics via SNMPView."""
    view = UCDView(client)
    cpu_stats = await view.get_cpu_stats(host, port)
    print(f"\n  [SNMPView] CPU Statistics")
    print(f"    CPU Usage: {cpu_stats.cpu_usage_percent:.1f}%")
    print(f"    CPU Count: {cpu_stats.cpu_count}")


async def _demo_load_avg(client: SNMPClientImpl, host: str, port: int) -> None:
    """Demonstrate load average statistics via SNMPView."""
    view = UCDView(client)
    cpu_stats = await view.get_cpu_stats(host, port)
    print("\n  [SNMPView] Load Averages")
    print(f"    1min:  {cpu_stats.load_avg_1:>8.2f}")
    print(f"    5min:  {cpu_stats.load_avg_5:>8.2f}")
    print(f"    15min: {cpu_stats.load_avg_15:>8.2f}")


async def _demo_memory(client: SNMPClientImpl, host: str, port: int) -> None:
    """Demonstrate memory statistics via SNMPView."""
    view = UCDView(client)
    mem_stats = await view.get_memory_stats(host, port)
    print("\n  [SNMPView] Memory Statistics")
    print(f"    Total: {mem_stats.total_kb} KB")
    print(f"    Free:  {mem_stats.free_kb} KB")
    print(f"    Used:  {mem_stats.used_kb} KB ({mem_stats.percent:.1f}%)")
    if mem_stats.buffers_kb or mem_stats.cached_kb:
        print(f"    Buffers: {mem_stats.buffers_kb} KB")
        print(f"    Cached:  {mem_stats.cached_kb} KB")


async def _demo_disk(client: SNMPClientImpl, host: str, port: int) -> None:
    """Demonstrate disk/storage metrics via SNMPView."""
    view = UCDView(client)
    disk_stats = await view.get_disk_stats(host, port)
    print("\n  [SNMPView] Disk/Storage Statistics")
    if disk_stats:
        print(f"    Received {len(disk_stats)} disk entries:")
        for i, disk in enumerate(disk_stats[:5], 1):
            print(f"    {i}. {disk.descr}")
            print(f"       Total: {disk.total_kb} KB, Used: {disk.used_kb} KB, Free: {disk.avail_kb} KB")
    else:
        print("    No disk storage data received")


async def _demo_tcp(client: SNMPClientImpl, host: str, port: int) -> None:
    """Demonstrate TCP connection statistics via SNMPView."""
    view = UCDView(client)
    tcp_stats = await view.get_tcp_stats(host, port)
    print("\n  [SNMPView] TCP Connection States")
    print(f"    ESTABLISHED: {tcp_stats.established}")
    print(f"    LISTEN:      {tcp_stats.listen}")
    print(f"    TIME_WAIT:   {tcp_stats.timewait}")
    print(f"    CLOSE_WAIT:  {tcp_stats.close_wait}")
    print(f"    CLOSE:       {tcp_stats.close}")
    print(f"    LAST_ACK:    {tcp_stats.last_ack}")


async def _demo_proc_users(client: SNMPClientImpl, host: str, port: int) -> None:
    """Demonstrate process and user statistics via SNMPView."""
    view = UCDView(client)
    stats = await view.get_process_user_stats(host, port)
    print("\n  [SNMPView] Process & User Statistics")
    print(f"    Running processes: {stats.process_count}")
    print(f"    Logged-in users:   {stats.user_count}")


async def _demo_battery(client: SNMPClientImpl, host: str, port: int) -> None:
    """Demonstrate battery/AC power status via SNMPView."""
    view = UCDView(client)
    battery = await view.get_battery(host, port)
    print("\n  [SNMPView] Battery/AC Power Status")
    if battery is None:
        print("    Battery status unavailable (no battery detected)")
    else:
        print(f"    Status:    {battery.status_text}")
        print(f"    Percent:   {battery.percent}%")
        print(f"    Seconds:   {battery.seconds_left if battery.seconds_left >= 0 else 'Unknown'}")


if __name__ == "__main__":
    asyncio.run(main())