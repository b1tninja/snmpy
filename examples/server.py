"""Real SNMP server implementation using system information providers.

This provides ExampleSNMPServer — a concrete SNMPServer subclass that:
- Exposes real system information (sysDescr, sysName, sysUpTime, etc.)
- Exposes real network interfaces via ifTable with lazy iteration
- Exposes system metrics (CPU, memory, disk, power) via UCD-HOST-MIB
- Listens on UDP for SNMP requests
- Supports community-based authentication (SNMPv1/v2c)

RFC 1157 §4.1 (Protocol Entity), RFC 1156 (MIB-2)
RFC 2731 (HOST-RESOURCES-MIB)
UCD-HOST-MIB (1.3.6.1.4.1.2021)
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Optional, Any

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

from snmp.server import SNMPServer
from snmp import CommunityDatabase, CommunityPolicy, AuthenticationService, SNMPDatagram, SNMPVersion
from snmp.handlers import DynamicValueHandler, EnumerableHandler
from snmp.providers import SystemInfoProvider, NetworkInterfaceProvider, NetworkInterfaceInfo
from snmp.enums import ErrorStatus
from snmp.statistics import get_statistics
from snmp.traps import get_trap_manager


# ===========================================================================
# UCD-HOST-MIB OIDs (1.3.6.1.4.1.2021) — UCD SNMP enterprise subtree
# ===========================================================================

# CPU raw counters (ssCpuRaw*)
_OID_SS_CPU_RAW_USER = "1.3.6.1.4.1.2021.11.10"
_OID_SS_CPU_RAW_NICE = "1.3.6.1.4.1.2021.11.11"
_OID_SS_CPU_RAW_SYSTEM = "1.3.6.1.4.1.2021.11.12"
_OID_SS_CPU_RAW_IDLE = "1.3.6.1.4.1.2021.11.13"
_OID_SS_CPU_RAW_IOWAIT = "1.3.6.1.4.1.2021.11.14"

# CPU stats (ssCpuStats)
_OID_SS_CPU_STATS_USER = "1.3.6.1.4.1.2021.11.50"
_OID_SS_CPU_STATS_NICE = "1.3.6.1.4.1.2021.11.51"
_OID_SS_CPU_STATS_SYSTEM = "1.3.6.1.4.1.2021.11.52"
_OID_SS_CPU_STATS_IDLE = "1.3.6.1.4.1.2021.11.53"
_OID_SS_CPU_STATS_IOWAIT = "1.3.6.1.4.1.2021.11.54"
_OID_SS_CPU_STATS_IRQ = "1.3.6.1.4.1.2021.11.55"
_OID_SS_CPU_STATS_SOFTIRQ = "1.3.6.1.4.1.2021.11.56"
_OID_SS_CPU_STATS_STEAL = "1.3.6.1.4.1.2021.11.57"
_OID_SS_CPU_STATS_GUEST = "1.3.6.1.4.1.2021.11.58"
_OID_SS_CPU_STATS_GUEST_NICE = "1.3.6.1.4.1.2021.11.59"

# Memory (mem*)
_OID_MEM_TOTAL_REAL = "1.3.6.1.4.1.2021.4.5"
_OID_MEM_FREE_REAL = "1.3.6.1.4.1.2021.4.6"
_OID_MEM_BUFFERS = "1.3.6.1.4.1.2021.4.10"
_OID_MEM_CACHED = "1.3.6.1.4.1.2021.4.11"
_OID_MEM_TOTAL_SWAP = "1.3.6.1.4.1.2021.4.8"
_OID_MEM_FREE_SWAP = "1.3.6.1.4.1.2021.4.9"
_OID_MEM_BUFFER_K = "1.3.6.1.4.1.2021.4.14"
_OID_MEM_CACHED_K = "1.3.6.1.4.1.2021.4.15"

# Disk/Storage (hrStorage*)
_OID_HR_STORAGE_INDEX = "1.3.6.1.4.1.2021.9.1"
_OID_HR_STORAGE_DESCR = "1.3.6.1.4.1.2021.9.2"
_OID_HR_STORAGE_ALLOCATION_UNITS = "1.3.6.1.4.1.2021.9.3"
_OID_HR_STORAGE_SIZE = "1.3.6.1.4.1.2021.9.4"
_OID_HR_STORAGE_USED = "1.3.6.1.4.1.2021.9.5"
_OID_HR_STORAGE_FAIL = "1.3.6.1.4.1.2021.9.6"
_OID_HR_STORAGE_AVAIL_UNAM = "1.3.6.1.4.1.2021.9.8"
_OID_HR_STORAGE_AVAIL_UNAM_K = "1.3.6.1.4.1.2021.9.9"

# UCS Battery
_OID_UCS_BATTERY_STATUS = "1.3.6.1.4.1.2021.33.1"
_OID_UCS_BATTERY_PERC = "1.3.6.1.4.1.2021.33.2"
_OID_UCS_BATTERY_ESTI_TIME = "1.3.6.1.4.1.2021.33.3"

# Load Average
_OID_SS_LOADAVG_1 = "1.3.6.1.4.1.2021.10.1"
_OID_SS_LOADAVG_5 = "1.3.6.1.4.1.2021.10.2"
_OID_SS_LOADAVG_15 = "1.3.6.1.4.1.2021.10.3"

# Network interfaces (netIf*)
_OID_NET_IF_INDEX = "1.3.6.1.4.1.2021.2.1"
_OID_NET_IF_NAMES = "1.3.6.1.4.1.2021.2.2"
_OID_NET_IF_TABLE = "1.3.6.1.4.1.2021.2.3"
_OID_NET_IF_IN_ERRORS = "1.3.6.1.4.1.2021.2.10"
_OID_NET_IF_IN_DISCARDS = "1.3.6.1.4.1.2021.2.11"
_OID_NET_IF_OUT_ERRORS = "1.3.6.1.4.1.2021.2.12"
_OID_NET_IF_OUT_DISCARDS = "1.3.6.1.4.1.2021.2.13"

# Network TCP/UDP stats (netStats*)
_OID_NET_TCP_ESTAB = "1.3.6.1.4.1.2021.6.1"
_OID_TCP_LISTEN = "1.3.6.1.4.1.2021.6.2"
_OID_TCP_TIME_WAIT = "1.3.6.1.4.1.2021.6.3"
_OID_TCP_CLOSE_WAIT = "1.3.6.1.4.1.2021.6.4"
_OID_TCP_CLOSE = "1.3.6.1.4.1.2021.6.5"
_OID_TCP_LAST_ACK = "1.3.6.1.4.1.2021.6.6"
_OID_TCP_ACTIVE_CNT = "1.3.6.1.4.1.2021.6.7"
_OID_TCP_PASSIVE_CNT = "1.3.6.1.4.1.2021.6.8"


class SystemMetricsProvider:
    """Collects real system metrics via psutil for SNMP exposure.

    Exposes system metrics via the UCD-HOST-MIB (1.3.6.1.4.1.2021)
    enterprise subtree. When psutil is unavailable, all methods
    return None gracefully.

    RFC 2731 (HOST-RESOURCES-MIB), UCD-HOST-MIB (1.3.6.1.4.1.2021)
    """

    def __init__(self) -> None:
        """Initialize the metrics provider."""
        self._cpu_percent_interval: float = 0.5  # psutil sample interval
        self._last_net_counters: Optional[dict[str, Any]] = None
        self._last_net_counters_time: float = 0.0

    # ------------------------------------------------------------------
    # CPU Metrics
    # ------------------------------------------------------------------

    def get_cpu_raw_counts(self, index: int = 0) -> Optional[dict[str, int]]:
        """Get raw CPU time counts from psutil.

        Returns:
            Dict with keys: user, nice, system, idle, iowait, irq,
            softirq, steal, guest, guest_nice. None if psutil unavailable.
        """
        if not _HAS_PSUTIL:
            return None
        try:
            cpus = psutil.cpu_times(percpu=False)
            return {
                "user": int(cpus.user * 100),
                "nice": int(cpus.nice * 100),
                "system": int(cpus.system * 100),
                "idle": int(cpus.idle * 100),
                "iowait": int(getattr(cpus, "iowait", 0) * 100),
                "irq": int(cpus.irq * 100),
                "softirq": int(cpus.softirq * 100),
                "steal": int(getattr(cpus, "steal", 0) * 100),
                "guest": int(getattr(cpus, "guest", 0) * 100),
                "guest_nice": int(getattr(cpus, "guest_nice", 0) * 100),
            }
        except Exception:
            return None

    def get_cpu_percent(self, index: int = 0) -> Optional[float]:
        """Get overall CPU usage percentage from psutil.

        Returns:
            A float 0-100 representing CPU usage. None if psutil unavailable.
        """
        if not _HAS_PSUTIL:
            return None
        try:
            return psutil.cpu_percent(percpu=False, interval=self._cpu_percent_interval)
        except Exception:
            return None

    def get_cpu_percent_per_core(self, index: int = 0) -> Optional[list[float]]:
        """Get per-CPU-core usage percentages."""
        if not _HAS_PSUTIL:
            return None
        try:
            return psutil.cpu_percent(percpu=True, interval=self._cpu_percent_interval)
        except Exception:
            return None

    def get_cpu_count(self) -> Optional[int]:
        """Get the number of logical CPUs."""
        if not _HAS_PSUTIL:
            return None
        try:
            return psutil.cpu_count(logical=True)
        except Exception:
            return None

    def get_cpu_count_physical(self) -> Optional[int]:
        """Get the number of physical (physical) CPU cores."""
        if not _HAS_PSUTIL:
            return None
        try:
            return psutil.cpu_count(logical=False)
        except Exception:
            return None

    def get_load_average(self) -> Optional[tuple[float, float, float]]:
        """Get 1, 5, and 15-minute load averages.

        Note: psutil.getloadavg() is only available on Unix-like systems.
        """
        if not _HAS_PSUTIL:
            return None
        try:
            avg = psutil.getloadavg()
            return avg
        except AttributeError:
            # getloadavg not available on Windows
            return None

    # ------------------------------------------------------------------
    # Memory Metrics
    # ------------------------------------------------------------------

    def get_memory_info(self) -> Optional[dict[str, int]]:
        """Get virtual memory information.

        Returns:
            Dict with keys: total, available, used, percent, free,
            active, inactive, buffers, cached. None if psutil unavailable.
        """
        if not _HAS_PSUTIL:
            return None
        try:
            mem = psutil.virtual_memory()
            return {
                "total": mem.total,
                "available": mem.available,
                "used": mem.used,
                "percent": int(mem.percent),
                "free": mem.free,
                "active": getattr(mem, "active", 0),
                "inactive": getattr(mem, "inactive", 0),
                "buffers": getattr(mem, "buffers", 0),
                "cached": getattr(mem, "cached", 0),
            }
        except Exception:
            return None

    def get_swap_info(self) -> Optional[dict[str, int]]:
        """Get swap memory information.

        Returns:
            Dict with keys: total, used, free, percent. None if psutil unavailable.
        """
        if not _HAS_PSUTIL:
            return None
        try:
            swap = psutil.swap_memory()
            return {
                "total": swap.total,
                "used": swap.used,
                "free": swap.free,
                "percent": int(swap.percent),
            }
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Disk Metrics
    # ------------------------------------------------------------------

    @dataclass
    class DiskInfo:
        """Disk partition information."""
        path: str
        mountpoint: str
        device: str
        fstype: str
        total: int
        used: int
        free: int
        percent: float

    def get_disk_partitions(self) -> Optional[list["SystemMetricsProvider.DiskInfo"]]:
        """Get disk partition information.

        Returns:
            List of DiskInfo objects. None if psutil unavailable.
        """
        if not _HAS_PSUTIL:
            return None
        try:
            partitions = psutil.disk_partitions(all=False)
            result = []
            for p in partitions:
                try:
                    usage = psutil.disk_usage(p.mountpoint)
                    result.append(SystemMetricsProvider.DiskInfo(
                        path=p.mountpoint,
                        mountpoint=p.mountpoint,
                        device=p.device,
                        fstype=p.fstype,
                        total=usage.total,
                        used=usage.used,
                        free=usage.free,
                        percent=usage.percent,
                    ))
                except (PermissionError, FileNotFoundError):
                    continue
            return result
        except Exception:
            return None

    def get_disk_usage(self, path: str = "/") -> Optional[dict[str, int]]:
        """Get disk usage for a specific path.

        Returns:
            Dict with keys: total, used, free, percent. None if psutil unavailable.
        """
        if not _HAS_PSUTIL:
            return None
        try:
            usage = psutil.disk_usage(path)
            return {
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": int(usage.percent),
            }
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Network Interface Metrics (Enhanced)
    # ------------------------------------------------------------------

    def get_net_io_counters(self) -> Optional[dict[str, Any]]:
        """Get per-interface network I/O counters from psutil.

        Returns:
            Dict mapping interface name to counter dict with keys:
            bytes_sent, bytes_recv, packets_sent, packets_recv,
            errin, errout, dropin, dropout. None if psutil unavailable.
        """
        if not _HAS_PSUTIL:
            return None
        try:
            counters = psutil.net_io_counters(pernic=True)
            result = {}
            for name, counters_nic in counters.items():
                result[name] = {
                    "bytes_sent": counters_nic.bytes_sent,
                    "bytes_recv": counters_nic.bytes_recv,
                    "packets_sent": counters_nic.packets_sent,
                    "packets_recv": counters_nic.packets_recv,
                    "errin": counters_nic.errin,
                    "errout": counters_nic.errout,
                    "dropin": counters_nic.dropin,
                    "dropout": counters_nic.dropout,
                }
            return result
        except Exception:
            return None

    # ------------------------------------------------------------------
    # AC Power / Battery
    # ------------------------------------------------------------------

    def get_battery_status(self) -> Optional[dict[str, Any]]:
        """Get battery/AC power status.

        Returns:
            Dict with keys: status, percent, seconds_left.
            status: 1=AC, 2=Battery, 3=Low
            None if psutil unavailable or no battery info.
        """
        if not _HAS_PSUTIL:
            return None
        try:
            battery = psutil.sensors_battery()
            if battery is None:
                return None
            # Determine status
            if battery.power_plugged is True:
                status = 1  # AC power
            elif battery.percent <= 5:
                status = 3  # Low battery
            else:
                status = 2  # On battery

            return {
                "status": status,
                "percent": battery.percent,
                "seconds_left": battery.secsleft if hasattr(battery, "secsleft") else -1,
            }
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Network TCP/UDP Stats
    # ------------------------------------------------------------------

    def get_tcp_stats(self) -> Optional[dict[str, int]]:
        """Get TCP connection state counts from psutil.

        Returns:
            Dict with keys: established, listen, timewait, closewait,
            close, lastack, active, passive. None if psutil unavailable.
        """
        if not _HAS_PSUTIL:
            return None
        try:
            connections = psutil.net_connections(kind="inet")
            counts: dict[str, int] = {
                "established": 0,
                "listen": 0,
                "timewait": 0,
                "closewait": 0,
                "close": 0,
                "lastack": 0,
                "active": 0,
                "passive": 0,
            }
            for conn in connections:
                state = conn.status if conn.status else ""
                if state == "ESTABLISHED":
                    counts["established"] += 1
                elif state == "LISTEN":
                    counts["listen"] += 1
                elif state == "TIME_WAIT":
                    counts["timewait"] += 1
                elif state == "CLOSE_WAIT":
                    counts["closewait"] += 1
                elif state == "CLOSE":
                    counts["close"] += 1
                elif state == "LAST_ACK":
                    counts["lastack"] += 1
                # Active/passive are counters, not states — skip
            return counts
        except Exception:
            return None

    def get_active_connections_count(self) -> Optional[int]:
        """Get count of active TCP connections."""
        if not _HAS_PSUTIL:
            return None
        try:
            return len(psutil.net_connections(kind="inet"))
        except Exception:
            return None

    # ------------------------------------------------------------------
    # System Info Extensions
    # ------------------------------------------------------------------

    def get_process_count(self) -> Optional[int]:
        """Get the number of running processes."""
        if not _HAS_PSUTIL:
            return None
        try:
            return len(psutil.pids())
        except Exception:
            return None

    def get_process_info(self) -> Optional[list[dict[str, Any]]]:
        """Get list of running processes."""
        if not _HAS_PSUTIL:
            return None
        try:
            result = []
            for proc in psutil.process_iter(["pid", "name", "status", "cpu_percent", "memory_percent"]):
                try:
                    info = proc.info
                    result.append({
                        "pid": info["pid"],
                        "name": info["name"] or "unknown",
                        "status": info["status"] or "unknown",
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return result
        except Exception:
            return None

    def get_users(self) -> Optional[list[dict[str, str]]]:
        """Get currently logged-in users."""
        if not _HAS_PSUTIL:
            return None
        try:
            users = psutil.users()
            return [
                {
                    "name": u.name,
                    "terminal": u.terminal or "",
                    "started": str(u.started) if hasattr(u, "started") else "",
                }
                for u in users
            ]
        except Exception:
            return None


class ExampleSNMPServer(SNMPServer):
    """Real SNMP server using system information providers.

    This is NOT a mock — it exposes real system data via the SNMP protocol:
    - sysDescr: Platform description from platform module
    - sysName: Real hostname from socket.gethostname()
    - sysUpTime: Time since server started
    - sysContact, sysLocation: Environment variables or defaults
    - ifTable: Real network interfaces from socket.if_nameindex()

    Additionally exposes system metrics via UCD-HOST-MIB (1.3.6.1.4.1.2021):
    - CPU usage, raw counters, load average
    - Memory (RAM + swap)
    - Disk partitions and usage
    - Network interface counters (psutil-based)
    - TCP connection state counts
    - Battery/AC power status (where available)

    The ifTable uses EnumerableHandler with lazy iteration, so GetNextRequest
    will enumerate interfaces one at a time without loading everything into memory.

    RFC 1157 §4.1 (Protocol Entity), RFC 1156 (MIB-2)
    """

    def __init__(
        self,
        community: str = "public",
        community_rw: str = "private",
        port: int = 1161,
    ) -> None:
        """Initialize the SNMP server.

        Args:
            community: Read-only community name (SNMPv1/v2c).
            community_rw: Read-write community name (SNMPv1/v2c).
            port: UDP port to listen on.
        """
        super().__init__()
        self.port = port

        # Real system information provider
        self._sys_info = SystemInfoProvider()

        # System metrics provider (psutil-based)
        self._metrics = SystemMetricsProvider()

        # Build community database
        self._build_community_db(community, community_rw)

        # Track server start time for sysUpTime
        self._start_time: float = time.time()

        # Initialize trap manager for trap notifications
        self._trap_mgr = get_trap_manager()
        self._trap_mgr.agent_addr = self._sys_info.get_sys_name()
        self._trap_mgr.enterprise = "1.3.6.1.4.1.0"

        # Initialize MIB with real system data
        self._init_mib()

    def _init_mib(self) -> None:
        """Initialize the MIB with real system information using handlers.

        Uses:
        - DynamicValueHandler for dynamic scalar values (sysUpTime, sysName)
        - EnumerableHandler for table-based data (ifTable, hrStorage)

        The EnumerableHandler uses lazy iteration — get_next() returns the
        next OID in lexicographic order, enabling clients to enumerate
        interfaces one at a time via GetNextRequest.
        """
        # ── System Group (RFC 1156) ──────────────────────────────────────

        # sysUpTime — dynamic scalar (computed at request time)
        # Per RFC 1212, sysUpTime returns time since boot in hundredths of seconds
        # Uses psutil.boot_time() for accurate system uptime, falls back to time.time()
        if _HAS_PSUTIL:
            self._uptime_base = psutil.boot_time()
        else:
            self._uptime_base = time.time()
        self._register_no_check(
            "1.3.6.1.2.1.1.3",
            DynamicValueHandler(
                oid="1.3.6.1.2.1.1.3",
                getter=lambda oid: int((time.time() - self._uptime_base) * 100),
                access="read",
            ),
        )

        # sysName — dynamic scalar (real hostname)
        self._register_no_check(
            "1.3.6.1.2.1.1.5",
            DynamicValueHandler(
                oid="1.3.6.1.2.1.1.5",
                getter=lambda oid: self._sys_info.get_sys_name(),
                access="read",
            ),
        )

        # sysDescr — dynamic scalar (real platform info)
        self.register_static(
            "1.3.6.1.2.1.1.1",
            self._sys_info.get_sys_descr(),
            access="read",
        )

        # sysContact — handled via direct storage in lookup_mib/set_mib
        # sysLocation — static
        self.register_static("1.3.6.1.2.1.1.6", self._sys_info.get_sys_location(), access="read")

        # ── SNMP Group (RFC 1907 §2.2) — Statistics Counters ────────────
        stats = get_statistics()
        self._register_no_check(
            "1.3.6.1.2.1.11.1",
            DynamicValueHandler(
                oid="1.3.6.1.2.1.11.1",
                getter=lambda oid: stats.snmp_in_pkts.get(),
                access="read",
            ),
        )
        self._register_no_check(
            "1.3.6.1.2.1.11.3",
            DynamicValueHandler(
                oid="1.3.6.1.2.1.11.3",
                getter=lambda oid: stats.snmp_in_bad_versions.get(),
                access="read",
            ),
        )
        self._register_no_check(
            "1.3.6.1.2.1.11.4",
            DynamicValueHandler(
                oid="1.3.6.1.2.1.11.4",
                getter=lambda oid: stats.snmp_in_bad_community_names.get(),
                access="read",
            ),
        )
        self._register_no_check(
            "1.3.6.1.2.1.11.5",
            DynamicValueHandler(
                oid="1.3.6.1.2.1.11.5",
                getter=lambda oid: stats.snmp_in_bad_community_uses.get(),
                access="read",
            ),
        )
        self._register_no_check(
            "1.3.6.1.2.1.11.6",
            DynamicValueHandler(
                oid="1.3.6.1.2.1.11.6",
                getter=lambda oid: stats.snmp_in_asn_parse_errs.get(),
                access="read",
            ),
        )

        # ── Interfaces Group (RFC 1156/1212) ─────────────────────────────

        # ifNumber — computed from interface list
        rows = self._build_interface_rows()
        self.register_static("1.3.6.1.2.1.2.1", len(rows), access="read")

        # ifTable — EnumerableHandler with lazy iteration
        # Column sub-OID suffixes per RFC 1213 (MIB-II) Section 6.4
        # ifIndex is .1 (implicit, not stored in items)
        columns = {
            "ifDescr": ".2",
            "ifType": ".3",
            "ifMtu": ".4",
            "ifSpeed": ".5",
            "ifPhysAddress": ".6",
            "ifAdminStatus": ".7",
            "ifOperStatus": ".8",
            "ifLastChange": ".9",
            "ifInOctets": ".10",
            "ifInUcastPkts": ".11",
            "ifInNUcastPkts": ".12",
            "ifInDiscards": ".13",
            "ifInErrors": ".14",
            "ifInUnknownProtos": ".15",
            "ifOutOctets": ".16",
            "ifOutUcastPkts": ".17",
            "ifOutNUcastPkts": ".18",
            "ifOutDiscards": ".19",
            "ifOutErrors": ".20",
            "ifOutQLen": ".21",
            "ifSpecific": ".22",
        }

        from snmp.handlers import EnumerableHandler
        self._if_table_handler = EnumerableHandler(
            base_oid="1.3.6.1.2.1.2.2.1",
            items=rows,
            columns=columns,
            access="read",
        )

        # ── UCD-HOST-MIB (1.3.6.1.4.1.2021) — System Metrics ─────────────

        # Only register psutil-based metrics if psutil is available
        if not _HAS_PSUTIL:
            return

        # ── CPU Metrics ──────────────────────────────────────────────────

        # ssCpuRaw* — raw CPU time counters (jiffies, scaled by 100)
        self._register_dynamic(
            _OID_SS_CPU_RAW_USER,
            DynamicValueHandler(
                oid=_OID_SS_CPU_RAW_USER,
                getter=lambda oid: self._metrics.get_cpu_raw_counts().get("user", 0) if _HAS_PSUTIL else 0,
                access="read",
            ),
        )
        self._register_dynamic(
            _OID_SS_CPU_RAW_NICE,
            DynamicValueHandler(
                oid=_OID_SS_CPU_RAW_NICE,
                getter=lambda oid: self._metrics.get_cpu_raw_counts().get("nice", 0) if _HAS_PSUTIL else 0,
                access="read",
            ),
        )
        self._register_dynamic(
            _OID_SS_CPU_RAW_SYSTEM,
            DynamicValueHandler(
                oid=_OID_SS_CPU_RAW_SYSTEM,
                getter=lambda oid: self._metrics.get_cpu_raw_counts().get("system", 0) if _HAS_PSUTIL else 0,
                access="read",
            ),
        )
        self._register_dynamic(
            _OID_SS_CPU_RAW_IDLE,
            DynamicValueHandler(
                oid=_OID_SS_CPU_RAW_IDLE,
                getter=lambda oid: self._metrics.get_cpu_raw_counts().get("idle", 0) if _HAS_PSUTIL else 0,
                access="read",
            ),
        )
        self._register_dynamic(
            _OID_SS_CPU_RAW_IOWAIT,
            DynamicValueHandler(
                oid=_OID_SS_CPU_RAW_IOWAIT,
                getter=lambda oid: self._metrics.get_cpu_raw_counts().get("iowait", 0) if _HAS_PSUTIL else 0,
                access="read",
            ),
        )

        # ssCpuStats — CPU usage percentages
        self._register_dynamic(
            _OID_SS_CPU_STATS_USER,
            DynamicValueHandler(
                oid=_OID_SS_CPU_STATS_USER,
                getter=lambda oid: self._get_cpu_stat("user"),
                access="read",
            ),
        )
        self._register_dynamic(
            _OID_SS_CPU_STATS_NICE,
            DynamicValueHandler(
                oid=_OID_SS_CPU_STATS_NICE,
                getter=lambda oid: self._get_cpu_stat("nice"),
                access="read",
            ),
        )
        self._register_dynamic(
            _OID_SS_CPU_STATS_SYSTEM,
            DynamicValueHandler(
                oid=_OID_SS_CPU_STATS_SYSTEM,
                getter=lambda oid: self._get_cpu_stat("system"),
                access="read",
            ),
        )
        self._register_dynamic(
            _OID_SS_CPU_STATS_IDLE,
            DynamicValueHandler(
                oid=_OID_SS_CPU_STATS_IDLE,
                getter=lambda oid: self._get_cpu_stat("idle"),
                access="read",
            ),
        )

        # CPU count
        self._register_dynamic(
            "1.3.6.1.4.1.2021.11.54",
            DynamicValueHandler(
                oid="1.3.6.1.4.1.2021.11.54",
                getter=lambda oid: self._metrics.get_cpu_count() or 0,
                access="read",
            ),
        )
        self._register_dynamic(
            "1.3.6.1.4.1.2021.11.55",
            DynamicValueHandler(
                oid="1.3.6.1.4.1.2021.11.55",
                getter=lambda oid: self._metrics.get_cpu_count_physical() or 0,
                access="read",
            ),
        )

        # ── Load Average ─────────────────────────────────────────────────

        self._register_dynamic(
            _OID_SS_LOADAVG_1,
            DynamicValueHandler(
                oid=_OID_SS_LOADAVG_1,
                getter=lambda oid: self._get_load_avg(0),
                access="read",
            ),
        )
        self._register_dynamic(
            _OID_SS_LOADAVG_5,
            DynamicValueHandler(
                oid=_OID_SS_LOADAVG_5,
                getter=lambda oid: self._get_load_avg(1),
                access="read",
            ),
        )
        self._register_dynamic(
            _OID_SS_LOADAVG_15,
            DynamicValueHandler(
                oid=_OID_SS_LOADAVG_15,
                getter=lambda oid: self._get_load_avg(2),
                access="read",
            ),
        )

        # ── Memory Metrics ───────────────────────────────────────────────

        mem_info = self._metrics.get_memory_info()
        if mem_info:
            self._register_dynamic(
                _OID_MEM_TOTAL_REAL,
                DynamicValueHandler(
                    oid=_OID_MEM_TOTAL_REAL,
                    getter=lambda oid: mem_info["total"] // 1024,  # Convert to KB
                    access="read",
                ),
            )
            self._register_dynamic(
                _OID_MEM_FREE_REAL,
                DynamicValueHandler(
                    oid=_OID_MEM_FREE_REAL,
                    getter=lambda oid: mem_info["free"] // 1024,
                    access="read",
                ),
            )
            self._register_dynamic(
                _OID_MEM_BUFFERS,
                DynamicValueHandler(
                    oid=_OID_MEM_BUFFERS,
                    getter=lambda oid: mem_info.get("buffers", 0) // 1024,
                    access="read",
                ),
            )
            self._register_dynamic(
                _OID_MEM_CACHED,
                DynamicValueHandler(
                    oid=_OID_MEM_CACHED,
                    getter=lambda oid: mem_info.get("cached", 0) // 1024,
                    access="read",
                ),
            )

        swap_info = self._metrics.get_swap_info()
        if swap_info:
            self._register_dynamic(
                _OID_MEM_TOTAL_SWAP,
                DynamicValueHandler(
                    oid=_OID_MEM_TOTAL_SWAP,
                    getter=lambda oid: swap_info["total"] // 1024,
                    access="read",
                ),
            )
            self._register_dynamic(
                _OID_MEM_FREE_SWAP,
                DynamicValueHandler(
                    oid=_OID_MEM_FREE_SWAP,
                    getter=lambda oid: swap_info["free"] // 1024,
                    access="read",
                ),
            )

        # ── Disk/Storage Metrics (hrStorage) ─────────────────────────────

        disk_partitions = self._metrics.get_disk_partitions()
        if disk_partitions:
            from snmp.handlers import EnumerableHandler as EH

            storage_items: list[dict] = []

            for idx, disk in enumerate(disk_partitions, start=1):
                storage_items.append({
                    "idx": idx,
                    "descr": f"{disk.fstype} at {disk.mountpoint}",
                    "alloc_unit": 1024,  # 1KB allocation units
                    "size": disk.total // 1024,  # in KB
                    "used": disk.used // 1024,  # in KB
                    "avail_unam": disk.free // 1024,  # in KB
                    "avail_unam_k": disk.free,  # in bytes
                })

            if storage_items:
                # hrStorageTable — store for walk support
                self._storage_items = storage_items

                # Register hrStorageDescr indexed entries for walk support
                for item in storage_items:
                    self.mib_registry.register(
                        f"1.3.6.1.4.1.2021.9.1.1.{item['idx']}",
                        DynamicValueHandler(
                            oid=f"1.3.6.1.4.1.2021.9.1.1.{item['idx']}",
                            getter=lambda oid, d=item["descr"]: d,
                            access="read",
                        ),
                    )

                # Register hrStorageSize indexed entries
                for item in storage_items:
                    self.mib_registry.register(
                        f"1.3.6.1.4.1.2021.9.1.3.{item['idx']}",
                        DynamicValueHandler(
                            oid=f"1.3.6.1.4.1.2021.9.1.3.{item['idx']}",
                            getter=lambda oid, s=item["size"]: s,
                            access="read",
                        ),
                    )

                # Register hrStorageUsed indexed entries
                for item in storage_items:
                    self.mib_registry.register(
                        f"1.3.6.1.4.1.2021.9.1.4.{item['idx']}",
                        DynamicValueHandler(
                            oid=f"1.3.6.1.4.1.2021.9.1.4.{item['idx']}",
                            getter=lambda oid, u=item["used"]: u,
                            access="read",
                        ),
                    )

                # Register hrStorageAvailAvailable indexed entries
                for item in storage_items:
                    self.mib_registry.register(
                        f"1.3.6.1.4.1.2021.9.1.5.{item['idx']}",
                        DynamicValueHandler(
                            oid=f"1.3.6.1.4.1.2021.9.1.5.{item['idx']}",
                            getter=lambda oid, a=item["avail_unam"]: a,
                            access="read",
                        ),
                    )

        # ── Battery/AC Power ─────────────────────────────────────────────

        battery = self._metrics.get_battery_status()
        if battery:
            self._register_dynamic(
                _OID_UCS_BATTERY_STATUS,
                DynamicValueHandler(
                    oid=_OID_UCS_BATTERY_STATUS,
                    getter=lambda oid: battery.get("status", 1),
                    access="read",
                ),
            )
            self._register_dynamic(
                _OID_UCS_BATTERY_PERC,
                DynamicValueHandler(
                    oid=_OID_UCS_BATTERY_PERC,
                    getter=lambda oid: battery.get("percent", 100),
                    access="read",
                ),
            )
            self._register_dynamic(
                _OID_UCS_BATTERY_ESTI_TIME,
                DynamicValueHandler(
                    oid=_OID_UCS_BATTERY_ESTI_TIME,
                    getter=lambda oid: battery.get("seconds_left", -1),
                    access="read",
                ),
            )

        # ── Network Interface Counters ───────────────────────────────────

        # netIfTable — netIfIndex, netIfName, netIfInErrors, etc.
        net_io = self._metrics.get_net_io_counters()
        if net_io:
            for name, counters in net_io.items():
                # netIfIndex (map interface name -> index)
                self._register_dynamic(
                    f"{_OID_NET_IF_INDEX}.1.{name}",
                    DynamicValueHandler(
                        oid=f"{_OID_NET_IF_INDEX}.1.{name}",
                        getter=lambda oid, n=name: hash(n) % 65536,
                        access="read",
                    ),
                )
                # netIfInErrors
                self._register_dynamic(
                    f"{_OID_NET_IF_IN_ERRORS}.1.{name}",
                    DynamicValueHandler(
                        oid=f"{_OID_NET_IF_IN_ERRORS}.1.{name}",
                        getter=lambda oid, n=name: counters.get("errin", 0),
                        access="read",
                    ),
                )
                # netIfInDiscards
                self._register_dynamic(
                    f"{_OID_NET_IF_IN_DISCARDS}.1.{name}",
                    DynamicValueHandler(
                        oid=f"{_OID_NET_IF_IN_DISCARDS}.1.{name}",
                        getter=lambda oid, n=name: counters.get("dropin", 0),
                        access="read",
                    ),
                )
                # netIfOutErrors
                self._register_dynamic(
                    f"{_OID_NET_IF_OUT_ERRORS}.1.{name}",
                    DynamicValueHandler(
                        oid=f"{_OID_NET_IF_OUT_ERRORS}.1.{name}",
                        getter=lambda oid, n=name: counters.get("errout", 0),
                        access="read",
                    ),
                )
                # netIfOutDiscards
                self._register_dynamic(
                    f"{_OID_NET_IF_OUT_DISCARDS}.1.{name}",
                    DynamicValueHandler(
                        oid=f"{_OID_NET_IF_OUT_DISCARDS}.1.{name}",
                        getter=lambda oid, n=name: counters.get("dropout", 0),
                        access="read",
                    ),
                )

        # ── TCP Connection Stats ─────────────────────────────────────────

        tcp_stats = self._metrics.get_tcp_stats()
        if tcp_stats:
            self._register_dynamic(
                _OID_NET_TCP_ESTAB,
                DynamicValueHandler(
                    oid=_OID_NET_TCP_ESTAB,
                    getter=lambda oid: tcp_stats.get("established", 0),
                    access="read",
                ),
            )
            self._register_dynamic(
                _OID_TCP_LISTEN,
                DynamicValueHandler(
                    oid=_OID_TCP_LISTEN,
                    getter=lambda oid: tcp_stats.get("listen", 0),
                    access="read",
                ),
            )
            self._register_dynamic(
                _OID_TCP_TIME_WAIT,
                DynamicValueHandler(
                    oid=_OID_TCP_TIME_WAIT,
                    getter=lambda oid: tcp_stats.get("timewait", 0),
                    access="read",
                ),
            )
            self._register_dynamic(
                _OID_TCP_CLOSE_WAIT,
                DynamicValueHandler(
                    oid=_OID_TCP_CLOSE_WAIT,
                    getter=lambda oid: tcp_stats.get("closewait", 0),
                    access="read",
                ),
            )
            self._register_dynamic(
                _OID_TCP_CLOSE,
                DynamicValueHandler(
                    oid=_OID_TCP_CLOSE,
                    getter=lambda oid: tcp_stats.get("close", 0),
                    access="read",
                ),
            )
            self._register_dynamic(
                _OID_TCP_LAST_ACK,
                DynamicValueHandler(
                    oid=_OID_TCP_LAST_ACK,
                    getter=lambda oid: tcp_stats.get("lastack", 0),
                    access="read",
                ),
            )

        # ── Process & User Metrics ───────────────────────────────────────

        self._register_dynamic(
            "1.3.6.1.4.1.2021.99.1",
            DynamicValueHandler(
                oid="1.3.6.1.4.1.2021.99.1",
                getter=lambda oid: self._metrics.get_process_count() or 0,
                access="read",
            ),
        )
        self._register_dynamic(
            "1.3.6.1.4.1.2021.99.2",
            DynamicValueHandler(
                oid="1.3.6.1.4.1.2021.99.2",
                getter=lambda oid: len(self._metrics.get_users() or []),
                access="read",
            ),
        )

    def _get_cpu_stat(self, stat_name: str) -> int:
        """Get a specific CPU stat percentage.

        Args:
            stat_name: One of 'user', 'nice', 'system', 'idle'.

        Returns:
            CPU stat as integer percentage, or 0 on failure.
        """
        if not _HAS_PSUTIL:
            return 0
        try:
            cpus = psutil.cpu_times(percpu=False)
            total = (cpus.user + cpus.nice + cpus.system + cpus.idle +
                     getattr(cpus, "iowait", 0) + getattr(cpus, "irq", 0) +
                     getattr(cpus, "softirq", 0) + getattr(cpus, "steal", 0))
            if total == 0:
                return 0
            values = {
                "user": cpus.user,
                "nice": cpus.nice,
                "system": cpus.system,
                "idle": cpus.idle,
            }
            val = values.get(stat_name, 0)
            return int((val / total) * 100)
        except Exception:
            return 0

    def _get_load_avg(self, index: int) -> float:
        """Get a load average value by index (0=1min, 1=5min, 2=15min).

        Args:
            index: Which load average to return.

        Returns:
            Load average as float, or 0.0 on failure.
        """
        if not _HAS_PSUTIL:
            return 0.0
        try:
            avg = psutil.getloadavg()
            if 0 <= index < len(avg):
                return avg[index]
            return 0.0
        except Exception:
            return 0.0

    def _register_dynamic(self, oid: str, handler: DynamicValueHandler) -> None:
        """Register a DynamicValueHandler directly with the MIB registry.

        Bypasses the normal register() validation for dynamic handlers.

        Args:
            oid: Object identifier string.
            handler: DynamicValueHandler instance.
        """
        self.mib_registry.register(oid, handler)

    def _build_interface_rows(self) -> list[dict]:
        """Build interface rows for the ifTable using psutil network data.

        Returns:
            List of dicts with keys matching the columns dict.
        """
        interfaces = NetworkInterfaceProvider.get_interfaces()
        rows: list[dict] = []

        # Get psutil network counters if available
        net_io: Optional[dict[str, Any]] = None
        if _HAS_PSUTIL:
            net_io = self._metrics.get_net_io_counters()

        for iface in interfaces:
            # Get network stats from psutil if available
            in_octets = 0
            out_octets = 0
            in_packets = 0
            out_packets = 0
            in_errors = 0
            out_errors = 0

            # Use psutil network counters for ifInOctets/ifOutOctets
            if net_io and iface.name in net_io:
                nic_stats = net_io[iface.name]
                in_octets = nic_stats.get("bytes_recv", 0)
                out_octets = nic_stats.get("bytes_sent", 0)
                in_packets = nic_stats.get("packets_recv", 0)
                out_packets = nic_stats.get("packets_sent", 0)
                in_errors = nic_stats.get("errin", 0)
                out_errors = nic_stats.get("errout", 0)

            # ifSpecific = .22 — reference to media-specific MIB OID
            # Default to ethernet MIB (1.3.6.1.2.1.2.2.1.22 = ifSpecific)
            if_specific_oid = "1.3.6.1.2.1.2.2.1.22" if iface.type_ == 6 else "0.0"
            from ber.object import ObjectIdentifier
            if_specific_val = ObjectIdentifier.from_string(if_specific_oid).get_object() if iface.type_ == 6 else None

            rows.append({
                "ifDescr": iface.name,
                "ifType": iface.type_,
                "ifMtu": iface.mtu,
                "ifSpeed": iface.speed,
                "ifPhysAddress": iface.mac_address,
                "ifAdminStatus": iface.admin_status,
                "ifOperStatus": iface.oper_status,
                "ifLastChange": 0,
                "ifInOctets": in_octets,
                "ifInUcastPkts": in_packets,
                "ifInNUcastPkts": 0,
                "ifInDiscards": 0,
                "ifInErrors": in_errors,
                "ifInUnknownProtos": 0,
                "ifOutOctets": out_octets,
                "ifOutUcastPkts": out_packets,
                "ifOutNUcastPkts": 0,
                "ifOutDiscards": 0,
                "ifOutErrors": out_errors,
                "ifOutQLen": 0,  # Queue length — always 0 for now
                "ifSpecific": if_specific_val,
            })
            
            # Log the actual net_io data for debugging


        if not rows:
            rows = self._get_fallback_interfaces()

        return rows

    def _get_fallback_interfaces(self) -> list[dict]:
        """Fallback interface data when no interfaces are available."""
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"
        from ber.object import ObjectIdentifier
        return [{
            "ifDescr": hostname,
            "ifType": 24,  # softwareLoopback
            "ifMtu": 65536,
            "ifSpeed": 0,
            "ifPhysAddress": "",
            "ifAdminStatus": 1,
            "ifOperStatus": 1,
            "ifLastChange": 0,
            "ifInOctets": 0,
            "ifInUcastPkts": 0,
            "ifInNUcastPkts": 0,
            "ifInDiscards": 0,
            "ifInErrors": 0,
            "ifInUnknownProtos": 0,
            "ifOutOctets": 0,
            "ifOutUcastPkts": 0,
            "ifOutNUcastPkts": 0,
            "ifOutDiscards": 0,
            "ifOutErrors": 0,
            "ifOutQLen": 0,
            "ifSpecific": ObjectIdentifier.from_string("0.0").get_object(),
        }]

    def _build_community_db(self, ro_community: str, rw_community: str) -> None:
        """Build the community database with read-only and read-write communities.

        Per RFC 2576 §5.3, the snmpCommunityTable maps community strings to
        security names, context engine IDs, and context names.
        """
        self._db = CommunityDatabase()

        ro_policy = CommunityPolicy(
            name=ro_community,
            read_only=["*"],
            read_write=[],
        )
        self._db.add_policy(ro_policy)

        rw_policy = CommunityPolicy(
            name=rw_community,
            read_write=["1.3.6.1.2.1"],  # entire MIB-2 subtree
        )
        self._db.add_policy(rw_policy)

        # Wire up AuthenticationService with the community database (RFC 2576)
        self._auth = AuthenticationService(community_db=self._db)

    # =========================================================================
    # Abstract method implementations
    # =========================================================================

    def lookup_mib(self, oid: str) -> Optional[Any]:
        """Look up a MIB value by OID instance via MIBRegistry + table handler."""
        # Check if-table handler for table lookups
        if hasattr(self, "_if_table_handler"):
            result = self._if_table_handler.get(oid)
            if result is not None:
                return result

        return self.mib_registry.lookup(oid)

    def lookup_mib_next(self, oid: str) -> Optional[str]:
        """Find the lexicographic successor of an OID via MIBRegistry + table handler."""
        # Check if-table handler for table lookups first
        if hasattr(self, "_if_table_handler"):
            result = self._if_table_handler.get_next(oid)
            if result is not None:
                return result

        return self.mib_registry.lookup_next(oid)

    def set_mib(self, oid: str, value: Any) -> bool:
        """Set a MIB value by OID via MIBRegistry."""
        # Handle sysContact
        if oid == "1.3.6.1.2.1.1.4.0" or oid.startswith("1.3.6.1.2.1.1.4"):
            if isinstance(value, bytes):
                self._sys_info.set_sys_contact(value.decode("utf-8", errors="replace"))
            elif isinstance(value, str):
                self._sys_info.set_sys_contact(value)
            return True

        set_result = self.mib_registry.get_set_handler(oid, "private")
        if set_result is None:
            return False
        handler, error_status = set_result
        if error_status != ErrorStatus.noError:
            return False
        status = handler.set(oid, value)
        return status == ErrorStatus.noError

    def get_mib_keys(self) -> list[str]:
        """Get all OIDs in the MIB via MIBRegistry + table handler."""
        keys = self.mib_registry.list_oids()
        # Add if-table cells
        if hasattr(self, "_if_table_handler"):
            cells = self._if_table_handler.get_all_cells()
            for oid, _ in cells:
                if oid not in keys:
                    keys.append(oid)
        return keys

    # =========================================================================
    # Hook overrides
    # =========================================================================

    def validate_community(self, community: str, source: str = "127.0.0.1") -> bool:
        """Validate community against the community database.

        Per RFC 2576 §5.2.1: If no matching snmpCommunityTable entry
        is found, authentication fails and no response is returned.
        """
        try:
            return self._auth.validate_community(community, source)
        except Exception:
            return False

    def validate_access(
        self,
        community: str,
        oid: str,
        access: str,
    ) -> bool:
        """Check if community has read/write access to this OID."""
        try:
            policy = self._db.get_policy(community)
            if policy is None:
                return False

            if access == "read":
                allowed = policy.read_only
            else:
                allowed = policy.read_write

            if "*" in allowed:
                return True

            for prefix in allowed:
                if oid.startswith(prefix):
                    return True
            return False
        except Exception:
            return False

    def get_response_version(self, datagram: SNMPDatagram) -> SNMPVersion:
        """Determine response version from the request datagram."""
        try:
            version_val = self._decode_version_value(datagram.version)
        except Exception:
            return SNMPVersion.v1

        if version_val == 1:
            return SNMPVersion.v2c
        return SNMPVersion.v1

    def __repr__(self) -> str:
        return f"ExampleSNMPServer(port={self.port}, mib_size={len(self.get_mib_keys())})"

    def get_trap_manager(self) -> Any:
        """Get the TrapManager for this server.

        Returns:
            The TrapManager instance.
        """
        return self._trap_mgr