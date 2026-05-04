# SNMP Examples

Example SNMP server and client implementations demonstrating RFC 1157/1156 protocol operations.

## Quick Start

```bash
python -m examples
```

This starts a real SNMP server (`ExampleSNMPServer`) and queries it via UDP using `SNMPClientImpl`:

1. Query sysDescr (1.3.6.1.2.1.1.1.0)
2. Query sysName (1.3.6.1.2.1.1.5.0)
3. Query sysUpTime (1.3.6.1.2.1.1.3.0)
4. Walk ifTable (1.3.6.1.2.1.2.2.1) — enumerate network interfaces
5. Test handler registration (StaticValueHandler, DynamicValueHandler, CounterHandler)
6. Demonstrate CompoundHandler for grouping subtrees
7. Test custom minimal server

## Examples

| File | Description |
|------|-------------|
| `__main__.py` | Full demo — start server, query sysDescr, walk interfaces, register handlers |
| `server.py` | `ExampleSNMPServer` — real SNMP server using system providers |

## ExampleSNMPServer

`examples/server.py` implements a **real** SNMP server using the `SNMPServer` ABC that exposes real system information:

```python
from examples.server import ExampleSNMPServer

server = ExampleSNMPServer(community="public", port=1161)
await server.start("127.0.0.1", 1161)
```

### RFC 1156 MIB-2 OIDs (System + Interfaces Groups)

| OID | Name | Type | Data Source |
|-----|------|------|-------------|
| 1.3.6.1.2.1.1.1 | sysDescr | Static | `platform.system() + platform.release()` |
| 1.3.6.1.2.1.1.3 | sysUpTime | Dynamic | `psutil.boot_time()` or `time.time()` |
| 1.3.6.1.2.1.1.4 | sysContact | Dynamic | Environment variable `SNMP_CONTACT` or "root@localhost" |
| 1.3.6.1.2.1.1.5 | sysName | Dynamic | `socket.gethostname()` |
| 1.3.6.1.2.1.1.6 | sysLocation | Static | Environment variable `SNMP_LOCATION` or "Server Room" |
| 1.3.6.1.2.1.1.7 | sysServices | Static | 7 (internet-ns) |
| 1.3.6.1.2.1.2.1 | ifNumber | Static | Number of active network interfaces |
| 1.3.6.1.2.1.2.2.1.* | ifTable | Enumerable | Real network interface data |

### UCD-HOST-MIB OIDs (1.3.6.1.4.1.2021)

When **psutil** is installed, the server exposes additional system metrics via the UCD SNMP enterprise subtree:

#### CPU Metrics (ssCpuRaw*, ssCpuStats)

| OID | Name | Type | Data Source |
|-----|------|------|-------------|
| 1.3.6.1.4.1.2021.11.10 | ssCpuRawUser | Dynamic | `psutil.cpu_times().user * 100` |
| 1.3.6.1.4.1.2021.11.11 | ssCpuRawNice | Dynamic | `psutil.cpu_times().nice * 100` |
| 1.3.6.1.4.1.2021.11.12 | ssCpuRawSystem | Dynamic | `psutil.cpu_times().system * 100` |
| 1.3.6.1.4.1.2021.11.13 | ssCpuRawIdle | Dynamic | `psutil.cpu_times().idle * 100` |
| 1.3.6.1.4.1.2021.11.14 | ssCpuRawIOWait | Dynamic | `psutil.cpu_times().iowait * 100` |
| 1.3.6.1.4.1.2021.11.50 | ssCpuStatsUser | Dynamic | CPU user % (percentage) |
| 1.3.6.1.4.1.2021.11.51 | ssCpuStatsNice | Dynamic | CPU nice % |
| 1.3.6.1.4.1.2021.11.52 | ssCpuStatsSystem | Dynamic | CPU system % |
| 1.3.6.1.4.1.2021.11.53 | ssCpuStatsIdle | Dynamic | CPU idle % |
| 1.3.6.1.4.1.2021.11.54 | ssCpuCount | Dynamic | `psutil.cpu_count(logical=True)` |
| 1.3.6.1.4.1.2021.11.55 | ssCpuCountPhysical | Dynamic | `psutil.cpu_count(logical=False)` |

#### Load Average (ssLoadAverage)

| OID | Name | Type | Data Source |
|-----|------|------|-------------|
| 1.3.6.1.4.1.2021.10.1 | ssLoadAverage1 | Dynamic | 1-minute load average |
| 1.3.6.1.4.1.2021.10.2 | ssLoadAverage5 | Dynamic | 5-minute load average |
| 1.3.6.1.4.1.2021.10.3 | ssLoadAverage15 | Dynamic | 15-minute load average |

#### Memory Metrics (mem*)

| OID | Name | Type | Data Source |
|-----|------|------|-------------|
| 1.3.6.1.4.1.2021.4.5 | memTotalReal | Dynamic | Total RAM in KB (`psutil.virtual_memory().total // 1024`) |
| 1.3.6.1.4.1.2021.4.6 | memFreeReal | Dynamic | Free RAM in KB |
| 1.3.6.1.4.1.2021.4.8 | memTotalSwap | Dynamic | Total swap in KB |
| 1.3.6.1.4.1.2021.4.9 | memFreeSwap | Dynamic | Free swap in KB |
| 1.3.6.1.4.1.2021.4.10 | memBuffers | Dynamic | Buffer memory in KB |
| 1.3.6.1.4.1.2021.4.11 | memCached | Dynamic | Cached memory in KB |

#### Disk/Storage Metrics (hrStorage)

| OID | Name | Type | Data Source |
|-----|------|------|-------------|
| 1.3.6.1.4.1.2021.9.1 | hrStorageIndex | Dynamic | Number of disk partitions |
| 1.3.6.1.4.1.2021.9.2 | hrStorageDescr | Dynamic | Filesystem description |
| 1.3.6.1.4.1.2021.9.4 | hrStorageSize | Dynamic | Total size in allocation units |
| 1.3.6.1.4.1.2021.9.5 | hrStorageUsed | Dynamic | Used space |
| 1.3.6.1.4.1.2021.9.8 | hrStorageAvailUnam | Dynamic | Available space |

#### Battery/AC Power (ucsBattery)

| OID | Name | Type | Data Source |
|-----|------|------|-------------|
| 1.3.6.1.4.1.2021.33.1 | ucsBatteryStatus | Dynamic | 1=AC, 2=Battery, 3=Low |
| 1.3.6.1.4.1.2021.33.2 | ucsBatteryPerc | Dynamic | Battery percentage |
| 1.3.6.1.4.1.2021.33.3 | ucsBatteryEstTime | Dynamic | Estimated seconds remaining |

#### Network Interface Counters (netIf)

| OID | Name | Type | Data Source |
|-----|------|------|-------------|
| 1.3.6.1.4.1.2021.2.10 | netIfInErrors | Dynamic | `psutil.net_io_counters().errin` |
| 1.3.6.1.4.1.2021.2.11 | netIfInDiscards | Dynamic | `psutil.net_io_counters().dropin` |
| 1.3.6.1.4.1.2021.2.12 | netIfOutErrors | Dynamic | `psutil.net_io_counters().errout` |
| 1.3.6.1.4.1.2021.2.13 | netIfOutDiscards | Dynamic | `psutil.net_io_counters().dropout` |

#### TCP Connection Stats (netStats)

| OID | Name | Type | Data Source |
|-----|------|------|-------------|
| 1.3.6.1.4.1.2021.6.1 | netTcpEstablished | Dynamic | `psutil.net_connections().ESTABLISHED` |
| 1.3.6.1.4.1.2021.6.2 | netTcpListen | Dynamic | `psutil.net_connections().LISTEN` |
| 1.3.6.1.4.1.2021.6.3 | netTcpTimeWait | Dynamic | `psutil.net_connections().TIME_WAIT` |
| 1.3.6.1.4.1.2021.6.4 | netTcpCloseWait | Dynamic | `psutil.net_connections().CLOSE_WAIT` |
| 1.3.6.1.4.1.2021.6.5 | netTcpClose | Dynamic | `psutil.net_connections().CLOSE` |
| 1.3.6.1.4.1.2021.6.6 | netTcpLastAck | Dynamic | `psutil.net_connections().LAST_ACK` |

#### Extension Metrics (ext*)

| OID | Name | Type | Data Source |
|-----|------|------|-------------|
| 1.3.6.1.4.1.2021.99.1 | extProcessCount | Dynamic | `len(psutil.pids())` |
| 1.3.6.1.4.1.2021.99.2 | extUserCount | Dynamic | `len(psutil.users())` |

### Enhanced ifTable

The ifTable (1.3.6.1.2.1.2.2.1.*) now includes real network interface counters when psutil is available:

| Column | OID Suffix | Description |
|--------|-----------|-------------|
| ifInOctets | .10 | Bytes received (psutil) |
| ifOutOctets | .14 | Bytes sent (psutil) |
| ifInUcastPkts | .11 | Packets received (psutil) |
| ifOutUcastPkts | .15 | Packets sent (psutil) |
| ifInErrors | .17 | Receive errors (psutil) |
| ifOutErrors | .18 | Transmit errors (psutil) |

## Using the Client

```python
from snmp.client import SNMPClientImpl
from snmp.enums import SNMPVersion

client = SNMPClientImpl(community="public", version=SNMPVersion.v1, timeout=2.0)

# GET a single OID
result = await client.get("127.0.0.1", "1.3.6.1.2.1.1.1.0", port=1161)
print(f"sysDescr = {result}")

# GETNEXT (lexicographic successor)
result = await client.get_next("127.0.0.1", "1.3.6.1.2.1.1.1.0", port=1161)
print(f"next OID = {result}")

# WALK a subtree (iterative GetNext)
results = await client.walk("127.0.0.1", "1.3.6.1.2.1.2.2.1", port=1161)
for oid, value in results:
    print(f"  {oid} = {value}")
```

## Custom Server

Create custom SNMP servers by subclassing `SNMPServer` and registering handlers:

```python
from snmp.server import SNMPServer
from snmp.handlers import StaticValueHandler, CounterHandler, CompoundHandler

server = ExampleSNMPServer()
server.register_static("1.3.6.1.2.1.1.8", 7200, access="read")

# Register a counter
counter = server.register_counter("1.3.6.1.2.1.2.2.1.20.1", initial_value=0)
counter.increment(delta=42)

# Group enterprise subtree
enterprise = CompoundHandler("1.3.6.1.4.1.99999")
enterprise.register("1.3.6.1.4.1.99999.1", StaticValueHandler("...", b"Vendor Name"))
server.register("1.3.6.1.4.1.99999", enterprise, access="read")
```

See `examples/__main__.py` for a complete example with handler registration, compound subtrees, and minimal server demonstration.

## Requirements

- Python 3.12+

Optional: `psutil>=6.0.0` — Enables all UCD-HOST-MIB metrics (CPU, memory, disk, network counters, battery, TCP stats)