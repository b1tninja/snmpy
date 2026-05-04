# SNMPy

<p align="center">
  <em>A Python SNMP library built with asyncio for Basic Encoding Rules (BER) encoding/decoding</em>
</p>

A lightweight, zero-dependency Python library for SNMP protocol operations. Supports BER encoding/decoding, SNMP Get/GetNext/GetResponse operations, MIB-2 OIDs, and masscan integration for network discovery.

## Features

| Feature | Description |
|---------|-------------|
| **BER Encoding/Decoding** | Full ASN.1 BER support for SNMP datagrams |
| **SNMP Protocol** | Get, GetNext, and GetResponse operations |
| **MIB-2 Support** | System OIDs (sysDescr, sysObjectID, sysUpTime, sysContact, sysName, sysLocation, sysServices) |
| **Masscan Integration** | Parse masscan output files and scan for SNMP devices |
| **Async/Await** | Built on Python's asyncio for efficient concurrent operations |
| **Zero Dependencies** | Uses Python stdlib only — no external packages required |

## Requirements

- **Python 3.12+**
- No external dependencies (stdlib only)

## Installation

```bash
# Install the package in development mode
pip install -e .

# Install with development dependencies (linting, testing, type checking)
pip install -e ".[dev]"

# Install with documentation dependencies
pip install -e ".[dev]"
```

## Documentation

Full API documentation is available in the `docs/` directory. To build HTML docs:

```bash
cd docs
sphinx-build -b html . _build/html
```

Then open `docs/_build/html/index.html` in your browser.

Alternatively, view the auto-generated API docs on [Read the Docs](https://snmpy.readthedocs.io).

## Quick Start

### SNMP Get Request

Retrieve a device's system description:

```python
import asyncio
from snmp.protocol import SNMPProtocol
from snmp.mib import sysDescr

async def get_device_info(host: str) -> None:
    loop = asyncio.get_event_loop()
    transport, protocol = loop.run_until_complete(
        loop.create_datagram_endpoint(
            lambda: SNMPProtocol(),
            local_addr=("0.0.0.0", 0),
        )
    )

    try:
        result = await asyncio.wait_for(
            protocol.get(host, oid=sysDescr),
            timeout=5,
        )
        print(f"Device: {result}")
    finally:
        transport.close()

asyncio.run(get_device_info("192.168.1.1"))
```

### SNMP Get Next (OID Walk)

Walk the MIB tree starting from a given OID:

```python
import asyncio
from snmp.protocol import SNMPProtocol
from snmp.mib import system

async def walk_device(host: str) -> list:
    loop = asyncio.get_event_loop()
    transport, protocol = loop.run_until_complete(
        loop.create_datagram_endpoint(
            lambda: SNMPProtocol(),
            local_addr=("0.0.0.0", 0),
        )
    )

    try:
        result = await asyncio.wait_for(
            protocol.get_next(host, oid=system),
            timeout=5,
        )
        return result
    finally:
        transport.close()

asyncio.run(walk_device("192.168.1.1"))
```

### CLI Usage

Query a device from the command line:

```bash
# Basic query (retrieves system description)
python -m snmpy 192.168.1.1

# Query with custom host and port
python -m snmpy -H 192.168.1.1 -P 161 .1.3.6.1.2.1.1.1.0

# Query a specific OID
python -m snmpy 192.168.1.1 .1.3.6.1.2.1.1.5.0
```

### Masscan Integration

Scan for SNMP devices from masscan output files:

```bash
python readscan.py "scan_results/*.txt"
```

## Architecture

```
snmpy/
├── ber/                    # BER (Basic Encoding Rules) ASN.1 encoding
│   ├── __init__.py         # Module package
│   ├── enums.py            # TagClassEnum, UniversalClassTags
│   ├── object.py           # Object, ObjectTag, ObjectIdentifier, Integer, etc.
│   └── test_objectIdentifier.py
├── snmp/                   # SNMP protocol implementation
│   ├── __init__.py         # Module package & exports
│   ├── datagram.py         # SNMPDatagram encoding/decoding
│   ├── database.py         # Database storage interface
│   ├── enums.py            # ErrorStatus, SNMPVersion enums
│   ├── mib.py              # MIB-2 OID definitions
│   ├── pdus.py             # PDU, Request, GetRequest, GetNextRequest, GetResponse
│   ├── protocol.py         # SNMPProtocol (asyncio.DatagramProtocol)
│   └── test_SNMPDatagram.py
├── snmpy/                  # Main package namespace
│   ├── __init__.py         # Version, exports, main()
│   └── __main__.py         # CLI entry point
├── masscan/                # Masscan -oB binary file reader (compat with masscan --readscan)
│   ├── __init__.py
│   └── readscan.py         # MasscanReader, record types (stdlib only)
├── readscan.py             # SNMP integration over masscan scan files
├── __main__.py             # Package entry point
├── pyproject.toml          # Project metadata, dependencies, tool config
└── README.md               # This file
```

## BER Encoding/Decoding

The `ber` module implements ASN.1 Basic Encoding Rules (BER) for encoding SNMP datagrams.

### Supported Types

| Type | Tag ID | Description |
|------|--------|-------------|
| `Null` | 5 | ASN.1 Null type |
| `Integer` | 2 | ASN.1 Integer (unsigned) |
| `ObjectIdentifier` | 6 | ASN.1 OID (e.g., `1.3.6.1.2.1.1.1`) |
| `OctetString` | 4 | ASN.1 Octet String |
| `Sequence` | 16 | ASN.1 Sequence (constructed) |

### Examples

```python
from ber.object import ObjectIdentifier, Integer, OctetString, Sequence

# Create an OID
oid = ObjectIdentifier.from_string("1.3.6.1.2.1.1.1.0")
print(str(oid))  # "1.3.6.1.2.1.1.1.0"
print(bytes(oid))  # b'\x06\x06\x2b\x06\x01\x02\x01\x01\x01\x00'

# Create an Integer
int_obj = Integer.from_int(42)
print(str(int_obj))  # "42"

# Create an OctetString
oct_str = OctetString(b"public")
print(str(oct_str))  # "public"

# Create a Sequence
seq = Sequence.from_list([oid.get_object(), int_obj.get_object()])
print(bytes(seq))  # BER-encoded sequence
```

## SNMP Protocol

The `snmp` module implements SNMP protocol operations using asyncio.

### Supported Operations

| Method | PDU Type | Tag ID | Description |
|--------|----------|--------|-------------|
| `get()` | GetRequest | 0 | Retrieve a specific OID |
| `get_next()` | GetNextRequest | 1 | Get the next OID in the MIB tree |
| `walk()` | GetNextRequest | 1 | Walk the MIB tree from a starting OID |

### Supported Error Statuses

| Status | Code | Description |
|--------|------|-------------|
| `no_error` | 0 | No error |
| `too_big` | 1 | PDU too large |
| `no_such_name` | 2 | Name does not exist |
| `bad_value` | 3 | Bad value |
| `read_only` | 4 | Read-only value |
| `generic_error` | 5 | Generic error |

### SNMP Versions

| Version | Code |
|---------|------|
| SNMPv1 | 0 |
| SNMPv2c | 1 |
| SNMPv3 | 2 |

### Factory Functions

Create SNMP objects with helper functions from `snmp.factories`:

```python
from snmp import make_var_bind, make_var_binds, SNMPValue

# Create a variable binding from an OID string and value
vb = make_var_bind("1.3.6.1.2.1.1.1.0", "Linux device")

# Create multiple variable bindings for bulk operations
pairs = [
    ("1.3.6.1.2.1.1.1.0", "Device 1"),
    ("1.3.6.1.2.1.1.5.0", "MyRouter"),
]
var_binds = make_var_binds(pairs)

# Convert Python values to SNMP-compatible BER objects
snmp_val: SNMPValue = 42  # int
value_obj = make_var_bind("1.3.6.1.2.1.1.1.0", snmp_val)
```

### Type Aliases

Shared type definitions are available in `snmp.types`:

```python
from snmp.types import VarBind, VarBinds, WalkResult, SNMPValue

# VarBind — a single variable binding: (oid, value)
binding: VarBind = ("1.3.6.1.2.1.1.1.0", "device")

# WalkResult — result of a walk operation
result: WalkResult = [("1.3.6.1.2.1.1.1.0", b"device")]
```

## Database Storage

The `snmp.database` module provides an interface for storing SNMP results in a database. Currently disabled due to the deprecation of `aiopg`. A future release will support modern async database drivers.

```python
from snmp.database import Database

db = Database()
await db.connect(host="localhost", dbname="snmp_data", user="snmp", password="secret")
await db.save_get_response("192.168.1.1", oid, response)
```

## Testing

Run the test suite:

```bash
pytest
```

Run with verbose output:

```bash
pytest -v
```

Run with coverage:

```bash
pip install coverage
coverage run -m pytest
coverage report
```

## Development

Set up your development environment:

```bash
# Install the package with dev dependencies
pip install -e ".[dev]"

# Run linting and formatting
ruff check .
ruff format .

# Run type checking
mypy snmp ber masscan readscan.py __main__.py snmpy

# Run tests
pytest -v
```

## Configuration

Project configuration is managed via `pyproject.toml`:

| Tool | Configuration |
|------|---------------|
| [Ruff](https://docs.astral.sh/ruff/) | Linting, auto-formatting (line length: 120) |
| [mypy](https://mypy.readthedocs.io/) | Static type checking (Python 3.12+) |
| [pytest](https://docs.pytest.org/) | Test discovery in `snmp/` and `ber/` directories |

## Examples & Use Cases

### Scanning a Subnet for SNMP Devices

```python
import asyncio
from ipaddress import IPv4Network
from snmp.protocol import SNMPProtocol

async def scan_subnet(network: str, timeout: float = 2.0) -> list:
    """Scan a subnet for SNMP-enabled devices."""
    results = []
    loop = asyncio.get_event_loop()
    transport, protocol = loop.run_until_complete(
        loop.create_datagram_endpoint(
            lambda: SNMPProtocol(),
            local_addr=("0.0.0.0", 0),
        )
    )

    try:
        tasks = []
        for host in IPv4Network(network, strict=False):
            tasks.append(protocol.get(str(host), oid=snmp.mib.sysDescr))

        for task in asyncio.as_completed(tasks, timeout=timeout):
            try:
                result = await asyncio.wait_for(task, timeout=timeout)
                results.append(result)
            except asyncio.TimeoutError:
                pass

        return results
    finally:
        transport.close()
```

### Walking the Full MIB Tree

```python
import asyncio
from snmp.protocol import SNMPProtocol

async def full_walk(host: str, starting_oid: str = None) -> list:
    """Walk the entire MIB tree starting from a given OID."""
    loop = asyncio.get_event_loop()
    transport, protocol = loop.run_until_complete(
        loop.create_datagram_endpoint(
            lambda: SNMPProtocol(),
            local_addr=("0.0.0.0", 0),
        )
    )

    try:
        result = await asyncio.wait_for(
            protocol.walk(host, starting_oid=starting_oid, timeout=5.0),
            timeout=30.0,
        )
        return result  # List of (oid, value) tuples
    finally:
        transport.close()
```

## Comparison to Other Libraries

| Feature | SNMPy | pysnmp | Net-SNMP |
|---------|-------|--------|----------|
| Zero Dependencies | ✅ | ❌ | ❌ |
| Async/Await | ✅ | Partial | ❌ |
| BER Encoding | ✅ | ❌ | ❌ |
| Lightweight | ✅ | ❌ | ❌ |
| Python 3.12+ | ✅ | Partial | N/A |
| CLI Tool | ✅ | ❌ | ✅ |

## License

MIT License — see the repository for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass (`pytest`)
5. Run linting (`ruff check .`)
6. Submit a pull request

## API Reference

| Resource | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.rst) | Quick start guide and usage examples |
| [API Reference](docs/api.rst) | Complete API documentation with autodoc |
| `snmp/` module docs | Module-level docstrings in all public classes |
| `snmp/types.py` | Shared type aliases (VarBind, SNMPValue, WalkResult) |
| `snmp/factories.py` | Factory functions for BER object construction |
| `ber/` module docs | BER encoding/decoding documentation |

## Acknowledgments

- [RFC 1155](https://www.ietf.org/rfc/rfc1155.txt) — Structure of Management Information for Network Management of SNMP
- [RFC 1157](https://www.ietf.org/rfc/rfc1157.txt) — SNMPv1 specifications
- [Masscan](https://github.com/robertdavidgraham/masscan) — TCP port scanner