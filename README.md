# snmpy

A pure-Python3 SNMP library built with asyncio — no third-party runtime
dependencies. Implements BER (X.690), SNMPv1 / v2c / v3 (USM), traps,
an agent framework, MIB/OID packs, and a small CLI.

Requires Python ≥ 3.12.

## Install

For development (this repo):

```bash
pip install -e .            # library
pip install -e ".[dev]"     # + ruff, mypy, pytest
```

To consume it as a dependency, install from a tagged release — the name
`snmpy` on PyPI belongs to an unrelated project, so nothing is published
there:

```bash
pip install "snmpy @ git+https://github.com/b1tninja/snmpy.git@v1.0.0"
```

Optional extras: `crypto` (cryptography, for SNMPv3 privacy),
`examples` (psutil, used by `examples/server.py`).

## Quick start — `Session` (blocking, simplest)

```python
from snmp import Session
from snmp.mib_system import sysDescr, sysName

with Session("192.168.1.71", community="public") as snmp:
    print(snmp.get_str(sysDescr))          # typed unwrap (RFC 3416 §4.1.6
    print(snmp.get_int("sysUpTime"))       # exceptions raise LookupError)
    for oid, value in snmp.walk("printer-mib:prtMarkerSuppliesTable"):
        print(oid, value)                  # toner levels, page counters, ...
    snmp.set("sysContact", "ops@example.com")
```

`Session` is v1/v2c, blocking UDP with retries, and accepts OIDs as
dotted strings, `Oid` objects, or `pack:leaf` shorthand
(`"mib2-system:sysName"`). See `examples/session_demo.py`.

## Async client

`SNMPClient` is an ABC whose concrete methods (`get`, `get_next`,
`walk`, `bulk_get`, `set`, `send_trap`) are template methods built on
one abstract `_send_receive(datagram, host, port)`. `SNMPClientImpl`
provides the asyncio UDP transport:

```python
import asyncio
from snmp.client import SNMPClientImpl

async def main():
    client = SNMPClientImpl(community="public")
    value = await client.get("192.168.1.71", "1.3.6.1.2.1.1.1.0")
    rows = await client.walk("192.168.1.71", "1.3.6.1.2.1.25.3.5.1")
    await client.close()

asyncio.run(main())
```

## CLI

```bash
python -m snmpy packs                       # list registered OidPacks
python -m snmpy get 192.168.1.71 sysDescr --pack mib2-system
python -m snmpy get 192.168.1.71 printer-mib:prtMarkerLifeCount -v 2c
python -m snmpy walk 192.168.1.71 1.3.6.1.2.1.43
python -m snmpy set 192.168.1.71 sysContact "ops@example.com" -c private
```

## MIB packs

`snmp.oid.OidPack` groups named `Oid` leaves; import side-effects
register them into `PACKS`:

| Pack | Source | Contents |
|---|---|---|
| `mib2-system` | RFC 1213 / RFC 1907 | system group scalars (`sysDescr` … `sysServices`) |
| `printer-mib` | RFC 3805 (+ RFC 2790 companions) | Printer MIB v2 tables & key scalars (`prtMarkerLifeCount`, supplies level/description, …) |

Add your own pack (e.g. a vendor subtree) by constructing an `OidPack`
and calling `register_pack()` — keep vendor OIDs out of the RFC packs.

## SNMPv3 / USM

`snmp.usm`, `snmp.auth`, `snmp.privacy`, `snmp.mpm` implement the
User-based Security Model: HMAC-MD5-96 (RFC 3414 §6), HMAC-SHA-96
(§7), HMAC-SHA-256/384/512 (RFC 7860), CBC-DES (§8), AES-128
(RFC 3826) and AES-192/256-CBC (RFC 7860) privacy, with the
password-to-key localization of RFC 3414 §2.6/§A.2.

## Traps / agent

- `snmp.trap` — v1 Trap and SNMPv2-Trap PDU construction/formatting.
- `snmp.traps` — async trap receptor (listen and decode).
- `snmp.server` — `SNMPServer` framework: `register_static`,
  `register_dynamic`, `register_table`, `register_counter`.

Examples in `examples/` (`trap_demo.py`, `bulk_demo.py`, `server.py`).

## Tests & lint

```bash
python -m pytest            # 154 tests + 102 subtests, incl. loopback UDP integration
python -m ruff check .      # ~875 findings today — see CI's advisory report
python -m mypy              # ~379 errors today (targets come from pyproject)
```

Both static tools are wired into CI as a **non-blocking** `quality` job that
publishes the current counts to the run summary; the test matrix and the
sdist/wheel build are blocking. Flip `continue-on-error` in
`.github/workflows/ci.yml` once either count reaches zero.

Integration tests (`snmp/test_session.py`) run a threaded in-process
mini agent on 127.0.0.1 — no network or SNMP service required.

## Releases

Version lives in `snmpy/__init__.py` (`__version__`) and is read by
setuptools at build time, so bump it there only. To ship:

```bash
git tag v1.0.1 && git push origin v1.0.1
```

`.github/workflows/release.yml` then verifies the tag matches
`__version__`, builds the sdist + wheel once, signs **SLSA build
provenance** with Sigstore (`actions/attest`), and attaches the artifacts
to a GitHub Release. Confirm a downloaded asset came from this repo:

```bash
gh attestation verify snmpy-1.0.1-py3-none-any.whl --repo b1tninja/snmpy
```

## Repository layout

```
ber/            BER codec (tags, lengths, OIDs, Object model)
snmp/           protocol: pdus, datagram, factories, session, client,
                security (v1/v2c), usm/auth/privacy/mpm (v3),
                server, traps, oid/mib packs, values helpers
snmpy/ + __main__   CLI (get / walk / set / bulk / packs)
examples/       runnable demos
masscan/        helper for fast SNMP discovery scans
```

## Standards implemented

RFC 1157 · RFC 1901–1907 (v2c) · RFC 2578/2579/2580 (SMIv2) ·
RFC 3411–3416 (v3 architecture, USM, PDU/SCOPE) · RFC 3417/3418
(transports, MIB) · RFC 3826 · RFC 7860 · RFC 1213/2790/3805 (MIBs) ·
ITU-T X.690 (BER).

