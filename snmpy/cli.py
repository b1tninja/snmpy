"""Command-line interface for SNMP get / walk / set (v1 and v2c).

Stdlib-only. Built-in OID packs are RFC-based (``mib2-system``, ``printer-mib``).
Vendor packs live outside snmpy — load with ``--import``::

    snmpy packs
    snmpy pack show mib2-system
    snmpy get --pack mib2-system 192.168.1.71 sysName
    snmpy --import my_vendor_oids get --pack myvendor HOST leaf
"""

from __future__ import annotations

import argparse
import asyncio
import binascii
import importlib
import sys
from typing import Optional

from ber.enums import UniversalClassTags
from ber.object import Object, OctetString
from snmp import DEFAULT_PORT
from snmp.client import SNMPClient, _SNMPClientProtocol
from snmp.datagram import SNMPDatagram
from snmp.enums import SNMPVersion
from snmp.oid import PACKS, get_pack, resolve_oid, resolve_symbolic

# Side-effect: register built-in RFC packs only
import snmp.mib_printer  # noqa: F401
import snmp.mib_system  # noqa: F401


# ---------------------------------------------------------------------------
# Lightweight UDP client (CLI-local; does not modify snmp.client)
# ---------------------------------------------------------------------------


class _UdpClient(SNMPClient):
    """Concrete SNMPClient for the CLI: one ephemeral UDP socket per request."""

    def __init__(
        self,
        community: str = "public",
        version: SNMPVersion = SNMPVersion.v2c,
        timeout: float = 5.0,
        retries: int = 3,
    ) -> None:
        self.community = community
        self.version = version
        self.timeout = timeout
        self.retries = retries

    async def _send_receive(
        self,
        datagram: SNMPDatagram,
        host: str,
        port: int,
    ) -> Optional[bytes]:
        protocol = _SNMPClientProtocol()
        try:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: protocol,
                local_addr=("0.0.0.0", 0),
            )
            try:
                transport.sendto(bytes(datagram), (host, port))
                await asyncio.wait_for(protocol.response_event.wait(), timeout=self.timeout)
                if protocol.response_data:
                    return protocol.response_data[0]
                return None
            finally:
                transport.close()
        except (asyncio.TimeoutError, OSError):
            return None


# ---------------------------------------------------------------------------
# Value formatting / parsing
# ---------------------------------------------------------------------------


def _octet_bytes(value: Object) -> Optional[bytes]:
    """Return raw octets if *value* is (or wraps) an OctetString / raw bytes."""
    inner = getattr(value, "value", value)
    if isinstance(inner, OctetString):
        return bytes(inner)
    if isinstance(inner, (bytes, bytearray)):
        tag = getattr(getattr(value, "tag", None), "tag_id", None)
        if tag is None or tag == UniversalClassTags.octet_string:
            return bytes(inner)
    return None


def format_value(value: Object, *, hex_mode: Optional[bool]) -> str:
    """Format a BER value for display.

    Args:
        value: SNMP response value Object.
        hex_mode: True → always hex for OctetString; False → decode as text;
            None → hex when non-ASCII / non-printable (default).
    """
    raw = _octet_bytes(value)
    if raw is not None:
        if hex_mode is True:
            return binascii.hexlify(raw).decode("ascii")
        if hex_mode is False:
            return raw.decode("latin-1", errors="replace")
        # auto: printable ASCII (no control chars except tab/LF/CR) → text, else hex
        try:
            text = raw.decode("ascii")
            if text and all(
                (32 <= ord(c) < 127) or c in "\t\n\r" for c in text
            ):
                return text
        except UnicodeDecodeError:
            pass
        return binascii.hexlify(raw).decode("ascii")
    try:
        return str(value)
    except Exception:
        return repr(value)


def parse_set_value(text: str, type_code: str) -> object:
    """Parse a SET value according to *type_code* (``s`` / ``i`` / ``x``)."""
    code = type_code.lower()
    if code == "i":
        return int(text, 0)
    if code == "x":
        cleaned = text[2:] if text.lower().startswith("0x") else text
        cleaned = cleaned.replace(":", "").replace(" ", "")
        return binascii.unhexlify(cleaned)
    if code == "s":
        return text
    raise ValueError(f"unknown type {type_code!r}; use s, i, or x")


def _parse_version(s: str) -> SNMPVersion:
    key = s.lower().removeprefix("v")
    if key == "1":
        return SNMPVersion.v1
    if key in ("2", "2c"):
        return SNMPVersion.v2c
    raise argparse.ArgumentTypeError("version must be 1 or 2c")


def _hex_flag(ns: argparse.Namespace) -> Optional[bool]:
    """Map --hex / --no-hex to True / False / None (auto)."""
    if getattr(ns, "hex", None) is True:
        return True
    if getattr(ns, "hex", None) is False:
        return False
    return None


# ---------------------------------------------------------------------------
# OID resolution (packs / symbolic names)
# ---------------------------------------------------------------------------


def _resolve_cli_oid(raw: str, pack: Optional[str]) -> str:
    """Resolve dotted OID, ``pack:leaf``, or ``--pack`` + leaf name."""
    try:
        if ":" in raw and not raw[0].isdigit():
            return resolve_oid(raw)
        if pack and raw and not raw[0].isdigit():
            return resolve_symbolic(pack, raw).oid
        return resolve_oid(raw)
    except (KeyError, ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def cmd_packs(_args: argparse.Namespace) -> int:
    if not PACKS:
        print("no packs registered", file=sys.stderr)
        return 1
    for name in sorted(PACKS):
        pack = PACKS[name]
        pen = f" pen={pack.pen}" if pack.pen is not None else ""
        print(f"{name}\t{len(pack)} oids{pen}\t{pack.doc}")
    return 0


def cmd_pack_show(args: argparse.Namespace) -> int:
    try:
        pack = get_pack(args.name)
    except KeyError:
        print(f"unknown pack {args.name!r}; try: snmpy packs", file=sys.stderr)
        return 1
    print(f"# {pack.name}" + (f" (PEN {pack.pen})" if pack.pen else ""))
    if pack.doc:
        print(f"# {pack.doc}")
    for leaf in pack:
        access = leaf.access or "-"
        kind = "scalar" if leaf.scalar else "tree"
        doc = f"  # {leaf.doc}" if leaf.doc else ""
        print(f"{leaf.name}\t{leaf.oid}\t{access}\t{kind}{doc}")
    return 0


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


async def cmd_get(args: argparse.Namespace) -> int:
    try:
        oid = _resolve_cli_oid(args.oid, getattr(args, "pack", None))
    except argparse.ArgumentTypeError as exc:
        print(exc, file=sys.stderr)
        return 2
    client = _UdpClient(
        community=args.community,
        version=args.version,
        timeout=args.timeout,
    )
    value = await client.get(args.host, oid, port=args.port)
    if value is None:
        print(f"timeout or error getting {oid}", file=sys.stderr)
        return 1
    print(f"{oid} = {format_value(value, hex_mode=_hex_flag(args))}")
    return 0


async def cmd_walk(args: argparse.Namespace) -> int:
    try:
        oid = _resolve_cli_oid(args.oid, getattr(args, "pack", None))
    except argparse.ArgumentTypeError as exc:
        print(exc, file=sys.stderr)
        return 2
    client = _UdpClient(
        community=args.community,
        version=args.version,
        timeout=args.timeout,
    )
    results = await client.walk(args.host, oid, port=args.port)
    if not results:
        print(f"no results walking {oid}", file=sys.stderr)
        return 1
    hex_mode = _hex_flag(args)
    for next_oid, value in results:
        print(f"{next_oid} = {format_value(value, hex_mode=hex_mode)}")
    return 0


async def cmd_set(args: argparse.Namespace) -> int:
    try:
        oid = _resolve_cli_oid(args.oid, getattr(args, "pack", None))
    except argparse.ArgumentTypeError as exc:
        print(exc, file=sys.stderr)
        return 2
    try:
        set_value = parse_set_value(args.value, args.type)
    except (ValueError, binascii.Error) as exc:
        print(f"bad value: {exc}", file=sys.stderr)
        return 2

    set_community = args.set_community or args.community
    hex_mode = _hex_flag(args)

    # Optional pre-GET with -c when a distinct SET community is used
    if args.community and args.set_community and args.community != args.set_community:
        get_client = _UdpClient(
            community=args.community,
            version=args.version,
            timeout=args.timeout,
        )
        prior = await get_client.get(args.host, oid, port=args.port)
        if prior is None:
            print(f"pre-GET timeout/error for {oid}", file=sys.stderr)
        else:
            print(f"GET {oid} = {format_value(prior, hex_mode=hex_mode)}")

    set_client = _UdpClient(
        community=set_community,
        version=args.version,
        timeout=args.timeout,
    )
    ok = await set_client.set(args.host, oid, set_value, port=args.port)
    if not ok:
        print(f"SET failed for {oid}", file=sys.stderr)
        return 1
    print(f"SET {oid} ok (community={set_community!r})")
    return 0


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------


def _load_import_modules(modules: Optional[list[str]]) -> None:
    """Import modules so they can ``register_pack`` vendor OID packs."""
    if not modules:
        return
    for name in modules:
        try:
            importlib.import_module(name)
        except ImportError as exc:
            raise SystemExit(f"failed to import {name!r}: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snmpy",
        description="SNMP get / walk / set (v1, v2c). OctetStrings print as hex when non-ASCII.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 1.0.0")
    parser.add_argument(
        "--import",
        dest="import_modules",
        action="append",
        default=[],
        metavar="MODULE",
        help="Import MODULE before resolving packs (vendor packs register via register_pack)",
    )

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-c",
        "--community",
        default="public",
        help="SNMP community (default: public). For set: optional GET community",
    )
    common.add_argument(
        "-v",
        dest="version",
        type=_parse_version,
        default=SNMPVersion.v2c,
        metavar="1|2c",
        help="SNMP version (default: 2c)",
    )
    common.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="Request timeout in seconds (default: 5)",
    )
    common.add_argument(
        "-P",
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"UDP port (default: {DEFAULT_PORT})",
    )
    hex_group = common.add_mutually_exclusive_group()
    hex_group.add_argument(
        "--hex",
        dest="hex",
        action="store_true",
        default=None,
        help="Always print OctetString values as hex",
    )
    hex_group.add_argument(
        "--no-hex",
        dest="hex",
        action="store_false",
        help="Print OctetString values as latin-1 text",
    )

    pack_opt = argparse.ArgumentParser(add_help=False)
    pack_opt.add_argument(
        "--pack",
        default=None,
        metavar="NAME",
        help="OID pack for symbolic leaf names (e.g. mib2-system, printer-mib)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_get = sub.add_parser(
        "get", parents=[common, pack_opt], help="SNMP GET one OID"
    )
    p_get.add_argument("host", help="Target host or IP")
    p_get.add_argument(
        "oid",
        help="Dotted OID, pack:leaf, or leaf name with --pack",
    )
    p_get.set_defaults(func=cmd_get, sync=False)

    p_walk = sub.add_parser(
        "walk", parents=[common, pack_opt], help="SNMP WALK (GetNext) a subtree"
    )
    p_walk.add_argument("host", help="Target host or IP")
    p_walk.add_argument(
        "oid",
        help="Starting OID, pack:leaf, or leaf name with --pack",
    )
    p_walk.set_defaults(func=cmd_walk, sync=False)

    p_set = sub.add_parser(
        "set", parents=[common, pack_opt], help="SNMP SET one OID"
    )
    p_set.add_argument("host", help="Target host or IP")
    p_set.add_argument(
        "oid",
        help="Dotted OID, pack:leaf, or leaf name with --pack",
    )
    p_set.add_argument("value", help="Value to set (see --type)")
    p_set.add_argument(
        "--set-community",
        default=None,
        help="Community for SET (e.g. Brother internal). Default: same as -c",
    )
    p_set.add_argument(
        "--type",
        dest="type",
        choices=("s", "i", "x"),
        default="s",
        help="Value type: s=string (default), i=integer, x=hex octets",
    )
    p_set.set_defaults(func=cmd_set, sync=False)

    p_packs = sub.add_parser("packs", help="List registered OID packs")
    p_packs.set_defaults(func=cmd_packs, sync=True)

    p_pack = sub.add_parser("pack", help="Inspect an OID pack")
    pack_sub = p_pack.add_subparsers(dest="pack_cmd", required=True)
    p_show = pack_sub.add_parser("show", help="List leaves in a pack")
    p_show.add_argument("name", help="Pack name (see snmpy packs)")
    p_show.set_defaults(func=cmd_pack_show, sync=True)

    return parser


def main(argv: Optional[list[str]] = None) -> None:
    """Entry point for the ``snmpy`` console script and ``python -m snmpy``."""
    parser = build_parser()
    args = parser.parse_args(argv)
    _load_import_modules(getattr(args, "import_modules", None))
    if getattr(args, "sync", False):
        raise SystemExit(args.func(args))
    raise SystemExit(asyncio.run(args.func(args)))


if __name__ == "__main__":
    main()
