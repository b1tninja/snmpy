"""Synchronous SNMP session for RE scripts and simple tools.

Built on ``SNMPDatagram`` + blocking UDP sockets rather than the asyncio
``SNMPClient`` / ``SNMPClientImpl`` path.  Prefer this for simple blocking scripts; the asyncio
``SNMPClientImpl`` path binds ``0.0.0.0`` and defaults to v2c. Keep Session
on the datagram encode path so RE tools do not hand-roll UDP.

Example::

    from snmp import Session
    from snmp.mib_system import sysDescr, sysName

    with Session("192.168.1.71", community="public") as snmp:
        print(snmp.get_str(sysDescr))
        print(snmp.get_str(sysName))
"""

from __future__ import annotations

import socket
from collections.abc import Sequence
from types import TracebackType
from typing import Optional, Type

from ber.object import Integer, Object, OctetString

from snmp.datagram import SNMPDatagram
from snmp.enums import ErrorStatus, SNMPVersion
from snmp.exceptions import SNMPTimeoutError
from snmp.factories import make_var_binds
from snmp.oid import OidLike, resolve_oid
from snmp.pdus import GetNextRequest, GetRequest, PDU, SetRequest
from snmp.types import SNMPValue, WalkResult
from snmp.values import as_bytes, as_int, as_str, oid_string


class Session:
    """Blocking SNMPv1/v2c session bound to one agent.

    Args:
        host: Agent address.
        port: UDP port (default 161).
        community: Community for GET / GETNEXT / WALK.
        set_community: Optional write community (when agents use a separate SET
            community). When omitted, SETs use ``community``.
        version: Protocol version (default ``v2c``).
        timeout: Per-attempt socket timeout in seconds.
        retries: Attempts per request (including the first send).
    """

    def __init__(
        self,
        host: str,
        *,
        port: int = 161,
        community: str = "public",
        set_community: Optional[str] = None,
        version: SNMPVersion = SNMPVersion.v2c,
        timeout: float = 2.0,
        retries: int = 3,
    ) -> None:
        self.host = host
        self.port = port
        self.community = community
        self.set_community = set_community if set_community is not None else community
        self.version = version if isinstance(version, SNMPVersion) else SNMPVersion(version)
        self.timeout = timeout
        self.retries = max(1, retries)
        self._sock: Optional[socket.socket] = None

    # ------------------------------------------------------------------
    # Context manager / lifecycle
    # ------------------------------------------------------------------

    def open(self) -> Session:
        """Open (or re-open) the UDP socket."""
        self.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        self._sock = sock
        return self

    def close(self) -> None:
        """Close the UDP socket if open."""
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> Session:
        return self.open()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public operations
    # ------------------------------------------------------------------

    def get(self, oid: OidLike) -> Optional[Object]:
        """GET a single OID. Returns the value Object, or None if empty."""
        oid_s = resolve_oid(oid)
        pdu = self._exchange(GetRequest.from_oid(oid_s), community=self.community, oid=oid_s)
        return self._first_value(pdu)

    def get_bytes(self, oid: OidLike) -> bytes:
        """GET and unwrap as ``bytes`` (raises if missing / wrong type)."""
        value = self.get(oid)
        if value is None:
            raise LookupError(f"GET empty for {resolve_oid(oid)}")
        return as_bytes(value)

    def get_int(self, oid: OidLike) -> int:
        """GET and unwrap as ``int``."""
        value = self.get(oid)
        if value is None:
            raise LookupError(f"GET empty for {resolve_oid(oid)}")
        return as_int(value)

    def get_str(self, oid: OidLike) -> str:
        """GET and unwrap as ``str``."""
        value = self.get(oid)
        if value is None:
            raise LookupError(f"GET empty for {resolve_oid(oid)}")
        return as_str(value)

    def get_many(self, oids: Sequence[OidLike]) -> list[tuple[str, Optional[Object]]]:
        """Sequential GETs; returns ``[(dotted_oid, value_or_None), ...]``."""
        out: list[tuple[str, Optional[Object]]] = []
        for oid in oids:
            oid_s = resolve_oid(oid)
            out.append((oid_s, self.get(oid_s)))
        return out

    def get_next(self, oid: OidLike) -> Optional[tuple[str, Object]]:
        """GETNEXT. Returns ``(next_oid, value)`` or None if empty."""
        oid_s = resolve_oid(oid)
        pdu = self._exchange(GetNextRequest.from_oid(oid_s), community=self.community, oid=oid_s)
        return self._first_binding(pdu)

    def walk(
        self,
        starting_oid: OidLike,
        stop_oid: Optional[OidLike] = None,
    ) -> WalkResult:
        """Walk a subtree via iterative GETNEXT.

        Stops when the next OID leaves ``starting_oid``'s prefix, repeats the
        requested OID (no successor), or optionally reaches ``stop_oid``.
        """
        start = resolve_oid(starting_oid)
        stop = resolve_oid(stop_oid) if stop_oid is not None else None
        results: WalkResult = []
        current = start
        while True:
            nxt = self.get_next(current)
            if nxt is None:
                break
            oid_str, value = nxt
            if stop is not None and oid_str >= stop:
                break
            if not oid_str.startswith(start):
                break
            if oid_str == current:
                break
            results.append((oid_str, value))
            current = oid_str
        return results

    def set(self, oid: OidLike, value: SNMPValue) -> bool:
        """SET using ``set_community``. Returns True on ``noError``."""
        status, _index = self.set_result(oid, value)
        return status == int(ErrorStatus.no_error)

    def set_result(self, oid: OidLike, value: SNMPValue) -> tuple[int, int]:
        """SET using ``set_community``. Returns ``(error_status, error_index)``."""
        oid_s = resolve_oid(oid)
        variable_bindings = make_var_binds([(oid_s, value)])
        pdu = self._exchange(
            SetRequest(variable_bindings=variable_bindings),
            community=self.set_community,
            oid=oid_s,
        )
        return int(pdu.error_status), int(pdu.error_index)

    # ------------------------------------------------------------------
    # Transport (datagram + sync UDP)
    # ------------------------------------------------------------------

    def _ensure_sock(self) -> socket.socket:
        if self._sock is None:
            self.open()
        assert self._sock is not None
        return self._sock

    def _build_datagram(self, pdu: PDU, community: str) -> SNMPDatagram:
        return SNMPDatagram(
            version=Integer.from_int(int(self.version)),
            community=OctetString(community.encode()).get_object(),
            pdu=pdu,
        )

    def _exchange(
        self,
        pdu: PDU,
        *,
        community: str,
        oid: Optional[str] = None,
    ) -> PDU:
        """Send one PDU and return the response PDU.

        Uses blocking UDP with retries.  Intentionally does **not** call
        ``SNMPClient`` / ``SNMPClientImpl`` (async UDP; binds any-iface).
        """
        datagram = self._build_datagram(pdu, community)
        packet = bytes(datagram)
        sock = self._ensure_sock()
        last_exc: Optional[BaseException] = None

        for attempt in range(self.retries):
            try:
                sock.sendto(packet, (self.host, self.port))
                data, _addr = sock.recvfrom(65535)
                resp = SNMPDatagram.decode(data)
                if resp.pdu is None:
                    continue
                return resp.pdu
            except (TimeoutError, socket.timeout, OSError) as exc:
                last_exc = exc
                if attempt < self.retries - 1:
                    continue
                break

        raise SNMPTimeoutError(
            host=self.host,
            port=self.port,
            timeout=self.timeout,
            retries=self.retries,
            oid=oid,
        ) from last_exc

    @staticmethod
    def _first_binding(pdu: PDU) -> Optional[tuple[str, Object]]:
        for oid, value in pdu:
            return oid_string(oid), value
        return None

    @staticmethod
    def _first_value(pdu: PDU) -> Optional[Object]:
        binding = Session._first_binding(pdu)
        if binding is None:
            return None
        return binding[1]

    def __repr__(self) -> str:
        return (
            f"Session(host={self.host!r}, port={self.port}, "
            f"community={self.community!r}, set_community={self.set_community!r}, "
            f"version={self.version.name})"
        )


__all__ = ["Session"]
